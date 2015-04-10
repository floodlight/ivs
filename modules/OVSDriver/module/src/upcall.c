/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#define AIM_CONFIG_INCLUDE_GNU_SOURCE 1
#include "ovs_driver_int.h"
#include "indigo/forwarding.h"
#include "indigo/port_manager.h"
#include "indigo/of_state_manager.h"
#include <linux/if_ether.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include "SocketManager/socketmanager.h"
#include "murmur/murmur.h"
#include <packet_trace/packet_trace.h>
#include <sys/mman.h>
#include <pwd.h>
#include <sys/capability.h>

#define DEFAULT_NUM_UPCALL_THREADS 4
#define MAX_UPCALL_THREADS 16
#define NUM_UPCALL_BUFFERS 64
#define MAX_KEY_SIZE 4096

#define BLOOM_BUCKETS 65536
#define BLOOM_CAPACITY 4096

struct ind_ovs_upcall_thread {
    int pid;
    int index;

    /* Epoll set containing all upcall netlink sockets assigned to this thread */
    int epfd;

    /*
     * Datagram socket used to send kflow requests to the main thread
     *
     * The maximum number of datagrams queued is limited by the sysctl
     * net.unix.max_dgram_qlen, which defaults to 10.
     */
    int kflow_sock_rd;
    int kflow_sock_wr;

    /* Cached here so we don't need to reallocate it every time */
    struct xbuf stats;

    /* Preallocated messages used by the upcall thread for send and recv. */
    struct nl_msg *msgs[NUM_UPCALL_BUFFERS];

    /*
     * Structures used by recvmmsg to receive multiple netlink messages at
     * once. These point into the preallocated messages above.
     */
    struct iovec iovecs[NUM_UPCALL_BUFFERS];
    struct mmsghdr msgvec[NUM_UPCALL_BUFFERS];

    /*
     * To reduce the number of user/kernel transitions we queue up
     * OVS_PACKET_CMD_EXECUTE msgs to send in one call to sendmsg.
     */
    struct iovec tx_queue[NUM_UPCALL_BUFFERS];
    int tx_queue_len;

    /*
     * Whether the VERBOSE log flags is set. Cached here so we only have to
     * look it up once per iteration of the upcall loop.
     */
    bool log_upcalls;

    /*
     * See ind_ovs_upcall_seen_key.
     */
    uint8_t bloom_filter[BLOOM_BUCKETS/8];
    uint16_t bloom_filter_count;

    /* Used to increment stats */
    struct stats_writer *stats_writer;
};

static void ind_ovs_handle_port_upcalls(struct ind_ovs_upcall_thread *thread, struct ind_ovs_port *port);
static void ind_ovs_handle_one_upcall(struct ind_ovs_upcall_thread *thread, struct ind_ovs_port *port, struct nl_msg *msg);
static void ind_ovs_handle_packet_miss(struct ind_ovs_upcall_thread *thread, struct ind_ovs_port *port, struct nl_msg *msg, struct nlattr **attrs);
static bool ind_ovs_upcall_seen_key(struct ind_ovs_upcall_thread *thread, struct nlattr *key);
static void ind_ovs_upcall_request_kflow(struct ind_ovs_upcall_thread *thread, struct nlattr *key);
static void ind_ovs_upcall_thread_init(struct ind_ovs_upcall_thread *thread, int parent_pid);

static int ind_ovs_num_upcall_threads;
static struct ind_ovs_upcall_thread *ind_ovs_upcall_threads[MAX_UPCALL_THREADS];
static int nobody_uid;

DEBUG_COUNTER(kflow_request, "ovsdriver.upcall.kflow_request", "Kernel flow requested by upcall process");
DEBUG_COUNTER(kflow_request_error, "ovsdriver.upcall.kflow_request_error", "Error on kernel flow request socket");
DEBUG_COUNTER(respawn, "ovsdriver.upcall.respawn", "Respawned upcall processes");
DEBUG_COUNTER(respawn_time, "ovsdriver.upcall.respawn_time", "Total time in microseconds spent respawning upcall processes");

SHARED_DEBUG_COUNTER(upcall, "ovsdriver.upcall", "Upcall from the kernel");
SHARED_DEBUG_COUNTER(wakeup, "ovsdriver.upcall.wakeup", "Upcall process woken up");
SHARED_DEBUG_COUNTER(upcall_time, "ovsdriver.upcall.time", "Total time in microseconds spent handling upcalls");

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif

static void
ind_ovs_upcall_thread_main(struct ind_ovs_upcall_thread *thread)
{
    while (1) {
        struct epoll_event events[128];
        thread->log_upcalls = aim_log_enabled(AIM_LOG_STRUCT_POINTER, AIM_LOG_FLAG_VERBOSE);
        int n = epoll_wait(thread->epfd, events, AIM_ARRAYSIZE(events), -1);
        if (n < 0 && errno != EINTR) {
            LOG_ERROR("epoll_wait failed: %s", strerror(errno));
            abort();
        } else if (n > 0) {
            debug_counter_inc(&wakeup);
            uint64_t start_time = monotonic_us();
            int j;
            for (j = 0; j < n; j++) {
                ind_ovs_handle_port_upcalls(thread, events[j].data.ptr);
            }
            uint64_t elapsed = monotonic_us() - start_time;
            debug_counter_add(&upcall_time, elapsed);
        }
    }
}

static void
ind_ovs_handle_port_upcalls(struct ind_ovs_upcall_thread *thread,
                            struct ind_ovs_port *port)
{
    int fd = nl_socket_get_fd(port->notify_socket);
    int count = 0; /* total messages processed */

    while (count < 128) {
        /* Fast recv into our preallocated messages */
        int n = recvmmsg(fd, thread->msgvec, NUM_UPCALL_BUFFERS, 0, NULL);
        if (n < 0) {
            if (errno == EAGAIN) {
                break;
            } else {
                continue;
            }
        }

        thread->tx_queue_len = 0;

        int i;
        for (i = 0; i < n; i++) {
            struct nl_msg *msg = thread->msgs[i];
            struct nlmsghdr *nlh = nlmsg_hdr(msg);

            /*
            * HACK to workaround OVS not using nlmsg_end().
            * This size is padded to 4 byte alignment which
            * nlmsg_len shouldn't be. This hasn't confused
            * the parser yet. Worse is that in the case of
            * multipart messages the buffer returned by
            * read contains multiple messages. Luckily the
            * only buggy messages are from the packet family,
            * which doesn't use any multipart messages.
            */
            /* Don't mess with messages that aren't broken. */
            int len = thread->msgvec[i].msg_len;
            if (nlh->nlmsg_len + nlmsg_padlen(nlh->nlmsg_len) != len) {
                //LOG_TRACE("fixup size: nlh->nlmsg_len=%d pad=%d len=%d", nlh->nlmsg_len, nlmsg_padlen(nlh->nlmsg_len), len);
                nlh->nlmsg_len = len;
            }

            ind_ovs_handle_one_upcall(thread, port, msg);
        }

        struct msghdr msghdr = { 0 };
        msghdr.msg_iov = thread->tx_queue;
        msghdr.msg_iovlen = thread->tx_queue_len;
        (void) sendmsg(fd, &msghdr, 0);

        count += n;

        if (n != NUM_UPCALL_BUFFERS) {
            break;
        }
    }

    debug_counter_add(&upcall, count);
}

static void
ind_ovs_handle_one_upcall(struct ind_ovs_upcall_thread *thread,
                          struct ind_ovs_port *port,
                          struct nl_msg *msg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = NLMSG_DATA(nlh);
        LOG_ERROR("Received error on upcall socket: %s", strerror(-err->error));
        LOG_VERBOSE("Original message:");
        ind_ovs_dump_msg(&err->msg);
        return;
    }

    if (thread->log_upcalls) {
        LOG_VERBOSE("Received upcall:");
        ind_ovs_dump_msg(nlh);
    }

    assert(nlh->nlmsg_type == ovs_packet_family);
    struct genlmsghdr *gnlh = (void *)(nlh + 1);

    struct nlattr *attrs[OVS_PACKET_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                      attrs, OVS_PACKET_ATTR_MAX,
                      NULL) < 0) {
        LOG_ERROR("failed to parse packet message");
        abort();
    }

    /* Will be ACTION in the case of OFPP_TABLE */
    AIM_ASSERT(gnlh->cmd == OVS_PACKET_CMD_MISS || gnlh->cmd == OVS_PACKET_CMD_ACTION);

    ind_ovs_handle_packet_miss(thread, port, msg, attrs);
}

static void
ind_ovs_handle_packet_miss(struct ind_ovs_upcall_thread *thread,
                           struct ind_ovs_port *port,
                           struct nl_msg *msg, struct nlattr **attrs)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (void *)(nlh + 1);

    struct nlattr *key = attrs[OVS_PACKET_ATTR_KEY];
    struct nlattr *packet = attrs[OVS_PACKET_ATTR_PACKET];
    assert(key && packet);

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key(key, &pkey);

    struct ind_ovs_parsed_key mask = { 0 };

    xbuf_reset(&thread->stats);

    struct nlattr *actions = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);

    struct action_context actx;
    action_context_init(&actx, &pkey, NULL, msg);

    indigo_error_t err = pipeline_process(&pkey, &mask, &thread->stats, &actx);
    if (err < 0) {
        return;
    }

    ind_ovs_nla_nest_end(msg, actions);

    struct stats_handle *stats_handles = xbuf_data(&thread->stats);
    int num_stats_handles = xbuf_length(&thread->stats) / sizeof(struct stats_handle);
    int i;
    for (i = 0; i < num_stats_handles; i++) {
        stats_inc(thread->stats_writer, &stats_handles[i],
                  1, nla_len(packet));
    }

    /* Reuse the incoming message for the packet execute */
    gnlh->cmd = OVS_PACKET_CMD_EXECUTE;

    /* Don't send the packet back out if it would be dropped. */
    if (nla_len(actions) > 0) {
        nlh->nlmsg_pid = 0;
        nlh->nlmsg_seq = 0;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        struct iovec *iovec = &thread->tx_queue[thread->tx_queue_len++];
        iovec->iov_base = nlh;
        iovec->iov_len = nlh->nlmsg_len;
        if (thread->log_upcalls) {
            LOG_VERBOSE("Sending upcall reply:");
            ind_ovs_dump_msg(nlh);
        }
    }

    /* See the comment for ind_ovs_upcall_seen_key. */
    if (!ind_ovs_disable_kflows && ind_ovs_upcall_seen_key(thread, key)) {
        /* Create a kflow with the given key and actions. */
        ind_ovs_upcall_request_kflow(thread, key);
    }
}

static void
ind_ovs_upcall_assign_thread(struct ind_ovs_port *port)
{
    static int idx;
    LOG_VERBOSE("assigning port %s to upcall thread %d", port->ifname, idx);
    port->upcall_thread = ind_ovs_upcall_threads[idx++];
    idx = idx % ind_ovs_num_upcall_threads;
}

void
ind_ovs_upcall_register(struct ind_ovs_port *port)
{
    ind_ovs_upcall_assign_thread(port);
}

void
ind_ovs_upcall_unregister(struct ind_ovs_port *port)
{
    port->upcall_thread = NULL;
}

/*
 * For single packet flows the cost of installing and expiring a kernel flow
 * is significant. This function uses a bloom filter to probabilistically check
 * if we've seen this flow before. To prevent the bloom filter from filling up
 * we reset it after a certain number of insertions, calculated to keep the
 * probability of a false positive around 1%.
 *
 * This is similar in function to the OVS governor though it uses a different
 * datastructure and runs all the time.
 */
static bool
ind_ovs_upcall_seen_key(struct ind_ovs_upcall_thread *thread,
                        struct nlattr *key)
{
#define BLOOM_TEST(idx) thread->bloom_filter[(idx)/8] &  (1 << ((idx) % 8))
#define BLOOM_SET(idx)  thread->bloom_filter[(idx)/8] |= (1 << ((idx) % 8))

    uint32_t key_hash = murmur_hash(nla_data(key), nla_len(key), ind_ovs_salt);
    uint16_t idx1 = key_hash & 0xFFFF;
    uint16_t idx2 = key_hash >> 16;

    if (BLOOM_TEST(idx1) && BLOOM_TEST(idx2)) {
        return true;
    } else {
        if (thread->bloom_filter_count >= BLOOM_CAPACITY) {
            memset(thread->bloom_filter, 0, sizeof(thread->bloom_filter));
            thread->bloom_filter_count = 0;
        }
        BLOOM_SET(idx1);
        BLOOM_SET(idx2);
        thread->bloom_filter_count++;
        return false;
    }

#undef BLOOM_TEST
#undef BLOOM_SET
}

static void
ind_ovs_upcall_request_kflow(struct ind_ovs_upcall_thread *thread,
                             struct nlattr *key)
{
    if (key->nla_len > MAX_KEY_SIZE) {
        AIM_LOG_WARN("Maximum kflow key size exceeded (is %u)", key->nla_len);
        return;
    }

    AIM_LOG_VERBOSE("Requesting kflow");

    int written = write(thread->kflow_sock_wr, key, key->nla_len);
    if (written < 0) {
        if (errno == EAGAIN) {
            AIM_LOG_VERBOSE("kflow socket buffer full");
        } else {
            AIM_LOG_ERROR("Failed to write to kflow socket: %s", strerror(errno));
        }
    } else if (written != key->nla_len) {
        AIM_LOG_ERROR("Short write to kflow socket");
    }
}


static void
kflow_sock_ready(int fd, void *cookie,
                 int ready_ready, int write_ready, int error_seen)
{
    static char buf[MAX_KEY_SIZE];

    debug_counter_inc(&kflow_request);

    int n = read(fd, buf, sizeof(buf));
    if (n < 0) {
        AIM_LOG_ERROR("Error on kflow socket: %s", strerror(errno));
        debug_counter_inc(&kflow_request_error);
        return;
    }

    AIM_ASSERT(n >= NLA_HDRLEN);

    struct nlattr *key = (void *)buf;
    if (key->nla_len != n) {
        AIM_LOG_ERROR("kflow socket length mismatch: read %u, attr len %u", n, key->nla_len);
        debug_counter_inc(&kflow_request_error);
        return;
    }

    AIM_LOG_VERBOSE("Received kflow request");
    ind_ovs_kflow_add(key);
}

void
ind_ovs_upcall_init(void)
{
    ind_ovs_num_upcall_threads = DEFAULT_NUM_UPCALL_THREADS;
    char *s = getenv("INDIGO_THREADS");
    if (s != NULL) {
        ind_ovs_num_upcall_threads = atoi(s);
        if (ind_ovs_num_upcall_threads <= 0 ||
            ind_ovs_num_upcall_threads > MAX_UPCALL_THREADS) {
            LOG_ERROR("invalid number of upcall threads");
            abort();
        }
    }

    LOG_INFO("using %d upcall threads", ind_ovs_num_upcall_threads);

    int i, j;
    for (i = 0; i < ind_ovs_num_upcall_threads; i++) {
        struct ind_ovs_upcall_thread *thread = aim_zmalloc(sizeof(*thread));
        thread->index = i;

        int sockfd[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_NONBLOCK, 0, sockfd) < 0) {
            AIM_DIE("Failed to create kflow socket: %s", strerror(errno));
        }
        thread->kflow_sock_rd = sockfd[0];
        thread->kflow_sock_wr = sockfd[1];
        if (ind_soc_socket_register(thread->kflow_sock_rd, kflow_sock_ready,
                                    NULL) < 0) {
            AIM_DIE("Failed to register kflow socket with SocketManager");
        }

        xbuf_init(&thread->stats);

        for (j = 0; j < NUM_UPCALL_BUFFERS; j++) {
            thread->msgs[j] = nlmsg_alloc();
            if (thread->msgs[j] == NULL) {
                LOG_ERROR("Failed to allocate upcall message buffers");
                abort();
            }
            thread->iovecs[j].iov_base = nlmsg_hdr(thread->msgs[j]);
            thread->iovecs[j].iov_len = IND_OVS_DEFAULT_MSG_SIZE;
            thread->msgvec[j].msg_hdr.msg_iov = &thread->iovecs[j];
            thread->msgvec[j].msg_hdr.msg_iovlen = 1;
        }

        thread->stats_writer = stats_writer_create();

        ind_ovs_upcall_threads[i] = thread;
    }

    struct passwd *nobody = getpwnam("nobody");
    if (nobody) {
        nobody_uid = nobody->pw_uid;
    } else {
        AIM_DIE("no user named \"nobody\" found");
    }
}

void
ind_ovs_upcall_enable(void)
{
    ind_ovs_upcall_respawn();
}

void
ind_ovs_upcall_finish(void)
{
    int i, j;

    for (i = 0; i < ind_ovs_num_upcall_threads; i++) {
        struct ind_ovs_upcall_thread *thread = ind_ovs_upcall_threads[i];
        close(thread->epfd);
        close(thread->kflow_sock_rd);
        close(thread->kflow_sock_wr);
        kill(thread->pid, SIGKILL);
        waitpid(thread->pid, NULL, 0);
        xbuf_cleanup(&thread->stats);
        for (j = 0; j < NUM_UPCALL_BUFFERS; j++) {
            nlmsg_free(thread->msgs[j]);
        }
        stats_writer_destroy(thread->stats_writer);
        aim_free(thread);
        ind_ovs_upcall_threads[i] = NULL;
    }
}

void
ind_ovs_upcall_respawn(void)
{
    uint64_t start_time = monotonic_us();
    int i;

    debug_counter_inc(&respawn);

    for (i = 0; i < ind_ovs_num_upcall_threads; i++) {
        struct ind_ovs_upcall_thread *thread = ind_ovs_upcall_threads[i];

        if (thread->pid != 0) {
            AIM_LOG_VERBOSE("Killing upcall process %d pid %d", i, thread->pid);
            kill(thread->pid, SIGKILL);
            waitpid(thread->pid, NULL, 0);
            thread->pid = 0;
        }

        AIM_LOG_VERBOSE("Spawning upcall process %d", i);

        int parent_pid = getpid();
        int child_pid = fork();
        if (child_pid < 0) {
            AIM_DIE("Failed to spawn upcall process: %s", strerror(errno));
        } else if (child_pid == 0) {
            ind_ovs_upcall_thread_init(thread, parent_pid);
            ind_ovs_upcall_thread_main(thread);
            AIM_LOG_INFO("Upcall process %d exiting", i);
            exit(0);
        }

        thread->pid = child_pid;
    }

    uint64_t elapsed = monotonic_us() - start_time;
    AIM_LOG_VERBOSE("Respawned upcall processes in %"PRIu64" us", elapsed);
    debug_counter_add(&respawn_time, elapsed);
}

static void
drop_privileges(void)
{
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
        AIM_DIE("prctl(PR_SET_KEEPCAPS) failed");
    }

    if (setuid(nobody_uid) < 0) {
        AIM_DIE("setuid(nobody) failed: %s", strerror(errno));
    }

    cap_t caps = cap_init();
    const cap_value_t cap_vector[] = { CAP_NET_ADMIN };

    if (cap_set_flag(caps, CAP_EFFECTIVE, AIM_ARRAYSIZE(cap_vector), cap_vector, CAP_SET) < 0) {
        AIM_DIE("cap_set_flag failed: %s", strerror(errno));
    }

    if (cap_set_flag(caps, CAP_PERMITTED, AIM_ARRAYSIZE(cap_vector), cap_vector, CAP_SET) < 0) {
        AIM_DIE("cap_set_flag failed: %s", strerror(errno));
    }

    if (cap_set_proc(caps) < 0) {
        AIM_DIE("cap_set_proc failed: %s", strerror(errno));
    }

    cap_free(caps);
}

static void
ind_ovs_upcall_thread_init(struct ind_ovs_upcall_thread *thread, int parent_pid)
{
    char threadname[16];
    snprintf(threadname, sizeof(threadname), "ivs upcall %d", thread->index);
    pthread_setname_np(pthread_self(), threadname);

    /* Ask the kernel to send us a SIGKILL if the main process dies */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0) {
        AIM_DIE("prctl(PR_SET_PDEATHSIG) failed: %s", strerror(errno));
    }

    /* Check if the parent exited before we did PR_SET_PDEATHSIG */
    if (kill(parent_pid, 0) < 0) {
        raise(SIGKILL);
    }

    thread->epfd = epoll_create(1);
    if (thread->epfd < 0) {
        AIM_DIE("failed to create epoll set: %s", strerror(errno));
    }

    /* Create a bitmap of file descriptors we want to keep */
    int max_fds = sysconf(_SC_OPEN_MAX);
    aim_bitmap_t *fds = aim_bitmap_alloc(NULL, max_fds);
    AIM_BITMAP_SET(fds, STDIN_FILENO);
    AIM_BITMAP_SET(fds, STDOUT_FILENO);
    AIM_BITMAP_SET(fds, STDERR_FILENO);
    AIM_BITMAP_SET(fds, thread->kflow_sock_wr);
    AIM_BITMAP_SET(fds, thread->epfd);

    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port && port->upcall_thread == thread) {
            AIM_LOG_VERBOSE("Adding port %s to upcall thread %d", port->ifname, thread->index);
            struct epoll_event evt = { EPOLLIN, { .ptr = port } };
            if (epoll_ctl(port->upcall_thread->epfd, EPOLL_CTL_ADD,
                        nl_socket_get_fd(port->notify_socket), &evt) < 0) {
                AIM_DIE("failed to add to epoll set: %s", strerror(errno));
            }
            AIM_BITMAP_SET(fds, nl_socket_get_fd(port->notify_socket));
        }
    }

    packet_trace_set_fd_bitmap(fds);

    /* Close all other file descriptors */
    for (i = 0; i < max_fds; i++) {
        if (!AIM_BITMAP_GET(fds, i)) {
            close(i);
        }
    }

    aim_bitmap_free(fds);

    /* Reset signal handlers */
    signal(SIGHUP, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    errno = 0;
    if (nice(-20) == -1 && errno != 0) {
        AIM_LOG_WARN("nice(-20) failed: %s", strerror(errno));
    }

    if (mlockall(MCL_CURRENT) < 0) {
        AIM_LOG_WARN("mlockall failed: %s", strerror(errno));
    }

    drop_privileges();
}
