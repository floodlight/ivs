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

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif
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
#include "SocketManager/socketmanager.h"
#include "murmur/murmur.h"

#define DEFAULT_NUM_UPCALL_THREADS 4
#define MAX_UPCALL_THREADS 16
#define NUM_UPCALL_BUFFERS 64

#define BLOOM_BUCKETS 65536
#define BLOOM_CAPACITY 4096

struct ind_ovs_upcall_thread {
    pthread_t pthread;
    volatile bool finished;

    /* Epoll set containing all upcall netlink sockets assigned to this thread */
    int epfd;

    /* Cached here so we don't need to reallocate it every time */
    struct pipeline_result result;

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
};

static void ind_ovs_handle_port_upcalls(struct ind_ovs_upcall_thread *thread, struct ind_ovs_port *port);
static void ind_ovs_handle_one_upcall(struct ind_ovs_upcall_thread *thread, struct ind_ovs_port *port, struct nl_msg *msg);
static void ind_ovs_handle_packet_miss(struct ind_ovs_upcall_thread *thread, struct ind_ovs_port *port, struct nl_msg *msg, struct nlattr **attrs);
static void ind_ovs_handle_packet_action(struct ind_ovs_upcall_thread *thread, struct ind_ovs_port *port, struct nl_msg *msg, struct nlattr **attrs);
static void ind_ovs_upcall_request_pktin(uint32_t port_no, struct ind_ovs_port *port, struct nlattr *packet, struct nlattr *key, int reason);
static bool ind_ovs_upcall_seen_key(struct ind_ovs_upcall_thread *thread, struct nlattr *key);
static void ind_ovs_upcall_rearm(struct ind_ovs_port *port);

static int ind_ovs_num_upcall_threads;
static struct ind_ovs_upcall_thread *ind_ovs_upcall_threads[MAX_UPCALL_THREADS];

static void *
ind_ovs_upcall_thread_main(void *arg)
{
    struct ind_ovs_upcall_thread *thread = arg;

    while (!thread->finished) {
        struct epoll_event events[128];
        thread->log_upcalls = aim_log_enabled(AIM_LOG_STRUCT_POINTER, AIM_LOG_FLAG_VERBOSE);
        int n = epoll_wait(thread->epfd, events, ARRAY_SIZE(events),
                           1000 /* check finished flag once per second */);
        if (n < 0 && errno != EINTR) {
            LOG_ERROR("epoll_wait failed: %s", strerror(errno));
            abort();
        } else if (n > 0) {
            int j;
            for (j = 0; j < n; j++) {
                ind_ovs_handle_port_upcalls(thread, events[j].data.ptr);
            }
        }
    }

    return NULL;
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

        ind_ovs_fwd_read_lock();

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

        ind_ovs_fwd_read_unlock();

        struct msghdr msghdr = { 0 };
        msghdr.msg_iov = thread->tx_queue;
        msghdr.msg_iovlen = thread->tx_queue_len;
        (void) sendmsg(fd, &msghdr, 0);

        count += n;

        if (n != NUM_UPCALL_BUFFERS) {
            break;
        }
    }

    /* See ind_ovs_upcall_quiesce */
    /* TODO remove locking from the fast path */
    pthread_mutex_lock(&port->quiesce_lock);
    if (port->quiescing) {
        port->quiescing = false;
        pthread_cond_signal(&port->quiesce_cvar);
        pthread_mutex_unlock(&port->quiesce_lock);
        return;
    }
    pthread_mutex_unlock(&port->quiesce_lock);

    ind_ovs_upcall_rearm(port);
}

static void
ind_ovs_handle_one_upcall(struct ind_ovs_upcall_thread *thread,
                          struct ind_ovs_port *port,
                          struct nl_msg *msg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        abort();
    } else if (nlh->nlmsg_type == ovs_datapath_family) {
        /* Spurious message used to wake up an upcall thread. */
        /* See ind_ovs_upcall_quiesce. */
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

    if (gnlh->cmd == OVS_PACKET_CMD_MISS || !attrs[OVS_PACKET_ATTR_USERDATA]) {
        ind_ovs_handle_packet_miss(thread, port, msg, attrs);
    } else {
        ind_ovs_handle_packet_action(thread, port, msg, attrs);
    }
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
    memset(&pkey, 0, sizeof(pkey));
    ind_ovs_parse_key(key, &pkey);

    struct ind_ovs_cfr cfr;
    ind_ovs_key_to_cfr(&pkey, &cfr);

    struct pipeline_result *result = &thread->result;
    pipeline_result_reset(result);
    indigo_error_t err = pipeline_process(&cfr, result);
    if (err < 0) {
        return;
    }

    struct ind_ovs_flow_stats **stats_ptrs = xbuf_data(&result->stats);
    int num_stats_ptrs = xbuf_length(&result->stats) / sizeof(void *);
    int i;
    for (i = 0; i < num_stats_ptrs; i++) {
        struct ind_ovs_flow_stats *stats = stats_ptrs[i];
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, nla_len(packet));
    }

    /* Check for a single controller action */
    {
        uint32_t actions_length = xbuf_length(&result->actions);
        struct nlattr *first_action = xbuf_data(&result->actions);
        if (actions_length >= NLA_HDRLEN &&
                actions_length == NLA_ALIGN(first_action->nla_len) &&
                first_action->nla_type == IND_OVS_ACTION_CONTROLLER) {
            /*
             * The only action is sending the packet to the controller.
             * It's wasteful to send it all the way through the kernel
             * to be received as another upcall, so request a pktin
             * directly here.
             */
            uint8_t reason = *XBUF_PAYLOAD(first_action, uint8_t);
            ind_ovs_upcall_request_pktin(pkey.in_port, port, packet, key, reason);
            return;
        }
    }

    /* Reuse the incoming message for the packet execute */
    gnlh->cmd = OVS_PACKET_CMD_EXECUTE;

    struct nlattr *actions = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);
    ind_ovs_translate_actions(&pkey, &result->actions, msg);
    ind_ovs_nla_nest_end(msg, actions);

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
    if (ind_ovs_upcall_seen_key(thread, key)) {
        /* Create a kflow with the given key and actions. */
        ind_ovs_bh_request_kflow(key);
    }
}

static void
ind_ovs_handle_packet_action(struct ind_ovs_upcall_thread *thread,
                             struct ind_ovs_port *port,
                             struct nl_msg *msg, struct nlattr **attrs)
{
    struct nlattr *key = attrs[OVS_PACKET_ATTR_KEY];
    struct nlattr *packet = attrs[OVS_PACKET_ATTR_PACKET];
    struct nlattr *userdata = attrs[OVS_PACKET_ATTR_USERDATA];
    assert(key && packet && userdata);

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key(key, &pkey);

    uint8_t reason = (uint8_t)nla_get_u64(userdata);

    /* Send packet-in to controller */
    ind_ovs_upcall_request_pktin(pkey.in_port, port, packet, key, reason);
}

static void
ind_ovs_upcall_request_pktin(uint32_t port_no, struct ind_ovs_port *port,
                             struct nlattr *packet, struct nlattr *key, int reason)
{
    if (ind_ovs_benchmark_mode || aim_ratelimiter_limit(&port->pktin_limiter, monotonic_us()) == 0) {
        ind_ovs_bh_request_pktin(port_no, packet, key, reason);
    } else {
        if (aim_ratelimiter_limit(&port->upcall_log_limiter, monotonic_us()) == 0) {
            LOG_WARN("rate limiting packet-ins from port %s", port->ifname);
        }
    }
}

static void
ind_ovs_upcall_assign_thread(struct ind_ovs_port *port)
{
    static int idx;
    LOG_INFO("assigning port %s to upcall thread %d", port->ifname, idx);
    port->upcall_thread = ind_ovs_upcall_threads[idx++];
    idx = idx % ind_ovs_num_upcall_threads;
}

void
ind_ovs_upcall_register(struct ind_ovs_port *port)
{
    ind_ovs_upcall_assign_thread(port);
    struct epoll_event evt = { EPOLLIN|EPOLLONESHOT, { .ptr = port } };
    if (epoll_ctl(port->upcall_thread->epfd, EPOLL_CTL_ADD,
                  nl_socket_get_fd(port->notify_socket), &evt) < 0) {
        LOG_ERROR("failed to add to epoll set: %s", strerror(errno));
        abort();
    }
}

void
ind_ovs_upcall_unregister(struct ind_ovs_port *port)
{
    if (epoll_ctl(port->upcall_thread->epfd, EPOLL_CTL_DEL,
                  nl_socket_get_fd(port->notify_socket), NULL) < 0) {
        LOG_ERROR("failed to remove from epoll set: %s", strerror(errno));
        abort();
    }
}

/*
 * Removes the notify socket from the epoll set and blocks until no upcall
 * threads are using this port. Must only be called from the main thread.
 */
void ind_ovs_upcall_quiesce(struct ind_ovs_port *port)
{
    /*
     * Set the quiescing flag on the port and wait until an upcall thread
     * acknowledges that the port is quiesced. In this case the upcall
     * thread will not rearm the port's notify socket in the epoll set,
     * so we are guaranteed that no upcall threads are processing upcalls
     * on this port unless we rearm it again.
     *
     * We send a netlink message that causes the kernel to send a reply
     * to ensure that an upcall thread processes this socket. The upcall
     * thread may acknowledge quiescing in the course of processing the
     * usual packet misses as well. The message content is irrelevant.
     */
    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_datapath_family,
                                              OVS_DP_CMD_GET);

    pthread_mutex_lock(&port->quiesce_lock);
    nl_send_auto(port->notify_socket, msg);
    port->quiescing = true;
    while (port->quiescing) {
        pthread_cond_wait(&port->quiesce_cvar, &port->quiesce_lock);
    }
    pthread_mutex_unlock(&port->quiesce_lock);

    ind_ovs_nlmsg_freelist_free(msg);
}

static void
ind_ovs_upcall_rearm(struct ind_ovs_port *port)
{
    struct epoll_event evt = { EPOLLIN|EPOLLONESHOT, { .ptr = port } };
    if (epoll_ctl(port->upcall_thread->epfd, EPOLL_CTL_MOD,
                  nl_socket_get_fd(port->notify_socket), &evt) < 0) {
        LOG_ERROR("failed to rearm epoll entry: %s", strerror(errno));
        abort();
    }
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
        struct ind_ovs_upcall_thread *thread = calloc(1, sizeof(*thread));
        if (thread == NULL) {
            LOG_ERROR("Failed to create upcall thread");
            abort();
        }

        thread->epfd = epoll_create(1);
        if (thread->epfd < 0) {
            LOG_ERROR("failed to create epoll set: %s", strerror(errno));
            abort();
        }

        pipeline_result_init(&thread->result);

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

        if (pthread_create(&thread->pthread, NULL,
                        ind_ovs_upcall_thread_main, thread) < 0) {
            LOG_ERROR("failed to start upcall thread");
            abort();
        }

        char threadname[16];
        snprintf(threadname, sizeof(threadname), "upcall thr %d", i);
        pthread_setname_np(thread->pthread, threadname);

        ind_ovs_upcall_threads[i] = thread;
    }
}

void
ind_ovs_upcall_finish(void)
{
    int i, j;

    for (i = 0; i < ind_ovs_num_upcall_threads; i++) {
        struct ind_ovs_upcall_thread *thread = ind_ovs_upcall_threads[i];
        thread->finished = true;
    }

    __sync_synchronize();

    for (i = 0; i < ind_ovs_num_upcall_threads; i++) {
        struct ind_ovs_upcall_thread *thread = ind_ovs_upcall_threads[i];
        pthread_join(thread->pthread, NULL);
        close(thread->epfd);
        pipeline_result_cleanup(&thread->result);
        for (j = 0; j < NUM_UPCALL_BUFFERS; j++) {
            nlmsg_free(thread->msgs[j]);
        }
        free(thread);
        ind_ovs_upcall_threads[i] = NULL;
    }
}
