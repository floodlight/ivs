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

#ifndef OVS_DRIVER_INT_H
#define OVS_DRIVER_INT_H


#include "ovsdriver_log.h"
#include <AIM/aim_list.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stdbool.h>
#include <pthread.h>
#include "indigo/error.h"
#include "indigo/types.h"
#include "openvswitch.h"
#include "AIM/aim_rl.h"
#include "AIM/aim_utils.h"
#include "xbuf/xbuf.h"
#include "ivs/ivs.h"
#include "pipeline/pipeline.h"
#include "tcam/tcam.h"
#include "BigHash/bighash.h"
#include <stats/stats.h>
#include <debug_counter/debug_counter.h>

#define IND_OVS_MAX_PORTS 1024

#define IND_OVS_NUM_TABLES 32

/*
 * Special pre-created ports.
 */
#define IND_OVS_TUN_LOOPBACK_PORT_NO (IND_OVS_MAX_PORTS-2)
#define IND_OVS_TUN_GRE_PORT_NO (IND_OVS_MAX_PORTS-1)

/*
 * Maximum size of a message allocated by nlmsg_alloc. Fixed size messages
 * shorter than this need no error handling during construction.
 *
 * This is sized to support MTU 9000 jumbo frames. Due to a bug in libnl it
 * actually needs to be twice as large as the maximum payload we'll use.
 */
#define IND_OVS_DEFAULT_MSG_SIZE 32768

/*
 * Limit the number of kernel flows for a given input port to prevent
 * a malicious guest from creating too many.
 * TODO should be configurable.
 * TODO increase or unlimit this for uplink ports?
 */
#define IND_OVS_MAX_KFLOWS_PER_PORT 16384

/* Per-port minimum average interval between packet-ins (in us) */
#define PORT_PKTIN_INTERVAL 5000

/* Per-port packet-in burstiness tolerance. */
#define PORT_PKTIN_BURST_SIZE 32

/* Overall minimum average interval between packet-ins (in us) */
#define PKTIN_INTERVAL 3000

/* Overall packet-in burstiness tolerance. */
#define PKTIN_BURST_SIZE 32

/* Short hand logging macros */
#define LOG_ERROR(fmt, ...) AIM_LOG_ERROR(fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) AIM_LOG_WARN(fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) AIM_LOG_INFO(fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) AIM_LOG_VERBOSE(fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) AIM_LOG_TRACE(fmt, ##__VA_ARGS__)

#define LOXI_SUCCESS(x)  ((x) == OF_ERROR_NONE)
#define LOXI_FAILURE(x)  (!LOXI_SUCCESS(x))

#define PPE_FAILURE(x)  ((x) < 0)
#define PPE_SUCCESS(x)  (!PPE_FAILURE(x))


/* Internal datastructures */

struct ind_ovs_upcall_thread;

/*
 * A port in the datapath.
 *
 * Stored in the ind_ovs_ports array.
 */
struct ind_ovs_port {
    char ifname[IFNAMSIZ]; /* Linux network interface name */
    uint32_t dp_port_no; /* Kernel datapath port number */
    int ifflags; /* Linux interface flags */
    enum ovs_vport_type type;
    of_mac_addr_t mac_addr;
    unsigned no_packet_in : 1;
    unsigned no_flood : 1;
    unsigned admin_down : 1;
    unsigned is_uplink : 1;
    uint32_t num_kflows; /* Number of kflows with this in_port */
    struct nl_sock *notify_socket; /* Netlink socket for upcalls */
    struct nl_sock *pktin_socket; /* Netlink socket for packet-ins */
    aim_ratelimiter_t upcall_log_limiter;
    aim_ratelimiter_t pktin_limiter;
    struct ind_ovs_upcall_thread *upcall_thread;
    struct ind_ovs_port_counters pcounters;
};

/*
 * A cached kernel flow.
 *
 * A kflow caches the actions for a particular openvswitch flow key. A kflow
 * may use multiple OpenFlow flows while traveling through the pipeline.
 */
struct ind_ovs_kflow {
    struct list_links global_links; /* (global) kflows */
    struct list_links bucket_links; /* (global) kflow_buckets[] */
    struct stats stats; /* periodically synchronized with the kernel */
    uint16_t in_port;
    uint16_t num_stats_handles; /* size of stats_handles array */
    uint16_t actions_len; /* length of actions blob */
    uint64_t last_used; /* monotonic time in ms */
    struct ind_ovs_parsed_key mask;
    void *actions; /* payload of actions nlattr */
    struct stats_handle *stats_handles;
    struct nlattr key[0];
};

/* An OpenFlow group bucket */
struct ind_ovs_group_bucket {
    struct xbuf actions;
    struct stats_handle stats_handle;
};

/* An OpenFlow group */
struct ind_ovs_group {
    bighash_entry_t hash_entry;
    uint32_t id;
    uint8_t type;
    uint16_t num_buckets;
    struct ind_ovs_group_bucket *buckets;
};

/* Internal functions */

/* Translate an OVS key into a flat struct */
void ind_ovs_parse_key(struct nlattr *key, struct ind_ovs_parsed_key *pkey);

/* Translate a parsed key into nlattrs */
void ind_ovs_emit_key(const struct ind_ovs_parsed_key *key, struct nl_msg *msg, bool omit_zeroes);

/* Translate an OVS key into an OpenFlow match object */
void ind_ovs_key_to_match(const struct ind_ovs_parsed_key *pkey, of_version_t version, of_match_t *match);

/* Management of the kernel flow table */
indigo_error_t ind_ovs_kflow_add(const struct nlattr *key);
void ind_ovs_kflow_sync_stats(struct ind_ovs_kflow *kflow);
void ind_ovs_kflow_invalidate(struct ind_ovs_kflow *kflow);
void ind_ovs_kflow_invalidate_all(void);
void ind_ovs_kflow_expire(void);
void ind_ovs_kflow_module_init(void);

/* Management of the port set */
void ind_ovs_port_init(void);
void ind_ovs_port_finish(void);
void ind_ovs_port_added(uint32_t port_no, const char *ifname, enum ovs_vport_type type, of_mac_addr_t mac_addr);
void ind_ovs_port_deleted(uint32_t port_no);
struct ind_ovs_port *ind_ovs_port_lookup(of_port_no_t port_no);
struct ind_ovs_port *ind_ovs_port_lookup_by_name(const char *ifname);

/* Interface of the uplink submodule */
bool ind_ovs_uplink_check_by_name(const char *name);
bool ind_ovs_uplink_check(of_port_no_t port_no);
of_port_no_t ind_ovs_uplink_first(void);

/* Interface of the upcall submodule */
void ind_ovs_upcall_init(void);
void ind_ovs_upcall_enable(void);
void ind_ovs_upcall_finish(void);
void ind_ovs_upcall_register(struct ind_ovs_port *port);
void ind_ovs_upcall_unregister(struct ind_ovs_port *port);
void ind_ovs_upcall_respawn(void);

/* Interface of the multicast submodule */
void ind_ovs_multicast_init(void);

/* Interface of the group submodule */
void ind_ovs_group_module_init(void);
struct ind_ovs_group *ind_ovs_group_lookup(uint32_t id);

/* Interface of the pktin submodule */
void ind_ovs_pktin_init(void);
void ind_ovs_pktin_register(struct ind_ovs_port *port);
void ind_ovs_pktin_unregister(struct ind_ovs_port *port);

/* Interface of the VLAN stats submodule */
void ind_ovs_vlan_stats_init(void);

/* Interface of the barrier submodule */
void ind_ovs_barrier_init(void);
void ind_ovs_barrier_defer_revalidation_internal(void);

/* Log Netlink attributes in human readable form */
void ind_ovs_dump_nested(const struct nlattr *nla, void (*cb)(const struct nlattr *attr));
void ind_ovs_dump_dp_attr(const struct nlattr *nla);
void ind_ovs_dump_packet_attr(const struct nlattr *nla);
void ind_ovs_dump_vport_attr(const struct nlattr *nla);
void ind_ovs_dump_key_attr(const struct nlattr *nla);
void ind_ovs_dump_flow_attr(const struct nlattr *nla);
void ind_ovs_dump_userspace_attr(const struct nlattr *nla);
void ind_ovs_dump_sample_attr(const struct nlattr *nla);
void ind_ovs_dump_action_attr(const struct nlattr *nla);
void ind_ovs_dump_key(const struct nlattr *key);

/* Return the name of the given generic netlink command. */
const char *ind_ovs_cmd_str(int family, uint8_t cmd);

/* Log Netlink messages in human readable from */
void ind_ovs_dump_msg(const struct nlmsghdr *nlh);

/* Utility functions */
uint32_t get_entropy(void);
uint64_t monotonic_us(void);
struct nl_sock *ind_ovs_create_nlsock(void);
struct nl_msg* ind_ovs_create_nlmsg(int family, int cmd);
struct nl_msg *ind_ovs_recv_nlmsg(struct nl_sock *sk);
void ind_ovs_nla_nest_end(struct nl_msg *msg, struct nlattr *start);
void ind_ovs_nlmsg_freelist_init(void);
void ind_ovs_nlmsg_freelist_finish(void);
struct nl_msg *ind_ovs_nlmsg_freelist_alloc(void);
void ind_ovs_nlmsg_freelist_free(struct nl_msg *msg);
indigo_error_t ind_ovs_get_interface_flags(const char *ifname, int *flags);
indigo_error_t ind_ovs_set_interface_flags(const char *ifname, int flags);
void ind_ovs_get_interface_features(const char *ifname, uint32_t *curr, uint32_t *advertised, uint32_t *supported, uint32_t *peer, int version);
indigo_error_t write_file(const char *filename, const char *str);

/* Sends msg, frees it, and waits for a reply. */
int ind_ovs_transact(struct nl_msg *msg);
int ind_ovs_transact_nofree(struct nl_msg *msg);
int ind_ovs_transact_reply(struct nl_msg *msg, struct nlmsghdr **reply);


/* Global state */

/* Interface index of the local interface for the datapath. */
extern int ind_ovs_dp_ifindex;

/* Main netlink socket. Used for synchronous transactions with the datapath. */
extern struct nl_sock *ind_ovs_socket;

/* Generic netlink families. */
extern int ovs_datapath_family, ovs_packet_family, ovs_vport_family, ovs_flow_family;

/* All ports on the switch */
extern struct ind_ovs_port *ind_ovs_ports[IND_OVS_MAX_PORTS];

/*
 * Many benchmarks have similar behavior to malicious VMs and would trigger our
 * rate limiters and other protections. This flag turns these mechanisms off.
 * Set it with the environment variable INDIGO_BENCHMARK=1.
 */
extern bool ind_ovs_benchmark_mode;

/*
 * When debugging the controller (and using verbose logging on the switch)
 * it's often helpful to see the pipeline logs for every packet. This flag
 * prevents IVS from installing kernel flows, so every packet will be
 * received as an upcall.
 * Set it with the environment variable IVS_DISABLE_KFLOWS=1.
 */
extern bool ind_ovs_disable_kflows;

/*
 * Disable megaflows for debugging and performance comparison.
 * Set with the environment variable IVS_DISABLE_MEGAFLOWS=1.
 */
extern bool ind_ovs_disable_megaflows;

/*
 * Random number used to prevent guests from deliberately causing hash
 * collisions.
 */
extern uint32_t ind_ovs_salt;

/*
 * Netlink socket to be used for sending pktin's to the controller from
 * pktout path.
 */
extern struct ind_ovs_pktin_socket ind_ovs_pktout_soc;

#endif
