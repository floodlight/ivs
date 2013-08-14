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
#include "tunnel.h"
#include "AIM/aim_rl.h"
#include "AIM/aim_utils.h"
#include "flowtable/flowtable.h"
#include "xbuf/xbuf.h"

#define IND_OVS_MAX_PORTS 1024

#define IND_OVS_NUM_TABLES 16

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

/* Use instead of assert for cases we should eventually handle. */
#define NYI(x) assert(!(x))

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

#define ARRAY_SIZE(a)  (sizeof(a) / sizeof((a)[0]))

#define ALIGN8(x) (((x) + 7) & ~7)

/* Manage a uint64_t bitmap of OVS key attributes. */
#define ATTR_BITMAP_TEST(bitmap, attr) ((bitmap & (1 << (attr))) != 0)
#define ATTR_BITMAP_SET(bitmap, attr) (bitmap |= (1 << (attr)))
#define ATTR_BITMAP_CLEAR(bitmap, attr) (bitmap &= ~(1 << (attr)))

#define VLAN_CFI_BIT (1<<12)
#define VLAN_TCI(vid, pcp) ( (((pcp) & 0x7) << 13) | ((vid) & 0xfff) )
#define VLAN_VID(tci) ((tci) & 0xfff)
#define VLAN_PCP(tci) ((tci) >> 13)

/* Same as VLAN_TCI above except the vid includes the CFI bit */
#define VLAN_TCI_WITH_CFI(vid, pcp) ( (((pcp) & 0x7) << 13) | ((vid) & 0x1fff) )


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
    of_mac_addr_t mac_addr;
    uint32_t config; /* OpenFlow config */
    uint32_t num_kflows; /* Number of kflows with this in_port */
    struct nl_sock *notify_socket; /* Netlink socket for upcalls */
    aim_ratelimiter_t upcall_log_limiter;
    aim_ratelimiter_t pktin_limiter;
    /* See ind_ovs_upcall_quiesce */
    bool quiescing;
    pthread_mutex_t quiesce_lock;
    pthread_cond_t quiesce_cvar;
    struct ind_ovs_upcall_thread *upcall_thread;
};

/*
 * X-macro representation of the OVS key (nlattr type, key field, type).
 */
#define OVS_KEY_FIELDS \
    field(OVS_KEY_ATTR_PRIORITY,  priority,  uint32_t) \
    field(OVS_KEY_ATTR_IN_PORT,   in_port,   uint32_t) \
    field(OVS_KEY_ATTR_ETHERNET,  ethernet,  struct ovs_key_ethernet) \
    field(OVS_KEY_ATTR_VLAN,      vlan,      uint16_t) \
    field(OVS_KEY_ATTR_ETHERTYPE, ethertype, uint16_t) \
    field(OVS_KEY_ATTR_IPV4,      ipv4,      struct ovs_key_ipv4) \
    field(OVS_KEY_ATTR_IPV6,      ipv6,      struct ovs_key_ipv6) \
    field(OVS_KEY_ATTR_TCP,       tcp,       struct ovs_key_tcp) \
    field(OVS_KEY_ATTR_UDP,       udp,       struct ovs_key_udp) \
    field(OVS_KEY_ATTR_ICMP,      icmp,      struct ovs_key_icmp) \
    field(OVS_KEY_ATTR_ICMPV6,    icmpv6,    struct ovs_key_icmpv6) \
    field(OVS_KEY_ATTR_ARP,       arp,       struct ovs_key_arp) \
    field(OVS_KEY_ATTR_ND,        nd,        struct ovs_key_nd)

#define OVS_TUNNEL_KEY_FIELDS \
    field(OVS_TUNNEL_KEY_ATTR_ID,       id,       uint64_t) \
    field(OVS_TUNNEL_KEY_ATTR_IPV4_SRC, ipv4_src, uint32_t) \
    field(OVS_TUNNEL_KEY_ATTR_IPV4_DST, ipv4_dst, uint32_t) \
    field(OVS_TUNNEL_KEY_ATTR_TOS,      tos,      uint8_t) \
    field(OVS_TUNNEL_KEY_ATTR_TTL,      ttl,      uint8_t)

/*
 * Efficient representation of the OVS flow key.
 *
 * This is used only as a temporary object which is easier to work with
 * than the OVS_ATTR_KEY_* netlink attributes. It contains a subset of the
 * information in the real key which is why we must store that instead.
 */
struct ind_ovs_parsed_key {
    uint64_t populated; /* bitmap of OVS_KEY_ATTR_* */
    uint32_t priority;
    uint32_t in_port;
    struct ovs_key_ethernet ethernet;
    uint16_t vlan; /* VLAN TCI */
    uint16_t ethertype;
    union { /* Network protocols */
        struct ovs_key_ipv4 ipv4;
        struct ovs_key_ipv6 ipv6;
    };
    union { /* Transport protocols */
        struct ovs_key_tcp tcp;
        struct ovs_key_udp udp;
        struct ovs_key_icmp icmp;
        struct ovs_key_icmpv6 icmpv6;
        struct ovs_key_arp arp;
        struct ovs_key_nd nd;
    };
    struct {
        uint64_t id;
        uint32_t ipv4_src;
        uint32_t ipv4_dst;
        uint8_t tos;
        uint8_t ttl;
    } tunnel;
};

/*
 * Canonical Flow Representation
 * Compressed version of the OpenFlow match fields for use in matching.
 * Does not contain the non-OpenFlow fields of the flow key.
 * Only contains OF 1.0 fields for now.
 * Wildcarded fields must be zeroed in the flow entry's CFR.
 * sizeof(struct ind_ovs_cfr) must be a multiple of 8.
 * All fields are in network byte order except in_port.
 */

struct ind_ovs_cfr {
    uint8_t dl_dst[6];          /* Ethernet destination address. */
    uint8_t dl_src[6];          /* Ethernet source address. */
    uint16_t in_port;           /* Input switch port. */
    uint16_t dl_type;           /* Ethernet frame type. */
    uint16_t dl_vlan;           /* VLAN id and priority, same as wire format
                                   plus CFI bit set if tag present. */
    uint8_t nw_tos;             /* IPv4 DSCP. */
    uint8_t nw_proto;           /* IP protocol. */
    uint32_t nw_src;            /* IP source address. */
    uint32_t nw_dst;            /* IP destination address. */
    uint16_t tp_src;            /* TCP/UDP source port. */
    uint16_t tp_dst;            /* TCP/UDP destination port. */
    uint32_t ipv6_src[4];       /* IPv6 source address. */
    uint32_t ipv6_dst[4];       /* IPv6 destination address. */
} __attribute__ ((aligned (8)));

AIM_STATIC_ASSERT(CFR_SIZE, sizeof(struct ind_ovs_cfr) == 8*8);
AIM_STATIC_ASSERT(CFR_SIZE, sizeof(struct ind_ovs_cfr) == FLOWTABLE_KEY_SIZE);

/*
 * Derived from a flow's actions/instructions.
 */
struct ind_ovs_flow_effects {
    struct xbuf apply_actions;
    struct xbuf write_actions;
    uint64_t metadata;
    uint64_t metadata_mask;
    uint32_t meter_id;
    uint8_t next_table_id;
    unsigned clear_actions : 1;
};

struct ind_ovs_flow_stats {
    uint64_t packets;
    uint64_t bytes;
};

/*
 * An OpenFlow flow.
 */
struct ind_ovs_flow {
    struct flowtable_entry fte;

    /* Updated periodically from the kernel flows */
    struct ind_ovs_flow_stats stats;

    indigo_cookie_t  flow_id;
    struct list_links flow_id_links; /* (global) ind_ovs_flow_id_buckets */

    /* Modified by of_flow_modify messages */
    struct ind_ovs_flow_effects effects;

    uint8_t table_id;
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
    struct ind_ovs_flow_stats stats; /* periodically synchronized with the kernel */
    uint16_t in_port;
    uint16_t num_stats_ptrs; /* size of stats_ptrs array */
    uint16_t actions_len; /* length of actions blob */
    uint64_t last_used; /* monotonic time in ms */
    void *actions; /* payload of actions nlattr */
    struct ind_ovs_flow_stats **stats_ptrs;
    struct nlattr key[0];
};

/* Configuration for the bsn_pktin_suppression extension */
struct ind_ovs_pktin_suppression_cfg {
    uint8_t enabled;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint16_t priority;
    uint64_t cookie;
};

/* An OpenFlow table */
struct ind_ovs_table {
    struct flowtable *ft;
    uint32_t num_flows;
    uint32_t max_flows;
    struct ind_ovs_flow_stats matched_stats;
    struct ind_ovs_flow_stats missed_stats;
    of_table_name_t name;
};

/*
 * Result of the forwarding pipeline (ind_ovs_fwd_process)
 *
 * See ind_ovs_fwd_result_{init,reset,cleanup}.
 */
struct ind_ovs_fwd_result {
    /*
     * List of IVS actions.
     */
    struct xbuf actions;

    /*
     * These stats objects may belong to flows or tables (and in the future
     * meters or groups). For example, every table a packet matched in will
     * have its matched_stats field added here.
     *
     * This is sized at 2x the number of tables because each table can
     * contribute a table stats and flow stats entry. This will have to
     * change when we add meters and groups.
     */
    int num_stats_ptrs;
    struct ind_ovs_flow_stats *stats_ptrs[IND_OVS_NUM_TABLES*2];
};

/* Internal functions */

/* Translate an OVS key into a flat struct */
void ind_ovs_parse_key(struct nlattr *key, struct ind_ovs_parsed_key *pkey);

/* Translate OpenFlow actions into IVS actions */
indigo_error_t ind_ovs_translate_openflow_actions(of_list_action_t *actions, struct xbuf *xbuf, bool table_miss);

/* Translate IVS actions into OVS actions */
void ind_ovs_translate_actions(const struct ind_ovs_parsed_key *pkey, struct xbuf *actions, struct nl_msg *msg);

/* Translate an OVS key into an OpenFlow match object */
void ind_ovs_key_to_match(const struct ind_ovs_parsed_key *pkey, of_match_t *match);

/* Translate an OVS key into a CFR */
void ind_ovs_key_to_cfr(const struct ind_ovs_parsed_key *pkey, struct ind_ovs_cfr *cfr);

/* Translate an OpenFlow match into a CFR and mask */
void ind_ovs_match_to_cfr(const of_match_t *match, struct ind_ovs_cfr *cfr, struct ind_ovs_cfr *mask);

/* Internal interfaces to the forwarding module */
indigo_error_t ind_ovs_fwd_init(void);
void ind_ovs_fwd_finish(void);
indigo_error_t ind_ovs_fwd_process(const struct ind_ovs_parsed_key *pkey, struct ind_ovs_fwd_result *result);
void ind_ovs_fwd_result_init(struct ind_ovs_fwd_result *result);
void ind_ovs_fwd_result_reset(struct ind_ovs_fwd_result *result);
void ind_ovs_fwd_result_cleanup(struct ind_ovs_fwd_result *result);
indigo_error_t ind_fwd_pkt_in(of_port_no_t of_port_num, uint8_t *data, unsigned int len, unsigned reason, of_match_t *match);

/*
 * Synchronization of the flow table between the main thread and upcall
 * threads. Only the main thread is allowed to mutate the flowtable, and when
 * it does so it must hold the writer lock (private). Upcall threads must hold
 * the reader lock while matching in the flowtable and while referencing the
 * resulting struct ind_ovs_flow.
 *
 * Also protects the ind_ovs_port array, since upcall threads access it
 * while translating actions.
 */
void ind_ovs_fwd_read_lock();
void ind_ovs_fwd_read_unlock();
void ind_ovs_fwd_write_lock();
void ind_ovs_fwd_write_unlock();

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
void ind_ovs_port_added(uint32_t port_no, const char *ifname, of_mac_addr_t mac_addr);
void ind_ovs_port_deleted(uint32_t port_no);
struct ind_ovs_port *ind_ovs_port_lookup(of_port_no_t port_no);
struct ind_ovs_port *ind_ovs_port_lookup_by_name(const char *ifname);

/* Interface of the upcall submodule */
void ind_ovs_upcall_init(void);
void ind_ovs_upcall_finish(void);
void ind_ovs_upcall_register(struct ind_ovs_port *port);
void ind_ovs_upcall_unregister(struct ind_ovs_port *port);
void ind_ovs_upcall_quiesce(struct ind_ovs_port *port);

/* Interface of the bottom-half submodule */
void ind_ovs_bh_init();
void ind_ovs_bh_request_kflow(struct nlattr *key);
void ind_ovs_bh_request_pktin(uint32_t in_port, struct nlattr *packet, struct nlattr *key, int reason);

/* Interface of the multicast submodule */
void ind_ovs_multicast_init(void);

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
void ind_ovs_dump_cfr(const struct ind_ovs_cfr *cfr);

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
 * Random number used to prevent guests from deliberately causing hash
 * collisions.
 */
extern uint32_t ind_ovs_salt;

/*
 * Configured OpenFlow version.
 */
extern int ind_ovs_version;

/*
 * OpenFlow tables. Protected by ind_ovs_fwd_{read,write}_{lock,unlock}.
 */
struct ind_ovs_table ind_ovs_tables[IND_OVS_NUM_TABLES];

/*
 * Configuration for the bsn_pktin_suppression extension.
 */
extern struct ind_ovs_pktin_suppression_cfg ind_ovs_pktin_suppression_cfg;

#endif
