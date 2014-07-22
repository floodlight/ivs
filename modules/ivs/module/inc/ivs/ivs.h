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

/*
 * ivs - Types and functions shared across IVS modules
 */

#ifndef IVS_H
#define IVS_H

#include "openvswitch.h"
#include <stdint.h>
#include <xbuf/xbuf.h>
#include <indigo/error.h>
#include <loci/loci.h>
#include <stats/stats.h>
#include <indigo/of_connection_manager.h>

#define VLAN_CFI_BIT (1<<12)
#define VLAN_TCI(vid, pcp) ( (((pcp) & 0x7) << 13) | ((vid) & 0xfff) )
#define VLAN_VID(tci) ((tci) & 0xfff)
#define VLAN_PCP(tci) ((tci) >> 13)

/* Same as VLAN_TCI above except the vid includes the CFI bit */
#define VLAN_TCI_WITH_CFI(vid, pcp) ( (((pcp) & 0x7) << 13) | ((vid) & 0x1fff) )

#define IP_DSCP_MASK 0xfc
#define IP_ECN_MASK 0x03
#define IPV6_FLABEL_MASK 0x000fffff

#define ALIGN8(x) (((x) + 7) & ~7)

/* Manage a uint64_t bitmap of OVS key attributes. */
#define ATTR_BITMAP_TEST(bitmap, attr) ((bitmap & (1 << (attr))) != 0)
#define ATTR_BITMAP_SET(bitmap, attr) (bitmap |= (1 << (attr)))
#define ATTR_BITMAP_CLEAR(bitmap, attr) (bitmap &= ~(1 << (attr)))

/* Use instead of assert for cases we should eventually handle. */
#define NYI(x) assert(!(x))

#define IVS_PKTIN_USERDATA(reason, metadata) (reason) | ((uint64_t)(metadata) << 8)
#define IVS_PKTIN_REASON(userdata) (userdata) & 0xff
#define IVS_PKTIN_METADATA(userdata) (userdata) >> 8

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
    field(OVS_KEY_ATTR_ND,        nd,        struct ovs_key_nd) \
    field(OVS_KEY_ATTR_TCP_FLAGS, tcp_flags, uint16_t)

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
    uint16_t tcp_flags;
    struct {
        uint64_t id;
        uint32_t ipv4_src;
        uint32_t ipv4_dst;
        uint8_t tos;
        uint8_t ttl;
    } tunnel;
};

struct ind_ovs_port_counters {
    struct stats_handle rx_unicast_stats_handle;
    struct stats_handle tx_unicast_stats_handle;
    struct stats_handle rx_broadcast_stats_handle;
    struct stats_handle tx_broadcast_stats_handle;
    struct stats_handle rx_multicast_stats_handle;
    struct stats_handle tx_multicast_stats_handle;
};

/*
 * Exported from OVSDriver for use by the pipeline
 */
indigo_error_t ind_ovs_group_select(uint32_t id, uint32_t hash, struct xbuf **actions);
indigo_error_t ind_ovs_group_indirect(uint32_t id, struct xbuf **actions);
void ind_ovs_fwd_write_lock();
void ind_ovs_fwd_write_unlock();
extern uint32_t ind_ovs_salt;
indigo_error_t ind_ovs_translate_openflow_actions(of_list_action_t *actions, struct xbuf *xbuf, bool table_miss);
struct stats_handle *ind_ovs_rx_vlan_stats_select(uint16_t vlan_vid);
struct stats_handle *ind_ovs_tx_vlan_stats_select(uint16_t vlan_vid);
struct ind_ovs_port_counters *ind_ovs_port_stats_select(of_port_no_t port_no);
uint32_t ind_ovs_port_lookup_netlink(of_port_no_t port_no);
void ind_ovs_barrier_defer_revalidation(indigo_cxn_id_t cxn_id);

#endif
