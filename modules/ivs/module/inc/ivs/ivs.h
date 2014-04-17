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

#define VLAN_CFI_BIT (1<<12)
#define VLAN_TCI(vid, pcp) ( (((pcp) & 0x7) << 13) | ((vid) & 0xfff) )
#define VLAN_VID(tci) ((tci) & 0xfff)
#define VLAN_PCP(tci) ((tci) >> 13)

/* Same as VLAN_TCI above except the vid includes the CFI bit */
#define VLAN_TCI_WITH_CFI(vid, pcp) ( (((pcp) & 0x7) << 13) | ((vid) & 0x1fff) )

#define IP_DSCP_MASK 0xfc
#define IP_ECN_MASK 0x03
#define IPV6_FLABEL_MASK 0x000fffff

#define ARRAY_SIZE(a)  (sizeof(a) / sizeof((a)[0]))

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
    unsigned disable_src_mac_check : 1;
    unsigned arp_offload : 1;
    unsigned dhcp_offload : 1;
    unsigned disable_split_horizon_check : 1;
    unsigned permit : 1;
    unsigned deny : 1;
    unsigned packet_of_death : 1;
};

struct ind_ovs_flow_stats {
    uint64_t packets;
    uint64_t bytes;
};

/*
 * Canonical Flow Representation
 * Compressed version of the OpenFlow match fields for use in matching.
 * Does not contain the non-OpenFlow fields of the flow key.
 * Wildcarded fields must be zeroed in the flow entry's CFR.
 * sizeof(struct ind_ovs_cfr) must be a multiple of 8.
 * All fields are in network byte order except in_port, lag_id, the
 * class_ids, egr_port_group_id, and global_vrf_allowed.
 */

struct ind_ovs_cfr {
    uint32_t in_port;           /* Input switch port. */
    uint8_t dl_dst[6];          /* Ethernet destination address. */
    uint8_t dl_src[6];          /* Ethernet source address. */
    uint16_t dl_type;           /* Ethernet frame type. */
    uint16_t dl_vlan;           /* VLAN id and priority, same as wire format
                                   plus CFI bit set if tag present. */
    uint8_t nw_tos;             /* IPv4 DSCP. */
    uint8_t nw_proto;           /* IP protocol. */
    uint16_t global_vrf_allowed:1;  /* bsn_global_vrf_allowed extension */
    uint32_t pad:15;
    uint32_t nw_src;            /* IP source address. */
    uint32_t nw_dst;            /* IP destination address. */
    uint16_t tp_src;            /* TCP/UDP source port. */
    uint16_t tp_dst;            /* TCP/UDP destination port. */
    uint32_t ipv6_src[4];       /* IPv6 source address. */
    uint32_t ipv6_dst[4];       /* IPv6 destination address. */
    uint32_t in_ports[4];       /* bsn_in_ports extension */
    uint32_t lag_id;            /* bsn_lag_id extension */
    uint32_t vrf;               /* bsn_vrf extension */
    uint32_t l3_interface_class_id;  /* bsn_l3_interface_class_id extension */
    uint32_t l3_src_class_id;   /* bsn_l3_src_class_id extension */
    uint32_t l3_dst_class_id;   /* bsn_l3_dst_class_id extension */
    uint32_t egr_port_group_id; /* bsn_egr_port_group_id extension */
    uint32_t pad2;
} __attribute__ ((aligned (8)));

AIM_STATIC_ASSERT(CFR_SIZE, sizeof(struct ind_ovs_cfr) == 14*8);

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

#define IVS_MAX_BITMAP_IN_PORT 127

/*
 * Exported from OVSDriver for use by the pipeline
 */
struct ind_ovs_flow_effects *ind_ovs_fwd_pipeline_lookup(int table_id, struct ind_ovs_cfr *cfr, struct xbuf *stats);
indigo_error_t ind_ovs_group_select(uint32_t id, uint32_t hash, struct xbuf **actions);
indigo_error_t ind_ovs_group_indirect(uint32_t id, struct xbuf **actions);

/* Translate an OVS key into a CFR */
void ind_ovs_key_to_cfr(const struct ind_ovs_parsed_key *pkey, struct ind_ovs_cfr *cfr);

/* Translate an OpenFlow match into a CFR and mask */
void ind_ovs_match_to_cfr(const of_match_t *match, struct ind_ovs_cfr *cfr, struct ind_ovs_cfr *mask);

#endif
