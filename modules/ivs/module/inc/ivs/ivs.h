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
 * class_ids, and global_vrf_allowed.
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
} __attribute__ ((aligned (8)));

AIM_STATIC_ASSERT(CFR_SIZE, sizeof(struct ind_ovs_cfr) == 13*8);

#define IVS_MAX_BITMAP_IN_PORT 127

/*
 * Exported from OVSDriver for use by the pipeline
 */
struct ind_ovs_flow_effects *ind_ovs_fwd_pipeline_lookup(int table_id, struct ind_ovs_cfr *cfr, struct xbuf *stats);
indigo_error_t ind_ovs_group_select(uint32_t id, uint32_t hash, struct xbuf **actions);
indigo_error_t ind_ovs_group_indirect(uint32_t id, struct xbuf **actions);

#endif
