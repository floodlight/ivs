#ifndef CFR_H
#define CFR_H

#include <stdint.h>

/*
 * Canonical Flow Representation
 * Compressed version of the OpenFlow match fields for use in matching.
 * Does not contain the non-OpenFlow fields of the flow key.
 * Wildcarded fields must be zeroed in the flow entry's CFR.
 * sizeof(struct pipeline_standard_cfr) must be a multiple of 8.
 * All fields are in network byte order except in_port, lag_id, the
 * class_ids, egr_port_group_id, and global_vrf_allowed.
 */

struct pipeline_standard_cfr {
    uint32_t in_port;           /* Input switch port. */
    uint8_t dl_dst[6];          /* Ethernet destination address. */
    uint8_t dl_src[6];          /* Ethernet source address. */
    uint16_t dl_type;           /* Ethernet frame type. */
    uint16_t dl_vlan;           /* VLAN id and priority, same as wire format
                                   plus CFI bit set if tag present. */
    uint8_t nw_tos;             /* IPv4 DSCP. */
    uint8_t nw_proto;           /* IP protocol. */
    uint16_t pad;
    uint32_t nw_src;            /* IP source address. */
    uint32_t nw_dst;            /* IP destination address. */
    uint16_t tp_src;            /* TCP/UDP source port. */
    uint16_t tp_dst;            /* TCP/UDP destination port. */
    uint32_t ipv6_src[4];       /* IPv6 source address. */
    uint32_t ipv6_dst[4];       /* IPv6 destination address. */
    uint32_t pad2;
} __attribute__ ((aligned (8)));

AIM_STATIC_ASSERT(CFR_SIZE, sizeof(struct pipeline_standard_cfr) == 9*8);

/* Translate an OVS key into a CFR */
void pipeline_standard_key_to_cfr(const struct ind_ovs_parsed_key *pkey, struct pipeline_standard_cfr *cfr);

/* Translate an OpenFlow match into a CFR and mask */
void pipeline_standard_match_to_cfr(const of_match_t *match, struct pipeline_standard_cfr *cfr, struct pipeline_standard_cfr *mask);

/* Log a readable version of the CFR */
void pipeline_standard_dump_cfr(const struct pipeline_standard_cfr *cfr);

#endif
