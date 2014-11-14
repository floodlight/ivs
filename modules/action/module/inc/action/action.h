/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
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
 * This module constructs action lists to be passed to the openvswitch
 * kernel datapath. After initializing the action_context, the client
 * calls the action_* functions to append actions to the Netlink message.
 * This module takes care of coalescing multiple writes to the same
 * header.
 */
#ifndef ACTION_H
#define ACTION_H

#include <ivs/ivs.h>

/*
 * Package up the data needed for action translation to reduce the
 * number of function arguments.
 */
struct action_context {
    struct ind_ovs_parsed_key current_key; /* see ind_ovs_commit_set_field_actions */
    uint64_t modified_attrs; /* bitmap of OVS_KEY_ATTR_* */
    struct nl_msg *msg; /* netlink message to add action attributes to */
};

/*
 * Initialize an action translation context.
 *
 * 'msg' will have OVS_ACTION_ATTR_* attributes appended to it as a side
 * effect of calling the action functions below.
 */
void action_context_init(struct action_context *ctx,
                         const struct ind_ovs_parsed_key *key,
                         struct nl_msg *msg);

/* Output */

void action_controller(struct action_context *ctx, uint64_t userdata);
void action_output(struct action_context *ctx, uint32_t port_no);
void action_output_local(struct action_context *ctx);
void action_output_in_port(struct action_context *ctx);

/* Ethernet */

void action_set_eth_dst(struct action_context *ctx, of_mac_addr_t mac);
void action_set_eth_src(struct action_context *ctx, of_mac_addr_t mac);

/* Used by the Lua pipeline */
void action_set_eth_dst_scalar(struct action_context *ctx, uint32_t mac_lo, uint16_t mac_hi);
void action_set_eth_src_scalar(struct action_context *ctx, uint32_t mac_lo, uint16_t mac_hi);

/* VLAN */

void action_set_vlan_vid(struct action_context *ctx, uint16_t vlan_vid);
void action_set_vlan_pcp(struct action_context *ctx, uint8_t vlan_pcp);
void action_pop_vlan(struct action_context *ctx);
void action_push_vlan(struct action_context *ctx);

/* IPv4 */

void action_set_ipv4_dst(struct action_context *ctx, uint32_t ipv4);
void action_set_ipv4_src(struct action_context *ctx, uint32_t ipv4);
void action_set_ipv4_dscp(struct action_context *ctx, uint8_t ip_dscp);
void action_set_ipv4_ecn(struct action_context *ctx, uint8_t ip_ecn);
void action_set_ipv4_ttl(struct action_context *ctx, uint8_t ttl);

/* IPv6 */

void action_set_ipv6_dst(struct action_context *ctx, of_ipv6_t ipv6);
void action_set_ipv6_src(struct action_context *ctx, of_ipv6_t ipv6);
void action_set_ipv6_dscp(struct action_context *ctx, uint8_t ip_dscp);
void action_set_ipv6_ecn(struct action_context *ctx, uint8_t ip_ecn);
void action_set_ipv6_ttl(struct action_context *ctx, uint8_t ttl);
void action_set_ipv6_flabel(struct action_context *ctx, uint32_t flabel);

/* TCP */

void action_set_tcp_src(struct action_context *ctx, uint16_t tcp_src);
void action_set_tcp_dst(struct action_context *ctx, uint16_t tcp_dst);

/* UDP */

void action_set_udp_src(struct action_context *ctx, uint16_t udp_src);
void action_set_udp_dst(struct action_context *ctx, uint16_t udp_dst);

/* Misc */

void action_set_priority(struct action_context *ctx, uint32_t priority);

#endif
