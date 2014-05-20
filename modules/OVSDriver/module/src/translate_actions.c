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
 * Translate actions from LOCI into OVS Netlink attributes.
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif
#include "ovs_driver_int.h"
#include "xbuf/xbuf.h"
#include <byteswap.h>
#include <linux/if_ether.h>
#include <murmur/murmur.h>

/*
 * Package up the data needed for action translation to reduce the
 * number of function arguments.
 */
struct translate_context {
    struct ind_ovs_parsed_key current_key; /* see ind_ovs_commit_set_field_actions */
    uint64_t modified_attrs; /* bitmap of OVS_KEY_ATTR_* */
    struct nl_msg *msg; /* netlink message to add action attributes to */
};

/*
 * Write out set-field actions
 *
 * Each flow key attribute contains several fields; for example,
 * OVS_KEY_ATTR_IPV4 contains the IP src, dst, tos, and ttl. If the OpenFlow
 * actions included a sequence like set-nw-src, set-nw-dst, set-nw-tos, it
 * would be wasteful to write out an OVS action for each of them.
 *
 * To optimize this, the set-field actions operate only on the 'current_key'
 * and 'modified_attrs' fields in the struct translate_context. 'current_key'
 * starts as a copy of the key of the original packet, and 'modified_attrs'
 * starts empty. Before writing an output action we call this function to
 * make sure all preceding set-field actions take effect on the output packet.
 */
static void
ind_ovs_commit_set_field_actions(struct translate_context *ctx)
{
    if (ctx->modified_attrs == 0) {
        return;
    }

    if (ATTR_BITMAP_TEST(ctx->modified_attrs, OVS_KEY_ATTR_VLAN)) {
        /* TODO only do this if the original packet had a vlan header */
        nla_put_flag(ctx->msg, OVS_ACTION_ATTR_POP_VLAN);
        if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
            struct ovs_action_push_vlan action;
            action.vlan_tpid = htons(ETH_P_8021Q);
            action.vlan_tci = ctx->current_key.vlan;
            nla_put(ctx->msg, OVS_ACTION_ATTR_PUSH_VLAN, sizeof(action), &action);
        }

        /*
         * HACK prevent the code below from doing an OVS_ACTION_ATTR_SET
         * of the VLAN field.
         */
        ATTR_BITMAP_CLEAR(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
    }

#define field(attr, name, type) \
    if (ATTR_BITMAP_TEST(ctx->modified_attrs, (attr))) { \
        struct nlattr *action_attr = nla_nest_start(ctx->msg, OVS_ACTION_ATTR_SET); \
        assert(action_attr); \
        nla_put(ctx->msg, (attr), sizeof(type), &ctx->current_key.name); \
        nla_nest_end(ctx->msg, action_attr); \
    }
OVS_KEY_FIELDS
#undef field

    if (ATTR_BITMAP_TEST(ctx->modified_attrs, OVS_KEY_ATTR_TUNNEL)) {
        struct nlattr *action_attr = nla_nest_start(ctx->msg, OVS_ACTION_ATTR_SET);
        struct nlattr *tunnel_attr = nla_nest_start(ctx->msg, OVS_KEY_ATTR_TUNNEL);
#define field(attr, name, type) \
        nla_put(ctx->msg, (attr), sizeof(type), &ctx->current_key.tunnel.name);
OVS_TUNNEL_KEY_FIELDS
#undef field
        nla_nest_end(ctx->msg, tunnel_attr);
        nla_nest_end(ctx->msg, action_attr);
    }

    ctx->modified_attrs = 0;
}

/* Send the packet back to an upcall thread with the given userdata */
static void
pktin(uint64_t userdata, struct translate_context *ctx)
{
    uint32_t ingress_port_no = ctx->current_key.in_port;
    if (ingress_port_no > IND_OVS_MAX_PORTS || ind_ovs_ports[ingress_port_no] == NULL) {
        return;
    }

    ind_ovs_commit_set_field_actions(ctx);
    struct nlattr *action_attr = nla_nest_start(ctx->msg, OVS_ACTION_ATTR_USERSPACE);
    struct nl_sock *sk = ind_ovs_ports[ingress_port_no]->notify_socket;
    nla_put_u32(ctx->msg, OVS_USERSPACE_ATTR_PID, nl_socket_get_local_port(sk));
    nla_put_u64(ctx->msg, OVS_USERSPACE_ATTR_USERDATA, userdata);
    nla_nest_end(ctx->msg, action_attr);
}

/*
 * Output actions
 */

static void
ind_ovs_action_output(struct nlattr *attr, struct translate_context *ctx)
{
    ind_ovs_commit_set_field_actions(ctx);
    nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, *XBUF_PAYLOAD(attr, uint32_t));
}

static void
ind_ovs_action_controller(struct nlattr *attr, struct translate_context *ctx)
{
    uint64_t userdata = *XBUF_PAYLOAD(attr, uint64_t);
    pktin(userdata, ctx);
}

static void
ind_ovs_action_flood(struct nlattr *attr, struct translate_context *ctx)
{
    uint32_t ingress_port_no = ctx->current_key.in_port;
    ind_ovs_commit_set_field_actions(ctx);
    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port != NULL && i != ingress_port_no && !port->no_flood) {
            nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, i);
        }
    }
}

static void
ind_ovs_action_all(struct nlattr *attr, struct translate_context *ctx)
{
    uint32_t ingress_port_no = ctx->current_key.in_port;
    ind_ovs_commit_set_field_actions(ctx);
    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port != NULL && i != ingress_port_no) {
            nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, i);
        }
    }
}

static void
ind_ovs_action_local(struct nlattr *attr, struct translate_context *ctx)
{
    ind_ovs_commit_set_field_actions(ctx);
    nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, 0);
}

static void
ind_ovs_action_in_port(struct nlattr *attr, struct translate_context *ctx)
{
    uint32_t ingress_port_no = ctx->current_key.in_port;
    ind_ovs_commit_set_field_actions(ctx);
    nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, ingress_port_no);
}

static void
ind_ovs_action_normal(struct nlattr *attr, struct translate_context *ctx)
{
    /* stub */
}

/*
 * Set-field actions
 *
 * Actions not applicable to the packet are ignored.
 */

static void
ind_ovs_action_set_eth_dst(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_ETHERNET);
        memcpy(ctx->current_key.ethernet.eth_dst, XBUF_PAYLOAD(attr, of_mac_addr_t), sizeof(of_mac_addr_t));
    }
}

static void
ind_ovs_action_set_eth_src(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_ETHERNET);
        memcpy(ctx->current_key.ethernet.eth_src, XBUF_PAYLOAD(attr, of_mac_addr_t), sizeof(of_mac_addr_t));
    }
}

static void
ind_ovs_action_set_ipv4_dst(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_dst = htonl(*XBUF_PAYLOAD(attr, uint32_t));
    }
}

static void
ind_ovs_action_set_ipv4_src(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_src = htonl(*XBUF_PAYLOAD(attr, uint32_t));
    }
}

static void
ind_ovs_action_set_ip_dscp(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_tos &= (uint8_t)(~IP_DSCP_MASK);
        ctx->current_key.ipv4.ipv4_tos |= *XBUF_PAYLOAD(attr, uint8_t);
    } else if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_tclass &= (uint8_t)(~IP_DSCP_MASK);
        ctx->current_key.ipv6.ipv6_tclass |= *XBUF_PAYLOAD(attr, uint8_t);
    }
}

static void
ind_ovs_action_set_ip_ecn(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_tos &= (uint8_t)(~IP_ECN_MASK);
        ctx->current_key.ipv4.ipv4_tos |= *XBUF_PAYLOAD(attr, uint8_t);
    } else if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_tclass &= (uint8_t)(~IP_ECN_MASK);
        ctx->current_key.ipv6.ipv6_tclass |= *XBUF_PAYLOAD(attr, uint8_t);
    }
}

static void
ind_ovs_action_set_nw_ttl(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_ttl = *XBUF_PAYLOAD(attr, uint8_t);
    } else if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_hlimit = *XBUF_PAYLOAD(attr, uint8_t);
    }
}

static void
ind_ovs_action_set_tcp_src(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_TCP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TCP);
        ctx->current_key.tcp.tcp_src = htons(*XBUF_PAYLOAD(attr, uint16_t));
    }
}

static void
ind_ovs_action_set_tcp_dst(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_TCP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TCP);
        ctx->current_key.tcp.tcp_dst = htons(*XBUF_PAYLOAD(attr, uint16_t));
    }
}

static void
ind_ovs_action_set_udp_src(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_UDP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_UDP);
        ctx->current_key.udp.udp_src = htons(*XBUF_PAYLOAD(attr, uint16_t));
    }
}

static void
ind_ovs_action_set_udp_dst(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_UDP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_UDP);
        ctx->current_key.udp.udp_dst = htons(*XBUF_PAYLOAD(attr, uint16_t));
    }
}

static void
ind_ovs_action_set_tp_src(struct nlattr *attr, struct translate_context *ctx)
{
    ind_ovs_action_set_tcp_src(attr, ctx);
    ind_ovs_action_set_udp_src(attr, ctx);
}

static void
ind_ovs_action_set_tp_dst(struct nlattr *attr, struct translate_context *ctx)
{
    ind_ovs_action_set_tcp_dst(attr, ctx);
    ind_ovs_action_set_udp_dst(attr, ctx);
}

/*
 * VLAN actions
 */

static void
ind_ovs_action_set_vlan_vid(struct nlattr *attr, struct translate_context *ctx)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
    uint16_t cur_tci;
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        cur_tci = ntohs(ctx->current_key.vlan);
    } else {
        cur_tci = VLAN_CFI_BIT;
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
    uint16_t vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
    ctx->current_key.vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(cur_tci)) | VLAN_CFI_BIT);
}

static void
ind_ovs_action_set_vlan_pcp(struct nlattr *attr, struct translate_context *ctx)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
    uint16_t cur_tci;
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        cur_tci = ntohs(ctx->current_key.vlan);
    } else {
        cur_tci = VLAN_CFI_BIT;
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
    uint8_t vlan_pcp = *XBUF_PAYLOAD(attr, uint8_t);
    ctx->current_key.vlan = htons(VLAN_TCI(VLAN_VID(cur_tci), vlan_pcp) | VLAN_CFI_BIT);
}

static void
ind_ovs_action_pop_vlan(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
        ATTR_BITMAP_CLEAR(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
}

static void
ind_ovs_action_push_vlan(struct nlattr *attr, struct translate_context *ctx)
{
    if (!ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
        ctx->current_key.vlan = htons(VLAN_CFI_BIT);
    }
}

/*
 * Extension actions
 */

static void
ind_ovs_action_set_tunnel_dst(struct nlattr *attr, struct translate_context *ctx)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TUNNEL);
    ctx->current_key.tunnel.ipv4_dst = htonl(*XBUF_PAYLOAD(attr, uint32_t));
}

/*
 * IPv6 Actions
 */

static void
ind_ovs_action_set_ipv6_dst(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        memcpy(ctx->current_key.ipv6.ipv6_dst, XBUF_PAYLOAD(attr, of_ipv6_t), sizeof(of_ipv6_t));
    }
}

static void
ind_ovs_action_set_ipv6_src(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        memcpy(ctx->current_key.ipv6.ipv6_src, XBUF_PAYLOAD(attr, of_ipv6_t), sizeof(of_ipv6_t));
    }
}

static void
ind_ovs_action_set_ipv6_flabel(struct nlattr *attr, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_label = htonl(*XBUF_PAYLOAD(attr, uint32_t));
    }
}

/* Group action */

static void
ind_ovs_action_group(struct nlattr *attr, struct translate_context *ctx)
{
    uint32_t group_id = *XBUF_PAYLOAD(attr, uint32_t);
    struct ind_ovs_group *group = ind_ovs_group_lookup(group_id);
    if (group == NULL) {
        return;
    }

    if (group->num_buckets == 0) {
        return;
    }

    uint32_t hash = murmur_hash(&ctx->current_key, sizeof(ctx->current_key),
                                ind_ovs_salt);

    struct ind_ovs_group_bucket *bucket = &group->buckets[hash % group->num_buckets];
    /* TODO update stats */

    ind_ovs_commit_set_field_actions(ctx);
    ind_ovs_translate_actions(&ctx->current_key, &bucket->actions, ctx->msg);

    /* TODO revert set-field changes */
}

void
ind_ovs_translate_actions(const struct ind_ovs_parsed_key *pkey,
                          struct xbuf *xbuf, struct nl_msg *msg)
{
    struct translate_context ctx;
    memcpy(&ctx.current_key, pkey, sizeof(*pkey));
    ctx.modified_attrs = 0;
    ctx.msg = msg;

    struct nlattr *attr;
    XBUF_FOREACH(xbuf_data(xbuf), xbuf_length(xbuf), attr) {
        switch (attr->nla_type) {
        case IND_OVS_ACTION_OUTPUT:
            ind_ovs_action_output(attr, &ctx);
            break;
        case IND_OVS_ACTION_CONTROLLER:
            ind_ovs_action_controller(attr, &ctx);
            break;
        case IND_OVS_ACTION_FLOOD:
            ind_ovs_action_flood(attr, &ctx);
            break;
        case IND_OVS_ACTION_ALL:
            ind_ovs_action_all(attr, &ctx);
            break;
        case IND_OVS_ACTION_LOCAL:
            ind_ovs_action_local(attr, &ctx);
            break;
        case IND_OVS_ACTION_IN_PORT:
            ind_ovs_action_in_port(attr, &ctx);
            break;
        case IND_OVS_ACTION_NORMAL:
            ind_ovs_action_normal(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_ETH_DST:
            ind_ovs_action_set_eth_dst(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_ETH_SRC:
            ind_ovs_action_set_eth_src(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_IPV4_DST:
            ind_ovs_action_set_ipv4_dst(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_IPV4_SRC:
            ind_ovs_action_set_ipv4_src(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_IP_DSCP:
            ind_ovs_action_set_ip_dscp(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_IP_ECN:
            ind_ovs_action_set_ip_ecn(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_TCP_DST:
            ind_ovs_action_set_tcp_dst(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_TCP_SRC:
            ind_ovs_action_set_tcp_src(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_UDP_DST:
            ind_ovs_action_set_udp_dst(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_UDP_SRC:
            ind_ovs_action_set_udp_src(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_TP_DST:
            ind_ovs_action_set_tp_dst(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_TP_SRC:
            ind_ovs_action_set_tp_src(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_VLAN_VID:
            ind_ovs_action_set_vlan_vid(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_VLAN_PCP:
            ind_ovs_action_set_vlan_pcp(attr, &ctx);
            break;
        case IND_OVS_ACTION_POP_VLAN:
            ind_ovs_action_pop_vlan(attr, &ctx);
            break;
        case IND_OVS_ACTION_PUSH_VLAN:
            ind_ovs_action_push_vlan(attr, &ctx);
            break;
        case IND_OVS_ACTION_DEC_NW_TTL:
            /* Special cased because it can drop the packet */
            if (ATTR_BITMAP_TEST(ctx.current_key.populated, OVS_KEY_ATTR_IPV4)) {
                ATTR_BITMAP_SET(ctx.modified_attrs, OVS_KEY_ATTR_IPV4);
                if (ctx.current_key.ipv4.ipv4_ttl == 0
                    || --ctx.current_key.ipv4.ipv4_ttl == 0) {
                    return;
                }
            }

            if (ATTR_BITMAP_TEST(ctx.current_key.populated, OVS_KEY_ATTR_IPV6)) {
                ATTR_BITMAP_SET(ctx.modified_attrs, OVS_KEY_ATTR_IPV6);
                if (ctx.current_key.ipv6.ipv6_hlimit == 0
                    || --ctx.current_key.ipv6.ipv6_hlimit == 0) {
                    return;
                }
            }
            break;
        case IND_OVS_ACTION_SET_NW_TTL:
            ind_ovs_action_set_nw_ttl(attr, &ctx);
            break;
        case OF_ACTION_BSN_SET_TUNNEL_DST:
            ind_ovs_action_set_tunnel_dst(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_IPV6_DST:
            ind_ovs_action_set_ipv6_dst(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_IPV6_SRC:
            ind_ovs_action_set_ipv6_src(attr, &ctx);
            break;
        case IND_OVS_ACTION_SET_IPV6_FLABEL:
            ind_ovs_action_set_ipv6_flabel(attr, &ctx);
            break;
        case IND_OVS_ACTION_GROUP:
            ind_ovs_action_group(attr, &ctx);
            break;
        default:
            assert(0);
            break;
        }
    }
}


/* The code below is not in a performance-critical path */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("s")
#endif

/**
 * Translate LOCI actions into an IVS-internal representation.
 *
 * The actions are written to 'xbuf'.
 */
indigo_error_t
ind_ovs_translate_openflow_actions(of_list_action_t *actions, struct xbuf *xbuf, bool table_miss)
{
    of_action_t act;
    int rv;
    OF_LIST_ACTION_ITER(actions, &act, rv) {
        switch (act.header.object_id) {
        case OF_ACTION_OUTPUT: {
            of_port_no_t port_no;
            of_action_output_port_get(&act.output, &port_no);
            switch (port_no) {
                case OF_PORT_DEST_CONTROLLER: {
                    uint8_t reason = table_miss ? OF_PACKET_IN_REASON_NO_MATCH :
                                                  OF_PACKET_IN_REASON_ACTION;
                    uint64_t userdata = IVS_PKTIN_USERDATA(reason, 0);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_CONTROLLER, &userdata, sizeof(userdata));
                    break;
                }
                case OF_PORT_DEST_FLOOD:
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_FLOOD, NULL, 0);
                    break;
                case OF_PORT_DEST_ALL:
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_ALL, NULL, 0);
                    break;
                case OF_PORT_DEST_USE_TABLE:
                    LOG_ERROR("unsupported output port OFPP_TABLE");
                    return INDIGO_ERROR_COMPAT;
                case OF_PORT_DEST_LOCAL:
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_LOCAL, NULL, 0);
                    break;
                case OF_PORT_DEST_IN_PORT:
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_IN_PORT, NULL, 0);
                    break;
                case OF_PORT_DEST_NORMAL:
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_NORMAL, NULL, 0);
                    break;
                default: {
                    if (port_no < IND_OVS_MAX_PORTS) {
                        xbuf_append_attr(xbuf, IND_OVS_ACTION_OUTPUT, &port_no, sizeof(port_no));
                    } else {
                        LOG_ERROR("invalid output port %u", port_no);
                        return INDIGO_ERROR_COMPAT;
                    }
                    break;
                }
            }
            break;
        }
        case OF_ACTION_SET_FIELD: {
            of_oxm_t oxm;
            of_action_set_field_field_bind(&act.set_field, &oxm.header);
            switch (oxm.header.object_id) {
                case OF_OXM_VLAN_VID: {
                    uint16_t vlan_vid;
                    of_oxm_vlan_vid_value_get(&oxm.vlan_vid, &vlan_vid);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_VLAN_VID, &vlan_vid, sizeof(vlan_vid));
                    break;
                }
                case OF_OXM_VLAN_PCP: {
                    uint8_t vlan_pcp;
                    of_oxm_vlan_pcp_value_get(&oxm.vlan_pcp, &vlan_pcp);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_VLAN_PCP, &vlan_pcp, sizeof(vlan_pcp));
                    break;
                }
                case OF_OXM_ETH_SRC: {
                    of_mac_addr_t mac;
                    of_oxm_eth_src_value_get(&oxm.eth_src, &mac);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_ETH_SRC, &mac, sizeof(mac));
                    break;
                }
                case OF_OXM_ETH_DST: {
                    of_mac_addr_t mac;
                    of_oxm_eth_dst_value_get(&oxm.eth_dst, &mac);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_ETH_DST, &mac, sizeof(mac));
                    break;
                }
                case OF_OXM_IPV4_SRC: {
                    uint32_t ipv4;
                    of_oxm_ipv4_src_value_get(&oxm.ipv4_src, &ipv4);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IPV4_SRC, &ipv4, sizeof(ipv4));
                    break;
                }
                case OF_OXM_IPV4_DST: {
                    uint32_t ipv4;
                    of_oxm_ipv4_dst_value_get(&oxm.ipv4_dst, &ipv4);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IPV4_DST, &ipv4, sizeof(ipv4));
                    break;
                }
                case OF_OXM_IP_DSCP: {
                    uint8_t ip_dscp;
                    of_oxm_ip_dscp_value_get(&oxm.ip_dscp, &ip_dscp);

                    if (ip_dscp > ((uint8_t)IP_DSCP_MASK >> 2)) {
                        LOG_ERROR("invalid dscp %d in action %s", ip_dscp,
                                of_object_id_str[act.header.object_id]);
                        return INDIGO_ERROR_COMPAT;
                    }

                    ip_dscp <<= 2;
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IP_DSCP, &ip_dscp, sizeof(ip_dscp));
                    break;
                }
                case OF_OXM_IP_ECN: {
                    uint8_t ip_ecn;
                    of_oxm_ip_ecn_value_get(&oxm.ip_ecn, &ip_ecn);

                    if (ip_ecn > IP_ECN_MASK) {
                        LOG_ERROR("invalid ecn %d in action %s", ip_ecn,
                                of_object_id_str[act.header.object_id]);
                        return INDIGO_ERROR_COMPAT;
                    }

                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IP_ECN, &ip_ecn, sizeof(ip_ecn));
                    break;
                }
                case OF_OXM_IPV6_SRC: {
                    of_ipv6_t ipv6;
                    of_oxm_ipv6_src_value_get(&oxm.ipv6_src, &ipv6);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IPV6_SRC, &ipv6, sizeof(ipv6));
                    break;
                }
                case OF_OXM_IPV6_DST: {
                    of_ipv6_t ipv6;
                    of_oxm_ipv6_dst_value_get(&oxm.ipv6_dst, &ipv6);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IPV6_DST, &ipv6, sizeof(ipv6));
                    break;
                }
                case OF_OXM_IPV6_FLABEL: {
                    uint32_t flabel;
                    of_oxm_ipv6_flabel_value_get(&oxm.ipv6_flabel, &flabel);

                    if (flabel > IPV6_FLABEL_MASK) {
                        LOG_ERROR("invalid flabel 0x%04x in action %s", flabel,
                                of_object_id_str[act.header.object_id]);
                        return INDIGO_ERROR_COMPAT;
                    }

                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IPV6_FLABEL, &flabel, sizeof(flabel));
                    break;
                }
                case OF_OXM_TCP_SRC: {
                    uint16_t port;
                    of_oxm_tcp_src_value_get(&oxm.tcp_src, &port);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_TCP_SRC, &port, sizeof(port));
                    break;
                }
                case OF_OXM_TCP_DST: {
                    uint16_t port;
                    of_oxm_tcp_dst_value_get(&oxm.tcp_dst, &port);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_TCP_DST, &port, sizeof(port));
                    break;
                }
                case OF_OXM_UDP_SRC: {
                    uint16_t port;
                    of_oxm_udp_src_value_get(&oxm.udp_src, &port);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_UDP_SRC, &port, sizeof(port));
                    break;
                }
                case OF_OXM_UDP_DST: {
                    uint16_t port;
                    of_oxm_udp_dst_value_get(&oxm.udp_dst, &port);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_UDP_DST, &port, sizeof(port));
                    break;
                }
                case OF_OXM_BSN_LAG_ID: {
                    uint32_t val;
                    of_oxm_bsn_lag_id_value_get(&oxm.bsn_lag_id, &val);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_LAG_ID, &val, sizeof(val));
                    break;
                }
                case OF_OXM_BSN_VRF: {
                    uint32_t val;
                    of_oxm_bsn_vrf_value_get(&oxm.bsn_vrf, &val);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_VRF, &val, sizeof(val));
                    break;
                }
                case OF_OXM_BSN_L3_INTERFACE_CLASS_ID: {
                    uint32_t val;
                    of_oxm_bsn_l3_interface_class_id_value_get(&oxm.bsn_l3_interface_class_id, &val);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_L3_INTERFACE_CLASS_ID, &val, sizeof(val));
                    break;
                }
                case OF_OXM_BSN_L3_SRC_CLASS_ID: {
                    uint32_t val;
                    of_oxm_bsn_l3_src_class_id_value_get(&oxm.bsn_l3_src_class_id, &val);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_L3_SRC_CLASS_ID, &val, sizeof(val));
                    break;
                }
                case OF_OXM_BSN_L3_DST_CLASS_ID: {
                    uint32_t val;
                    of_oxm_bsn_l3_dst_class_id_value_get(&oxm.bsn_l3_dst_class_id, &val);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_L3_DST_CLASS_ID, &val, sizeof(val));
                    break;
                }
                case OF_OXM_BSN_GLOBAL_VRF_ALLOWED: {
                    uint8_t val;
                    of_oxm_bsn_global_vrf_allowed_value_get(&oxm.bsn_global_vrf_allowed, &val);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_GLOBAL_VRF_ALLOWED, &val, sizeof(val));
                    break;
                }
                case OF_OXM_BSN_EGR_PORT_GROUP_ID: {
                    uint32_t val;
                    of_oxm_bsn_egr_port_group_id_value_get(&oxm.bsn_egr_port_group_id, &val);
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_EGR_PORT_GROUP_ID, &val, sizeof(val));
                    break;
                }
                default:
                    LOG_ERROR("unsupported set-field oxm %s", of_object_id_str[oxm.header.object_id]);
                    return INDIGO_ERROR_COMPAT;
            }
            break;
        }
        case OF_ACTION_SET_DL_DST: {
            of_mac_addr_t mac;
            of_action_set_dl_dst_dl_addr_get(&act.set_dl_dst, &mac);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_ETH_DST, &mac, sizeof(mac));
            break;
        }
        case OF_ACTION_SET_DL_SRC: {
            of_mac_addr_t mac;
            of_action_set_dl_src_dl_addr_get(&act.set_dl_src, &mac);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_ETH_SRC, &mac, sizeof(mac));
            break;
        }
        case OF_ACTION_SET_NW_DST: {
            uint32_t ipv4;
            of_action_set_nw_dst_nw_addr_get(&act.set_nw_dst, &ipv4);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IPV4_DST, &ipv4, sizeof(ipv4));
            break;
        }
        case OF_ACTION_SET_NW_SRC: {
            uint32_t ipv4;
            of_action_set_nw_src_nw_addr_get(&act.set_nw_src, &ipv4);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IPV4_SRC, &ipv4, sizeof(ipv4));
            break;
        }
        case OF_ACTION_SET_NW_TOS: {
            uint8_t tos;
            of_action_set_nw_tos_nw_tos_get(&act.set_nw_tos, &tos);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_IP_DSCP, &tos, sizeof(tos));
            break;
        }
        case OF_ACTION_SET_TP_DST: {
            uint16_t port;
            of_action_set_tp_dst_tp_port_get(&act.set_tp_dst, &port);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_TP_DST, &port, sizeof(port));
            break;
        }
        case OF_ACTION_SET_TP_SRC: {
            uint16_t port;
            of_action_set_tp_src_tp_port_get(&act.set_tp_src, &port);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_TP_SRC, &port, sizeof(port));
            break;
        }
        case OF_ACTION_SET_VLAN_VID: {
            uint16_t vlan_vid;
            of_action_set_vlan_vid_vlan_vid_get(&act.set_vlan_vid, &vlan_vid);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_VLAN_VID, &vlan_vid, sizeof(vlan_vid));
            break;
        }
        case OF_ACTION_SET_VLAN_PCP: {
            uint8_t vlan_pcp;
            of_action_set_vlan_pcp_vlan_pcp_get(&act.set_vlan_pcp, &vlan_pcp);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_VLAN_PCP, &vlan_pcp, sizeof(vlan_pcp));
            break;
        }
        case OF_ACTION_POP_VLAN:
        case OF_ACTION_STRIP_VLAN: {
            xbuf_append_attr(xbuf, IND_OVS_ACTION_POP_VLAN, NULL, 0);
            break;
        }
        case OF_ACTION_PUSH_VLAN: {
            uint16_t eth_type;
            of_action_push_vlan_ethertype_get(&act.push_vlan, &eth_type);

            if (eth_type != ETH_P_8021Q) {
                LOG_ERROR("unsupported eth_type 0x%04x in action %s", eth_type,
                           of_object_id_str[act.header.object_id]);
                return INDIGO_ERROR_COMPAT;
            }

            xbuf_append_attr(xbuf, IND_OVS_ACTION_PUSH_VLAN, &eth_type, sizeof(eth_type));
            break;
        }
        case OF_ACTION_DEC_NW_TTL:
        case OF_ACTION_NICIRA_DEC_TTL: {
            xbuf_append_attr(xbuf, IND_OVS_ACTION_DEC_NW_TTL, NULL, 0);
            break;
        }
        case OF_ACTION_SET_NW_TTL: {
            uint8_t ttl;
            of_action_set_nw_ttl_nw_ttl_get(&act.set_nw_ttl, &ttl);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_NW_TTL, &ttl, sizeof(ttl));
            break;
        }
        case OF_ACTION_BSN_SET_TUNNEL_DST: {
            uint32_t ipv4;
            of_action_bsn_set_tunnel_dst_dst_get(&act.bsn_set_tunnel_dst, &ipv4);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_SET_TUNNEL_DST, &ipv4, sizeof(ipv4));
            break;
        }
        case OF_ACTION_GROUP: {
            uint32_t group_id;
            of_action_group_group_id_get(&act.group, &group_id);
            xbuf_append_attr(xbuf, IND_OVS_ACTION_GROUP, &group_id, sizeof(group_id));
            break;
        }
        default:
            LOG_ERROR("unsupported action %s", of_object_id_str[act.header.object_id]);
            return INDIGO_ERROR_COMPAT;
        }
    }

    return INDIGO_ERROR_NONE;
}
