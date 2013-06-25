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
#pragma GCC optimize (4)
#include "ovs_driver_int.h"
#include <byteswap.h>
#include <linux/if_ether.h>

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

static void
ind_ovs_action_output(of_action_output_t *act, struct translate_context *ctx)
{
    uint32_t ingress_port_no = ctx->current_key.in_port;
    of_port_no_t of_port_num;
    of_action_output_port_get(act, &of_port_num);
    switch (of_port_num) {
    case OF_PORT_DEST_CONTROLLER: {
        struct nlattr *action_attr = nla_nest_start(ctx->msg, OVS_ACTION_ATTR_USERSPACE);
        struct nl_sock *sk = ind_ovs_ports[ingress_port_no]->notify_socket;
        nla_put_u32(ctx->msg, OVS_USERSPACE_ATTR_PID, nl_socket_get_local_port(sk));
        nla_nest_end(ctx->msg, action_attr);
        break;
    }
    case OF_PORT_DEST_FLOOD:
        /* Fallthrough */
    case OF_PORT_DEST_ALL: {
        /* Add all port numbers as outputs */
        int flood = of_port_num == OF_PORT_DEST_FLOOD;
        int i;
        for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
            struct ind_ovs_port *port = ind_ovs_ports[i];
            if (port != NULL && i != ingress_port_no &&
                (!flood || !(port->config & OF_PORT_CONFIG_FLAG_NO_FLOOD))) {
                nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, i);
            }
        }
        break;
    }
    case OF_PORT_DEST_USE_TABLE: {
        /* HACK send the packet through the datapath to have all its
         * actions executed, then back to userspace to be treated
         * as a table miss (but with no flow install). */
        struct nlattr *action_attr = nla_nest_start(ctx->msg, OVS_ACTION_ATTR_USERSPACE);
        struct nl_sock *sk = ind_ovs_ports[ingress_port_no]->notify_socket;
        nla_put_u32(ctx->msg, OVS_USERSPACE_ATTR_PID, nl_socket_get_local_port(sk));
        nla_put_u64(ctx->msg, OVS_USERSPACE_ATTR_USERDATA, -1);
        nla_nest_end(ctx->msg, action_attr);
        break;
    }
    case OF_PORT_DEST_LOCAL:
        nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, 0);
        break;
    case OF_PORT_DEST_IN_PORT:
        nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, ingress_port_no);
        break;
    default:
        nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, of_port_num);
        break;
    }
}

/*
 * Set-field actions
 *
 * Actions not applicable to the packet are ignored.
 */

static void
ind_ovs_action_set_dl_dst(of_action_set_dl_dst_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_ETHERNET);
        of_action_set_dl_dst_dl_addr_get(act,
            (of_mac_addr_t *)ctx->current_key.ethernet.eth_dst);
    }
}

static void
ind_ovs_action_set_dl_src(of_action_set_dl_src_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_ETHERNET);
        of_action_set_dl_src_dl_addr_get(act,
            (of_mac_addr_t *)ctx->current_key.ethernet.eth_src);
    }
}

static void
ind_ovs_action_set_nw_dst(of_action_set_nw_dst_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        uint32_t tmp;
        of_action_set_nw_dst_nw_addr_get(act, &tmp);
        ctx->current_key.ipv4.ipv4_dst = htonl(tmp);
    }
}

static void
ind_ovs_action_set_nw_src(of_action_set_nw_src_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        uint32_t tmp;
        of_action_set_nw_src_nw_addr_get(act, &tmp);
        ctx->current_key.ipv4.ipv4_src = htonl(tmp);
    }
}

static void
ind_ovs_action_set_nw_tos(of_action_set_nw_tos_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        of_action_set_nw_tos_nw_tos_get(act,
            &ctx->current_key.ipv4.ipv4_tos);
    }
}

static void
ind_ovs_action_set_tp_dst(of_action_set_tp_dst_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_TCP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TCP);
        uint16_t tmp;
        of_action_set_tp_dst_tp_port_get(act, &tmp);
        ctx->current_key.tcp.tcp_dst = htons(tmp);
    } else if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_UDP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_UDP);
        uint16_t tmp;
        of_action_set_tp_dst_tp_port_get(act, &tmp);
        ctx->current_key.udp.udp_dst = htons(tmp);
    }
}

static void
ind_ovs_action_set_tp_src(of_action_set_tp_src_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_TCP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TCP);
        uint16_t tmp;
        of_action_set_tp_src_tp_port_get(act, &tmp);
        ctx->current_key.tcp.tcp_src = htons(tmp);
    } else if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_UDP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_UDP);
        uint16_t tmp;
        of_action_set_tp_src_tp_port_get(act, &tmp);
        ctx->current_key.udp.udp_src = htons(tmp);
    }
}

static void
ind_ovs_action_set_vlan_vid(of_action_set_vlan_vid_t *act, struct translate_context *ctx)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
    uint16_t cur_tci;
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        cur_tci = ntohs(ctx->current_key.vlan);
    } else {
        cur_tci = VLAN_CFI_BIT;
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
    uint16_t vlan_vid;
    of_action_set_vlan_vid_vlan_vid_get(act, &vlan_vid);
    ctx->current_key.vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(cur_tci)) | VLAN_CFI_BIT);
}

static void
ind_ovs_action_set_vlan_pcp(of_action_set_vlan_pcp_t *act, struct translate_context *ctx)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
    uint16_t cur_tci;
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        cur_tci = ntohs(ctx->current_key.vlan);
    } else {
        cur_tci = VLAN_CFI_BIT;
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
    uint8_t vlan_pcp;
    of_action_set_vlan_pcp_vlan_pcp_get(act, &vlan_pcp);
    ctx->current_key.vlan = htons(VLAN_TCI(VLAN_VID(cur_tci), vlan_pcp) | VLAN_CFI_BIT);
}

static void
ind_ovs_action_strip_vlan(of_action_strip_vlan_t *act, struct translate_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
        ATTR_BITMAP_CLEAR(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
}

static void
ind_ovs_action_bsn_set_tunnel_dst(of_action_bsn_set_tunnel_dst_t *act, struct translate_context *ctx)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TUNNEL);
    uint32_t ipv4_dst;
    of_action_bsn_set_tunnel_dst_dst_get(act, &ipv4_dst);
    ctx->current_key.tunnel.ipv4_dst = htonl(ipv4_dst);
}

void
ind_ovs_translate_actions(const struct ind_ovs_parsed_key *pkey,
                          of_list_action_t *actions,
                          struct nl_msg *msg, int attr_type)
{
    struct translate_context ctx;
    memcpy(&ctx.current_key, pkey, sizeof(*pkey));
    ctx.modified_attrs = 0;
    ctx.msg = msg;

    struct nlattr *actions_attr = nla_nest_start(msg, attr_type);

    of_action_t act;
    int rv;
    OF_LIST_ACTION_ITER(actions, &act, rv) {
        switch (act.header.object_id) {
        case OF_ACTION_OUTPUT:
            ind_ovs_commit_set_field_actions(&ctx);
            ind_ovs_action_output(&act.output, &ctx);
            break;
        case OF_ACTION_SET_DL_DST:
            ind_ovs_action_set_dl_dst(&act.set_dl_dst, &ctx);
            break;
        case OF_ACTION_SET_DL_SRC:
            ind_ovs_action_set_dl_src(&act.set_dl_src, &ctx);
            break;
        case OF_ACTION_SET_NW_DST:
            ind_ovs_action_set_nw_dst(&act.set_nw_dst, &ctx);
            break;
        case OF_ACTION_SET_NW_SRC:
            ind_ovs_action_set_nw_src(&act.set_nw_src, &ctx);
            break;
        case OF_ACTION_SET_NW_TOS:
            ind_ovs_action_set_nw_tos(&act.set_nw_tos, &ctx);
            break;
        case OF_ACTION_SET_TP_DST:
            ind_ovs_action_set_tp_dst(&act.set_tp_dst, &ctx);
            break;
        case OF_ACTION_SET_TP_SRC:
            ind_ovs_action_set_tp_src(&act.set_tp_src, &ctx);
            break;
        case OF_ACTION_SET_VLAN_VID:
            ind_ovs_action_set_vlan_vid(&act.set_vlan_vid, &ctx);
            break;
        case OF_ACTION_SET_VLAN_PCP:
            ind_ovs_action_set_vlan_pcp(&act.set_vlan_pcp, &ctx);
            break;
        case OF_ACTION_STRIP_VLAN:
            ind_ovs_action_strip_vlan(&act.strip_vlan, &ctx);
            break;
        case OF_ACTION_NICIRA_DEC_TTL:
            /* Special cased because it can drop the packet */
            if (ATTR_BITMAP_TEST(ctx.current_key.populated, OVS_KEY_ATTR_IPV4)) {
                ATTR_BITMAP_SET(ctx.modified_attrs, OVS_KEY_ATTR_IPV4);
                if (--ctx.current_key.ipv4.ipv4_ttl == 0) {
                    goto finish;
                }
            }
            break;
        case OF_ACTION_BSN_SET_TUNNEL_DST:
            ind_ovs_action_bsn_set_tunnel_dst(&act.bsn_set_tunnel_dst, &ctx);
            break;
        default:
            LOG_ERROR("unsupported action");
            break;
        }
    }

finish:
    nla_nest_end(msg, actions_attr);

    if (nlmsg_tail(nlmsg_hdr(msg)) == actions_attr) {
        /* HACK OVS expects an empty nested attribute */
        /* Not technically legal netlink before 2.6.29 */
        nla_put(msg, attr_type, 0, NULL);
    }
}
