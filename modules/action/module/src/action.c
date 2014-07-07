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

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif
#include <action/action.h>
#include <byteswap.h>
#include <linux/if_ether.h>
#include <netlink/genl/genl.h>

static void commit_set_field_actions(struct action_context *ctx);

void
action_context_init(struct action_context *ctx,
                    const struct ind_ovs_parsed_key *key,
                    struct nl_msg *msg)
{
    assert(ctx != NULL);
    memcpy(&ctx->current_key, key, sizeof(*key));
    ctx->modified_attrs = 0;
    ctx->msg = msg;
}

/*
 * Output actions
 */

/* Send the packet back to an upcall thread with the given userdata */
void
action_controller(struct action_context *ctx, uint64_t userdata)
{
    uint32_t netlink_port = ind_ovs_port_lookup_netlink(ctx->current_key.in_port);

    commit_set_field_actions(ctx);

    struct nlattr *action_attr = nla_nest_start(ctx->msg, OVS_ACTION_ATTR_USERSPACE);
    nla_put_u32(ctx->msg, OVS_USERSPACE_ATTR_PID, netlink_port);
    nla_put_u64(ctx->msg, OVS_USERSPACE_ATTR_USERDATA, userdata);
    nla_nest_end(ctx->msg, action_attr);
}

void
action_output(struct action_context *ctx, uint32_t port_no)
{
    commit_set_field_actions(ctx);
    nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, port_no);
}

void
action_output_local(struct action_context *ctx)
{
    commit_set_field_actions(ctx);
    nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, 0);
}

void
action_output_in_port(struct action_context *ctx)
{
    commit_set_field_actions(ctx);
    nla_put_u32(ctx->msg, OVS_ACTION_ATTR_OUTPUT, ctx->current_key.in_port);
}

/*
 * Ethernet actions
 */

void
action_set_eth_dst(struct action_context *ctx, of_mac_addr_t mac)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_ETHERNET);
        memcpy(ctx->current_key.ethernet.eth_dst, &mac, sizeof(of_mac_addr_t));
    }
}

void
action_set_eth_src(struct action_context *ctx, of_mac_addr_t mac)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_ETHERNET);
        memcpy(ctx->current_key.ethernet.eth_src, &mac, sizeof(of_mac_addr_t));
    }
}

/*
 * VLAN actions
 */

void
action_set_vlan_vid(struct action_context *ctx, uint16_t vlan_vid)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
    uint16_t cur_tci;
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        cur_tci = ntohs(ctx->current_key.vlan);
    } else {
        cur_tci = VLAN_CFI_BIT;
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
    ctx->current_key.vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(cur_tci)) | VLAN_CFI_BIT);
}

void
action_set_vlan_pcp(struct action_context *ctx, uint8_t vlan_pcp)
{
    ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
    uint16_t cur_tci;
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        cur_tci = ntohs(ctx->current_key.vlan);
    } else {
        cur_tci = VLAN_CFI_BIT;
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
    ctx->current_key.vlan = htons(VLAN_TCI(VLAN_VID(cur_tci), vlan_pcp) | VLAN_CFI_BIT);
}

void
action_pop_vlan(struct action_context *ctx)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
        ATTR_BITMAP_CLEAR(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
    }
}

void
action_push_vlan(struct action_context *ctx)
{
    if (!ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_VLAN)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_VLAN);
        ATTR_BITMAP_SET(ctx->current_key.populated, OVS_KEY_ATTR_VLAN);
        ctx->current_key.vlan = htons(VLAN_CFI_BIT);
    }
}

/*
 * IPv4 actions
 */

void
action_set_ipv4_dst(struct action_context *ctx, uint32_t ipv4)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_dst = htonl(ipv4);
    }
}

void
action_set_ipv4_src(struct action_context *ctx, uint32_t ipv4)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_src = htonl(ipv4);
    }
}

void
action_set_ipv4_dscp(struct action_context *ctx, uint8_t ip_dscp)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_tos &= (uint8_t)(~IP_DSCP_MASK);
        ctx->current_key.ipv4.ipv4_tos |= ip_dscp;
    }
}

void
action_set_ipv4_ecn(struct action_context *ctx, uint8_t ip_ecn)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_tos &= (uint8_t)(~IP_ECN_MASK);
        ctx->current_key.ipv4.ipv4_tos |= ip_ecn;
    }
}

void
action_set_ipv4_ttl(struct action_context *ctx, uint8_t ttl)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
        ctx->current_key.ipv4.ipv4_ttl = ttl;
    }
}

/*
 * IPv6 actions
 */

void
action_set_ipv6_dst(struct action_context *ctx, of_ipv6_t ipv6)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        memcpy(ctx->current_key.ipv6.ipv6_dst, &ipv6, sizeof(of_ipv6_t));
    }
}

void
action_set_ipv6_src(struct action_context *ctx, of_ipv6_t ipv6)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        memcpy(ctx->current_key.ipv6.ipv6_src, &ipv6, sizeof(of_ipv6_t));
    }
}

void
action_set_ipv6_dscp(struct action_context *ctx, uint8_t ip_dscp)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_tclass &= (uint8_t)(~IP_DSCP_MASK);
        ctx->current_key.ipv6.ipv6_tclass |= ip_dscp;
    }
}

void
action_set_ipv6_ecn(struct action_context *ctx, uint8_t ip_ecn)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_tclass &= (uint8_t)(~IP_ECN_MASK);
        ctx->current_key.ipv6.ipv6_tclass |= ip_ecn;
    }
}

void
action_set_ipv6_ttl(struct action_context *ctx, uint8_t ttl)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_hlimit = ttl;
    }
}

void
action_set_ipv6_flabel(struct action_context *ctx, uint32_t flabel)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
        ctx->current_key.ipv6.ipv6_label = htonl(flabel);
    }
}

/*
 * TCP actions
 */

void
action_set_tcp_src(struct action_context *ctx, uint16_t tcp_src)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_TCP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TCP);
        ctx->current_key.tcp.tcp_src = htons(tcp_src);
    }
}

void
action_set_tcp_dst(struct action_context *ctx, uint16_t tcp_dst)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_TCP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_TCP);
        ctx->current_key.tcp.tcp_dst = htons(tcp_dst);
    }
}

/*
 * UDP actions
 */

void
action_set_udp_src(struct action_context *ctx, uint16_t udp_src)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_UDP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_UDP);
        ctx->current_key.udp.udp_src = htons(udp_src);
    }
}

void
action_set_udp_dst(struct action_context *ctx, uint16_t udp_dst)
{
    if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_UDP)) {
        ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_UDP);
        ctx->current_key.udp.udp_dst = htons(udp_dst);
    }
}


/*
 * Write out set-field actions
 *
 * Each flow key attribute contains several fields; for example,
 * OVS_KEY_ATTR_IPV4 contains the IP src, dst, tos, and ttl. If the OpenFlow
 * actions included a sequence like set-nw-src, set-nw-dst, set-nw-tos, it
 * would be wasteful to write out an OVS action for each of them.
 *
 * To optimize this, the set-field actions operate only on the 'current_key'
 * and 'modified_attrs' fields in the struct action_context. 'current_key'
 * starts as a copy of the key of the original packet, and 'modified_attrs'
 * starts empty. Before writing an output action we call this function to
 * make sure all preceding set-field actions take effect on the output packet.
 */
static void
commit_set_field_actions(struct action_context *ctx)
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

    ctx->modified_attrs = 0;
}
