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
 *
 * TODO:
 * - Add error handling.
 * - Support OF 1.x actions.
 */
#pragma GCC optimize (4)
#include "ovs_driver_int.h"
#include <byteswap.h>
#include <linux/if_ether.h>

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

static void
ind_ovs_parse_key__(struct nlattr *key, struct ind_ovs_parsed_key *pkey)
{
    struct nlattr *attrs[OVS_KEY_ATTR_MAX+1];
    if (nla_parse_nested(attrs, OVS_KEY_ATTR_MAX, key, NULL) < 0) {
        abort();
    }

#define field(attr, name, type) \
    if (attrs[attr]) { \
        assert(sizeof(type) == sizeof(pkey->name)); \
        memcpy(&pkey->name, nla_data(attrs[attr]), sizeof(type)); \
        ATTR_BITMAP_SET(pkey->populated, (attr)); \
    }
    OVS_KEY_FIELDS
#undef field

    if (attrs[OVS_KEY_ATTR_ENCAP]) {
        ind_ovs_parse_key__(attrs[OVS_KEY_ATTR_ENCAP], pkey);
    }

    if (attrs[OVS_KEY_ATTR_TUNNEL]) {
        struct nlattr *tunnel_attrs[OVS_TUNNEL_KEY_ATTR_MAX+1];
        if (nla_parse_nested(tunnel_attrs, OVS_TUNNEL_KEY_ATTR_MAX,
                             attrs[OVS_KEY_ATTR_TUNNEL], NULL) < 0) {
            abort();
        }

#define field(attr, name, type) \
        if (tunnel_attrs[attr]) { \
            assert(sizeof(type) == sizeof(pkey->tunnel.name)); \
            memcpy(&pkey->tunnel.name, nla_data(tunnel_attrs[attr]), sizeof(type)); \
        }
        OVS_TUNNEL_KEY_FIELDS
#undef field
    }
}

void
ind_ovs_parse_key(struct nlattr *key, struct ind_ovs_parsed_key *pkey)
{
    pkey->populated = 0;
    pkey->in_port = -1;
    pkey->tunnel.id = 0;
    pkey->tunnel.ipv4_src = 0;
    pkey->tunnel.ipv4_dst = 0;
    pkey->tunnel.tos = 0;
    pkey->tunnel.ttl = 64;
    ind_ovs_parse_key__(key, pkey);
    assert(ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ETHERNET));
}

static void
ind_ovs_commit_modify_actions(struct ind_ovs_parsed_key *current_key,
                              uint64_t modified_attrs,
                              struct nl_msg *msg)
{
    if (ATTR_BITMAP_TEST(modified_attrs, OVS_KEY_ATTR_VLAN)) {
        /* TODO only do this if the original packet had a vlan header */
        nla_put_flag(msg, OVS_ACTION_ATTR_POP_VLAN);
        if (ATTR_BITMAP_TEST(current_key->populated, OVS_KEY_ATTR_VLAN)) {
            struct ovs_action_push_vlan action;
            action.vlan_tpid = htons(ETH_P_8021Q);
            action.vlan_tci = current_key->vlan;
            nla_put(msg, OVS_ACTION_ATTR_PUSH_VLAN, sizeof(action), &action);
        }

        /*
         * HACK prevent the code below from doing an OVS_ACTION_ATTR_SET
         * of the VLAN field.
         */
        ATTR_BITMAP_CLEAR(modified_attrs, OVS_KEY_ATTR_VLAN);
    }

#define field(attr, name, type) \
    if (ATTR_BITMAP_TEST(modified_attrs, (attr))) { \
        struct nlattr *action_attr = nla_nest_start(msg, OVS_ACTION_ATTR_SET); \
        assert(action_attr); \
        nla_put(msg, (attr), sizeof(type), &current_key->name); \
        nla_nest_end(msg, action_attr); \
    }
OVS_KEY_FIELDS
#undef field

    if (ATTR_BITMAP_TEST(modified_attrs, OVS_KEY_ATTR_TUNNEL)) {
        struct nlattr *action_attr = nla_nest_start(msg, OVS_ACTION_ATTR_SET);
        struct nlattr *tunnel_attr = nla_nest_start(msg, OVS_KEY_ATTR_TUNNEL);
#define field(attr, name, type) \
        nla_put(msg, (attr), sizeof(type), &current_key->tunnel.name);
OVS_TUNNEL_KEY_FIELDS
#undef field
        nla_nest_end(msg, tunnel_attr);
        nla_nest_end(msg, action_attr);
    }
}

void
ind_ovs_translate_actions(const struct ind_ovs_parsed_key *pkey,
                          of_list_action_t *of_list_action,
                          struct nl_msg *msg, int attr_type)
{
    uint64_t modified_attrs = 0; /* bitmap of OVS_KEY_ATTR_* */
    struct ind_ovs_parsed_key current_key;
    memcpy(&current_key, pkey, sizeof(current_key));

    struct nlattr *actions_attr = nla_nest_start(msg, attr_type);

    of_action_t of_action[1];
    int rv;
    OF_LIST_ACTION_ITER(of_list_action, of_action, rv) {
        switch (of_action->header.object_id) {
        case OF_ACTION_OUTPUT: {
            ind_ovs_commit_modify_actions(&current_key, modified_attrs, msg);
            modified_attrs = 0;
            uint32_t ingress_port_no = current_key.in_port;
            of_port_no_t of_port_num;
            of_action_output_port_get(&of_action->output, &of_port_num);
            switch (of_port_num) {
            case OF_PORT_DEST_CONTROLLER: {
                struct nlattr *action_attr = nla_nest_start(msg, OVS_ACTION_ATTR_USERSPACE);
                struct nl_sock *sk = ind_ovs_ports[ingress_port_no]->notify_socket;
                nla_put_u32(msg, OVS_USERSPACE_ATTR_PID, nl_socket_get_local_port(sk));
                nla_nest_end(msg, action_attr);
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
                        nla_put_u32(msg, OVS_ACTION_ATTR_OUTPUT, i);
                    }
                }
                break;
            }
            case OF_PORT_DEST_USE_TABLE: {
                /* HACK send the packet through the datapath to have all its
                 * actions executed, then back to userspace to be treated
                 * as a table miss (but with no flow install). */
                struct nlattr *action_attr = nla_nest_start(msg, OVS_ACTION_ATTR_USERSPACE);
                struct nl_sock *sk = ind_ovs_ports[ingress_port_no]->notify_socket;
                nla_put_u32(msg, OVS_USERSPACE_ATTR_PID, nl_socket_get_local_port(sk));
                nla_put_u64(msg, OVS_USERSPACE_ATTR_USERDATA, -1);
                nla_nest_end(msg, action_attr);
                break;
            }
            case OF_PORT_DEST_LOCAL:
                nla_put_u32(msg, OVS_ACTION_ATTR_OUTPUT, 0);
                break;
            case OF_PORT_DEST_IN_PORT:
                nla_put_u32(msg, OVS_ACTION_ATTR_OUTPUT, current_key.in_port);
                break;
            default:
                nla_put_u32(msg, OVS_ACTION_ATTR_OUTPUT, of_port_num);
                break;
            }
            break;
        }
        case OF_ACTION_SET_DL_DST: {
            if (!ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
                break;
            }
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_ETHERNET);
            of_action_set_dl_dst_dl_addr_get(&of_action->set_dl_dst,
                (of_mac_addr_t *)current_key.ethernet.eth_dst);
            break;
        }
        case OF_ACTION_SET_DL_SRC: {
            if (!ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_ETHERNET)) {
                break;
            }
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_ETHERNET);
            of_action_set_dl_src_dl_addr_get(&of_action->set_dl_src,
                (of_mac_addr_t *)current_key.ethernet.eth_src);
            break;
        }
        case OF_ACTION_SET_NW_DST: {
            if (!ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_IPV4)) {
                break;
            }
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_IPV4);
            uint32_t tmp;
            of_action_set_nw_dst_nw_addr_get(&of_action->set_nw_dst, &tmp);
            current_key.ipv4.ipv4_dst = htonl(tmp);
            break;
        }
        case OF_ACTION_SET_NW_SRC: {
            if (!ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_IPV4)) {
                break;
            }
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_IPV4);
            uint32_t tmp;
            of_action_set_nw_src_nw_addr_get(&of_action->set_nw_src, &tmp);
            current_key.ipv4.ipv4_src = htonl(tmp);
            break;
        }
        case OF_ACTION_SET_NW_TOS: {
            if (!ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_IPV4)) {
                break;
            }
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_IPV4);
            of_action_set_nw_tos_nw_tos_get(&of_action->set_nw_tos,
                &current_key.ipv4.ipv4_tos);
            break;
        }
        case OF_ACTION_SET_TP_DST: {
            if (ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_TCP)) {
                ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_TCP);
                uint16_t tmp;
                of_action_set_tp_dst_tp_port_get(&of_action->set_tp_dst, &tmp);
                current_key.tcp.tcp_dst = htons(tmp);
            } else if (ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_UDP)) {
                ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_UDP);
                uint16_t tmp;
                of_action_set_tp_dst_tp_port_get(&of_action->set_tp_dst, &tmp);
                current_key.udp.udp_dst = htons(tmp);
            }
            break;
        }
        case OF_ACTION_SET_TP_SRC: {
            if (ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_TCP)) {
                ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_TCP);
                uint16_t tmp;
                of_action_set_tp_src_tp_port_get(&of_action->set_tp_src, &tmp);
                current_key.tcp.tcp_src = htons(tmp);
            } else if (ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_UDP)) {
                ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_UDP);
                uint16_t tmp;
                of_action_set_tp_src_tp_port_get(&of_action->set_tp_src, &tmp);
                current_key.udp.udp_src = htons(tmp);
            }
            break;
        }
        case OF_ACTION_SET_VLAN_VID: {
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_VLAN);
            uint16_t cur_tci;
            if (ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_VLAN)) {
                cur_tci = ntohs(current_key.vlan);
            } else {
                cur_tci = VLAN_CFI_BIT;
                ATTR_BITMAP_SET(current_key.populated, OVS_KEY_ATTR_VLAN);
            }
            uint16_t vlan_vid;
            of_action_set_vlan_vid_vlan_vid_get(&of_action->set_vlan_vid, &vlan_vid);
            current_key.vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(cur_tci)) | VLAN_CFI_BIT);
            break;
        }
        case OF_ACTION_SET_VLAN_PCP: {
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_VLAN);
            uint16_t cur_tci;
            if (ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_VLAN)) {
                cur_tci = ntohs(current_key.vlan);
            } else {
                cur_tci = VLAN_CFI_BIT;
                ATTR_BITMAP_SET(current_key.populated, OVS_KEY_ATTR_VLAN);
            }
            uint8_t vlan_pcp;
            of_action_set_vlan_pcp_vlan_pcp_get(&of_action->set_vlan_pcp, &vlan_pcp);
            current_key.vlan = htons(VLAN_TCI(VLAN_VID(cur_tci), vlan_pcp) | VLAN_CFI_BIT);
            break;
        }
        case OF_ACTION_STRIP_VLAN: {
            if (ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_VLAN)) {
                ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_VLAN);
                ATTR_BITMAP_CLEAR(current_key.populated, OVS_KEY_ATTR_VLAN);
            }
            break;
        }
        case OF_ACTION_NICIRA_DEC_TTL: {
            if (!ATTR_BITMAP_TEST(current_key.populated, OVS_KEY_ATTR_IPV4)) {
                break;
            }
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_IPV4);
            if (--current_key.ipv4.ipv4_ttl == 0) {
                goto finish;
            }
            break;
        }
        case OF_ACTION_BSN_SET_TUNNEL_DST: {
            ATTR_BITMAP_SET(modified_attrs, OVS_KEY_ATTR_TUNNEL);
            uint32_t ipv4_dst;
            of_action_bsn_set_tunnel_dst_dst_get(&of_action->bsn_set_tunnel_dst, &ipv4_dst);
            current_key.tunnel.ipv4_dst = htonl(ipv4_dst);
            break;
        }
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

void
ind_ovs_key_to_match(const struct ind_ovs_parsed_key *pkey,
                     of_match_t *match)
{
    memset(match, 0, sizeof(*match));

    /* We only populate the masks for this OF version */
    match->version = OF_VERSION_1_0;

    of_match_fields_t *fields = &match->fields;

    assert(ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_IN_PORT));
    fields->in_port = pkey->in_port;
    OF_MATCH_MASK_IN_PORT_EXACT_SET(match);

    assert(ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ETHERNET));
    memcpy(&fields->eth_dst, pkey->ethernet.eth_dst, OF_MAC_ADDR_BYTES);
    memcpy(&fields->eth_src, pkey->ethernet.eth_src, OF_MAC_ADDR_BYTES);
    OF_MATCH_MASK_ETH_DST_EXACT_SET(match);
    OF_MATCH_MASK_ETH_SRC_EXACT_SET(match);

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ETHERTYPE)) {
        fields->eth_type = ntohs(pkey->ethertype);
        if (fields->eth_type <= OF_DL_TYPE_NOT_ETH_TYPE) {
            fields->eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
        }
    } else {
        fields->eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
    }
    OF_MATCH_MASK_ETH_TYPE_EXACT_SET(match);

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_VLAN)) {
        fields->vlan_vid = VLAN_VID(ntohs(pkey->vlan));
        fields->vlan_pcp = VLAN_PCP(ntohs(pkey->vlan));
    } else {
        fields->vlan_vid = -1;
        fields->vlan_pcp = 0;
    }
    OF_MATCH_MASK_VLAN_VID_EXACT_SET(match);
    OF_MATCH_MASK_VLAN_PCP_EXACT_SET(match);

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_IPV4)) {
        fields->ipv4_src = ntohl(pkey->ipv4.ipv4_src);
        fields->ipv4_dst = ntohl(pkey->ipv4.ipv4_dst);
        fields->ip_dscp = pkey->ipv4.ipv4_tos;
        fields->ip_proto = pkey->ipv4.ipv4_proto;
        OF_MATCH_MASK_IPV4_SRC_EXACT_SET(match);
        OF_MATCH_MASK_IPV4_DST_EXACT_SET(match);
        OF_MATCH_MASK_IP_DSCP_EXACT_SET(match);
        OF_MATCH_MASK_IP_PROTO_EXACT_SET(match);
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_IPV6)) {
        memcpy(&fields->ipv6_src, pkey->ipv6.ipv6_src, OF_IPV6_BYTES);
        memcpy(&fields->ipv6_dst, pkey->ipv6.ipv6_dst, OF_IPV6_BYTES);
        fields->ipv6_flabel = ntohl(pkey->ipv6.ipv6_label);
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ARP)) {
        fields->arp_op = ntohs(pkey->arp.arp_op);
        fields->arp_spa = ntohl(pkey->arp.arp_sip);
        fields->arp_tpa = ntohl(pkey->arp.arp_tip);
        memcpy(&fields->arp_sha, pkey->arp.arp_sha, OF_MAC_ADDR_BYTES);
        memcpy(&fields->arp_tha, pkey->arp.arp_tha, OF_MAC_ADDR_BYTES);

        /* Special case ARP for OF 1.0 */
        fields->ipv4_src = ntohl(pkey->arp.arp_sip);
        fields->ipv4_dst = ntohl(pkey->arp.arp_tip);
        fields->ip_proto = ntohs(pkey->arp.arp_op) & 0xFF;
        OF_MATCH_MASK_IPV4_SRC_EXACT_SET(match);
        OF_MATCH_MASK_IPV4_DST_EXACT_SET(match);
        OF_MATCH_MASK_IP_PROTO_EXACT_SET(match);
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_TCP)) {
        fields->tcp_dst = ntohs(pkey->tcp.tcp_dst);
        fields->tcp_src = ntohs(pkey->tcp.tcp_src);
        OF_MATCH_MASK_TCP_DST_EXACT_SET(match);
        OF_MATCH_MASK_TCP_SRC_EXACT_SET(match);
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_UDP)) {
        fields->udp_dst = ntohs(pkey->udp.udp_dst);
        fields->udp_src = ntohs(pkey->udp.udp_src);

        /* Special case UDP for OF 1.0 */
        fields->tcp_dst = ntohs(pkey->udp.udp_dst);
        fields->tcp_src = ntohs(pkey->udp.udp_src);
        OF_MATCH_MASK_TCP_DST_EXACT_SET(match);
        OF_MATCH_MASK_TCP_SRC_EXACT_SET(match);
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ICMP)) {
        fields->icmpv4_type = pkey->icmp.icmp_type;
        fields->icmpv4_code = pkey->icmp.icmp_code;

        /* Special case ICMP for OF 1.0 */
        fields->tcp_dst = pkey->icmp.icmp_code;
        fields->tcp_src = pkey->icmp.icmp_type;
        OF_MATCH_MASK_TCP_DST_EXACT_SET(match);
        OF_MATCH_MASK_TCP_SRC_EXACT_SET(match);
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ICMPV6)) {
        fields->icmpv6_type = pkey->icmpv6.icmpv6_type;
        fields->icmpv6_code = pkey->icmpv6.icmpv6_code;
    }

    /*
     * Not supported by OVS:
     * sctp_dst, sctp_src, ipv6_nd_target, ipv6_nd_sll, ipv6_nd_tll,
     * mpls_label, mpls_tc, ip_ecn, in_phy_port, metadata
    */
}

void
ind_ovs_key_to_cfr(const struct ind_ovs_parsed_key *pkey,
                   struct ind_ovs_cfr *cfr)
{
    cfr->in_port = pkey->in_port;

    memcpy(cfr->dl_dst, pkey->ethernet.eth_dst, OF_MAC_ADDR_BYTES);
    memcpy(cfr->dl_src, pkey->ethernet.eth_src, OF_MAC_ADDR_BYTES);

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ETHERTYPE)) {
        cfr->dl_type = pkey->ethertype;
        if (ntohs(cfr->dl_type) <= OF_DL_TYPE_NOT_ETH_TYPE) {
            cfr->dl_type = htons(OF_DL_TYPE_NOT_ETH_TYPE);
        }
    } else {
        cfr->dl_type = htons(OF_DL_TYPE_NOT_ETH_TYPE);
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_VLAN)) {
        cfr->dl_vlan = pkey->vlan;
    } else {
        cfr->dl_vlan = VLAN_CFI_BIT;
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_IPV4)) {
        cfr->nw_tos = pkey->ipv4.ipv4_tos;
        cfr->nw_proto = pkey->ipv4.ipv4_proto;
        cfr->nw_src = pkey->ipv4.ipv4_src;
        cfr->nw_dst = pkey->ipv4.ipv4_dst;
    } else if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ARP)) {
        cfr->nw_tos = 0;
        cfr->nw_proto = ntohs(pkey->arp.arp_op) & 0xFF;
        cfr->nw_src = pkey->arp.arp_sip;
        cfr->nw_dst = pkey->arp.arp_tip;
    } else {
        cfr->nw_tos = 0;
        cfr->nw_proto = 0;
        cfr->nw_src = 0;
        cfr->nw_dst = 0;
    }

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_TCP)) {
        cfr->tp_src = pkey->tcp.tcp_src;
        cfr->tp_dst = pkey->tcp.tcp_dst;
    } else if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_UDP)) {
        cfr->tp_src = pkey->udp.udp_src;
        cfr->tp_dst = pkey->udp.udp_dst;
    } else if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ICMP)) {
        cfr->tp_src = pkey->icmp.icmp_type << 8;
        cfr->tp_dst = pkey->icmp.icmp_code << 8;
    } else {
        cfr->tp_src = 0;
        cfr->tp_dst = 0;
    }
}

void
ind_ovs_match_to_cfr(const of_match_t *match,
                     struct ind_ovs_cfr *fields, struct ind_ovs_cfr *masks)
{
    assert(match->version == OF_VERSION_1_0);

    memset(fields, 0, sizeof(*fields));
    memset(masks, 0, sizeof(*masks));

    /* input port */
    fields->in_port = match->fields.in_port;
    masks->in_port = match->masks.in_port;

    /* ether addrs */
    memcpy(fields->dl_dst, &match->fields.eth_dst, OF_MAC_ADDR_BYTES);
    memcpy(fields->dl_src, &match->fields.eth_src, OF_MAC_ADDR_BYTES);
    memcpy(masks->dl_src, &match->masks.eth_src, OF_MAC_ADDR_BYTES);
    memcpy(masks->dl_dst, &match->masks.eth_dst, OF_MAC_ADDR_BYTES);

    /* ether type */
    fields->dl_type = htons(match->fields.eth_type);
    masks->dl_type = htons(match->masks.eth_type);

    /* vlan & pcp are combined, with a bit indicating untagged */
    uint16_t vlan = (match->fields.vlan_vid & match->masks.vlan_vid);
    if (vlan == (uint16_t)-1) {
        fields->dl_vlan = VLAN_CFI_BIT;
        masks->dl_vlan = 0xffff;
    } else {
        fields->dl_vlan = htons(VLAN_TCI(match->fields.vlan_vid, match->fields.vlan_pcp));
        masks->dl_vlan = htons(VLAN_TCI(match->masks.vlan_vid, match->masks.vlan_pcp));
    }

    fields->nw_tos = match->fields.ip_dscp & 0xFC;
    fields->nw_proto = match->fields.ip_proto;
    fields->nw_src = htonl(match->fields.ipv4_src);
    fields->nw_dst = htonl(match->fields.ipv4_dst);
    masks->nw_tos = match->masks.ip_dscp & 0xFC;
    masks->nw_proto = match->masks.ip_proto;
    masks->nw_src = htonl(match->masks.ipv4_src);
    masks->nw_dst = htonl(match->masks.ipv4_dst);

    /* subsequent fields are type dependent */
    if (match->fields.eth_type == ETH_P_IP) {
        if (match->fields.ip_proto == IPPROTO_TCP
            || match->fields.ip_proto == IPPROTO_UDP
            || match->fields.ip_proto == IPPROTO_ICMP) {
            fields->tp_src = htons(match->fields.tcp_src);
            fields->tp_dst = htons(match->fields.tcp_dst);
            masks->tp_src = htons(match->masks.tcp_src);
            masks->tp_dst = htons(match->masks.tcp_dst);
        }
    }

    /* normalize the flow entry */
    int i;
    char *f = (char *)fields;
    char *m = (char *)masks;
    for (i = 0; i < sizeof (struct ind_ovs_cfr); i++) {
        f[i] &= m[i];
    }
}
