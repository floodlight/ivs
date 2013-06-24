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
