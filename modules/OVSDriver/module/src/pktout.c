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

#include "ovs_driver_int.h"
#include <action/action.h>
#include <errno.h>

static bool check_for_table_action(of_list_action_t *actions, uint32_t *queue_id);
static indigo_error_t translate_openflow_actions(of_list_action_t *actions, struct ind_ovs_parsed_key *key, struct nl_msg *msg);

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *of_packet_out)
{
    of_port_no_t     of_port_num;
    of_list_action_t of_list_action[1];
    of_octets_t      of_octets[1];
    indigo_error_t   rv;
    uint32_t         queue_id = 0;

    of_packet_out_in_port_get(of_packet_out, &of_port_num);
    of_packet_out_data_get(of_packet_out, of_octets);
    of_packet_out_actions_bind(of_packet_out, of_list_action);

    bool use_table = check_for_table_action(of_list_action, &queue_id);

    int netlink_pid;
    if (use_table) {
        if (of_port_num == OF_PORT_DEST_CONTROLLER) {
            of_port_num = OF_PORT_DEST_LOCAL;
        }
        /* Send the packet to in_port's upcall thread */
        struct ind_ovs_port *in_port = ind_ovs_port_lookup(of_port_num);
        if (in_port == NULL) {
            LOG_ERROR("controller specified an invalid packet-out in_port: 0x%x", of_port_num);
            return INDIGO_ERROR_PARAM;
        }
        netlink_pid = nl_socket_get_local_port(in_port->notify_socket);
    } else {
        /* Send the packet back to ourselves with the full key */
        netlink_pid = nl_socket_get_local_port(ind_ovs_socket);
    }

    /* Create the OVS_PACKET_CMD_EXECUTE message which will be used twice: once
     * to ask the kernel to parse the packet, and then again with the real actions. */
    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_packet_family, OVS_PACKET_CMD_EXECUTE);

    /*
    * The key attribute sent to the kernel only needs to have the metadata:
    * in_port, priority, etc. The kernel parses the packet to get the rest.
    */
    struct nlattr *key = nla_nest_start(msg, OVS_PACKET_ATTR_KEY);
    if (of_port_num < IND_OVS_MAX_PORTS) {
        nla_put_u32(msg, OVS_KEY_ATTR_IN_PORT, of_port_num);
    } else if (of_port_num == OF_PORT_DEST_LOCAL) {
        nla_put_u32(msg, OVS_KEY_ATTR_IN_PORT, OVSP_LOCAL);
    } else {
        /* Can't have an empty key. */
        nla_put_u32(msg, OVS_KEY_ATTR_PRIORITY, 0);
    }
    if (use_table && queue_id) {
        nla_put_u32(msg, OVS_KEY_ATTR_PRIORITY, queue_id);
    }
    nla_nest_end(msg, key);

    nla_put(msg, OVS_PACKET_ATTR_PACKET, of_octets->bytes, of_octets->data);

    struct nlattr *actions = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);
    struct nlattr *action_attr = nla_nest_start(msg, OVS_ACTION_ATTR_USERSPACE);
    nla_put_u32(msg, OVS_USERSPACE_ATTR_PID, netlink_pid);
    nla_nest_end(msg, action_attr);
    nla_nest_end(msg, actions);

    /* Send the first message */
    int err = nl_send_auto(ind_ovs_socket, msg);
    if (err < 0) {
        LOG_ERROR("nl_send failed: %s", nl_geterror(err));
        ind_ovs_nlmsg_freelist_free(msg);
        return INDIGO_ERROR_UNKNOWN;
    }

    if (use_table) {
        /* An upcall thread will forward the packet */
        ind_ovs_nlmsg_freelist_free(msg);
        return INDIGO_ERROR_NONE;
    }

    /* Receive the OVS_PACKET_CMD_ACTION we just caused */
    struct nl_msg *reply_msg = ind_ovs_recv_nlmsg(ind_ovs_socket);
    if (reply_msg == NULL) {
        LOG_ERROR("ind_ovs_recv_nlmsg failed: %s", strerror(errno));
        ind_ovs_nlmsg_freelist_free(msg);
        return INDIGO_ERROR_UNKNOWN;
    }

    struct nlmsghdr *nlh = nlmsg_hdr(reply_msg);
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        assert(nlh->nlmsg_seq == nlmsg_hdr(msg)->nlmsg_seq);
        LOG_ERROR("Kernel failed to parse packet-out data");
        ind_ovs_nlmsg_freelist_free(msg);
        ind_ovs_nlmsg_freelist_free(reply_msg);
        return INDIGO_ERROR_UNKNOWN;
    }

    /* Parse the reply to get the flow key */
    assert(nlh->nlmsg_type == ovs_packet_family);
#ifndef NDEBUG
    struct genlmsghdr *gnlh = (void *)(nlh + 1);
    assert(gnlh->cmd == OVS_PACKET_CMD_ACTION);
#endif
    key = nlmsg_find_attr(nlh,
                          sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
                          OVS_PACKET_ATTR_KEY);
    assert(key);

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key(key, &pkey);

    ind_ovs_nlmsg_freelist_free(reply_msg);

    /* Discard the actions list added earlier */
    nlmsg_hdr(msg)->nlmsg_len -= nla_total_size(nla_len(actions));

    /* Add the real actions generated from the kernel's flow key */
    struct nlattr *actions_attr = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);
    rv = translate_openflow_actions(of_list_action, &pkey, msg);
    if (rv < 0) {
        ind_ovs_nlmsg_freelist_free(msg);
        return rv;
    }
    ind_ovs_nla_nest_end(msg, actions_attr);

    /* Send the second message */
    if (ind_ovs_transact(msg) < 0) {
        LOG_ERROR("OVS_PACKET_CMD_EXECUTE failed");
        return INDIGO_ERROR_UNKNOWN;
    }

    return INDIGO_ERROR_NONE;
}

/* Check for a output to OFPP_TABLE */
static bool
check_for_table_action(of_list_action_t *actions, uint32_t *queue_id)
{
    of_object_t action;
    int rv;
    OF_LIST_ACTION_ITER(actions, &action, rv) {
        switch (action.object_id) {
        case OF_ACTION_OUTPUT: {
            of_port_no_t port_no;
            of_action_output_port_get(&action, &port_no);
            if (port_no != OF_PORT_DEST_USE_TABLE) {
                return false;
            } else {
                return true;
            }
        }
        case OF_ACTION_SET_QUEUE: {
            of_action_set_queue_queue_id_get(&action, queue_id);
            break;
        }
        default:
            return false;
        }
    }

    return false;
}

static void
flood(struct action_context *ctx, uint32_t in_port)
{
    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port && i != in_port && !port->no_flood) {
            action_output(ctx, i);
        }
    }
}

static indigo_error_t
translate_openflow_actions(of_list_action_t *actions, struct ind_ovs_parsed_key *pkey, struct nl_msg *msg)
{
    struct action_context ctx;
    action_context_init(&ctx, pkey, NULL, msg);

    of_object_t act;
    int rv;
    OF_LIST_ACTION_ITER(actions, &act, rv) {
        switch (act.object_id) {
        case OF_ACTION_OUTPUT: {
            of_port_no_t port_no;
            of_action_output_port_get(&act, &port_no);
            switch (port_no) {
                case OF_PORT_DEST_CONTROLLER: {
                    uint8_t reason = OF_PACKET_IN_REASON_ACTION;
                    uint64_t userdata = IVS_PKTIN_USERDATA(reason, 0);
                    action_controller(&ctx, userdata);
                    break;
                }
                case OF_PORT_DEST_ALL:
                    LOG_ERROR("unsupported output port OFPP_ALL");
                    return INDIGO_ERROR_COMPAT;
                case OF_PORT_DEST_FLOOD:
                    flood(&ctx, pkey->in_port);
                    break;
                case OF_PORT_DEST_USE_TABLE:
                    LOG_ERROR("unsupported output port OFPP_TABLE");
                    return INDIGO_ERROR_COMPAT;
                case OF_PORT_DEST_LOCAL:
                    action_output_local(&ctx);
                    break;
                case OF_PORT_DEST_IN_PORT:
                    action_output_in_port(&ctx);
                    break;
                case OF_PORT_DEST_NORMAL:
                    LOG_ERROR("unsupported output port OFPP_NORMAL");
                    return INDIGO_ERROR_COMPAT;
                default: {
                    if (port_no < IND_OVS_MAX_PORTS) {
                        action_output(&ctx, port_no);
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
            of_object_t oxm;
            of_action_set_field_field_bind(&act, &oxm);
            switch (oxm.object_id) {
                case OF_OXM_VLAN_VID: {
                    uint16_t vlan_vid;
                    of_oxm_vlan_vid_value_get(&oxm, &vlan_vid);
                    action_set_vlan_vid(&ctx, vlan_vid);
                    break;
                }
                case OF_OXM_VLAN_PCP: {
                    uint8_t vlan_pcp;
                    of_oxm_vlan_pcp_value_get(&oxm, &vlan_pcp);
                    action_set_vlan_pcp(&ctx, vlan_pcp);
                    break;
                }
                case OF_OXM_ETH_SRC: {
                    of_mac_addr_t mac;
                    of_oxm_eth_src_value_get(&oxm, &mac);
                    action_set_eth_src(&ctx, mac);
                    break;
                }
                case OF_OXM_ETH_DST: {
                    of_mac_addr_t mac;
                    of_oxm_eth_dst_value_get(&oxm, &mac);
                    action_set_eth_dst(&ctx, mac);
                    break;
                }
                case OF_OXM_IPV4_SRC: {
                    uint32_t ipv4;
                    of_oxm_ipv4_src_value_get(&oxm, &ipv4);
                    action_set_ipv4_src(&ctx, ipv4);
                    break;
                }
                case OF_OXM_IPV4_DST: {
                    uint32_t ipv4;
                    of_oxm_ipv4_dst_value_get(&oxm, &ipv4);
                    action_set_ipv4_dst(&ctx, ipv4);
                    break;
                }
                case OF_OXM_IP_DSCP: {
                    uint8_t ip_dscp;
                    of_oxm_ip_dscp_value_get(&oxm, &ip_dscp);

                    if (ip_dscp > ((uint8_t)IP_DSCP_MASK >> 2)) {
                        LOG_ERROR("invalid dscp %d in action %s", ip_dscp,
                                of_object_id_str[act.object_id]);
                        return INDIGO_ERROR_COMPAT;
                    }

                    ip_dscp <<= 2;
                    action_set_ipv4_dscp(&ctx, ip_dscp);
                    action_set_ipv6_dscp(&ctx, ip_dscp);
                    break;
                }
                case OF_OXM_IP_ECN: {
                    uint8_t ip_ecn;
                    of_oxm_ip_ecn_value_get(&oxm, &ip_ecn);

                    if (ip_ecn > IP_ECN_MASK) {
                        LOG_ERROR("invalid ecn %d in action %s", ip_ecn,
                                of_object_id_str[act.object_id]);
                        return INDIGO_ERROR_COMPAT;
                    }

                    action_set_ipv4_ecn(&ctx, ip_ecn);
                    action_set_ipv6_ecn(&ctx, ip_ecn);
                    break;
                }
                case OF_OXM_IPV6_SRC: {
                    of_ipv6_t ipv6;
                    of_oxm_ipv6_src_value_get(&oxm, &ipv6);
                    action_set_ipv6_src(&ctx, ipv6);
                    break;
                }
                case OF_OXM_IPV6_DST: {
                    of_ipv6_t ipv6;
                    of_oxm_ipv6_dst_value_get(&oxm, &ipv6);
                    action_set_ipv6_dst(&ctx, ipv6);
                    break;
                }
                case OF_OXM_IPV6_FLABEL: {
                    uint32_t flabel;
                    of_oxm_ipv6_flabel_value_get(&oxm, &flabel);

                    if (flabel > IPV6_FLABEL_MASK) {
                        LOG_ERROR("invalid flabel 0x%04x in action %s", flabel,
                                of_object_id_str[act.object_id]);
                        return INDIGO_ERROR_COMPAT;
                    }

                    action_set_ipv6_flabel(&ctx, flabel);
                    break;
                }
                case OF_OXM_TCP_SRC: {
                    uint16_t port;
                    of_oxm_tcp_src_value_get(&oxm, &port);
                    action_set_tcp_src(&ctx, port);
                    break;
                }
                case OF_OXM_TCP_DST: {
                    uint16_t port;
                    of_oxm_tcp_dst_value_get(&oxm, &port);
                    action_set_tcp_dst(&ctx, port);
                    break;
                }
                case OF_OXM_UDP_SRC: {
                    uint16_t port;
                    of_oxm_udp_src_value_get(&oxm, &port);
                    action_set_udp_src(&ctx, port);
                    break;
                }
                case OF_OXM_UDP_DST: {
                    uint16_t port;
                    of_oxm_udp_dst_value_get(&oxm, &port);
                    action_set_udp_dst(&ctx, port);
                    break;
                }
                default:
                    LOG_ERROR("unsupported set-field oxm %s", of_object_id_str[oxm.object_id]);
                    return INDIGO_ERROR_COMPAT;
            }
            break;
        }
        case OF_ACTION_SET_DL_DST: {
            of_mac_addr_t mac;
            of_action_set_dl_dst_dl_addr_get(&act, &mac);
            action_set_eth_dst(&ctx, mac);
            break;
        }
        case OF_ACTION_SET_DL_SRC: {
            of_mac_addr_t mac;
            of_action_set_dl_src_dl_addr_get(&act, &mac);
            action_set_eth_src(&ctx, mac);
            break;
        }
        case OF_ACTION_SET_NW_DST: {
            uint32_t ipv4;
            of_action_set_nw_dst_nw_addr_get(&act, &ipv4);
            action_set_ipv4_dst(&ctx, ipv4);
            break;
        }
        case OF_ACTION_SET_NW_SRC: {
            uint32_t ipv4;
            of_action_set_nw_src_nw_addr_get(&act, &ipv4);
            action_set_ipv4_src(&ctx, ipv4);
            break;
        }
        case OF_ACTION_SET_NW_TOS: {
            uint8_t tos;
            of_action_set_nw_tos_nw_tos_get(&act, &tos);
            action_set_ipv4_dscp(&ctx, tos);
            action_set_ipv6_dscp(&ctx, tos);
            break;
        }
        case OF_ACTION_SET_TP_DST: {
            uint16_t port;
            of_action_set_tp_dst_tp_port_get(&act, &port);
            action_set_tcp_dst(&ctx, port);
            action_set_udp_dst(&ctx, port);
            break;
        }
        case OF_ACTION_SET_TP_SRC: {
            uint16_t port;
            of_action_set_tp_src_tp_port_get(&act, &port);
            action_set_tcp_src(&ctx, port);
            action_set_udp_src(&ctx, port);
            break;
        }
        case OF_ACTION_SET_VLAN_VID: {
            uint16_t vlan_vid;
            of_action_set_vlan_vid_vlan_vid_get(&act, &vlan_vid);
            action_set_vlan_vid(&ctx, vlan_vid);
            break;
        }
        case OF_ACTION_SET_VLAN_PCP: {
            uint8_t vlan_pcp;
            of_action_set_vlan_pcp_vlan_pcp_get(&act, &vlan_pcp);
            action_set_vlan_pcp(&ctx, vlan_pcp);
            break;
        }
        case OF_ACTION_POP_VLAN:
        case OF_ACTION_STRIP_VLAN: {
            action_pop_vlan(&ctx);
            break;
        }
        case OF_ACTION_PUSH_VLAN: {
            uint16_t eth_type;
            of_action_push_vlan_ethertype_get(&act, &eth_type);

            if (eth_type != ETH_P_8021Q) {
                LOG_ERROR("unsupported eth_type 0x%04x in action %s", eth_type,
                           of_object_id_str[act.object_id]);
                return INDIGO_ERROR_COMPAT;
            }

            action_push_vlan(&ctx);
            break;
        }
        case OF_ACTION_DEC_NW_TTL:
        case OF_ACTION_NICIRA_DEC_TTL: {
            if (ATTR_BITMAP_TEST(ctx.current_key.populated, OVS_KEY_ATTR_IPV4)) {
                ATTR_BITMAP_SET(ctx.modified_attrs, OVS_KEY_ATTR_IPV4);
                if (ctx.current_key.ipv4.ipv4_ttl == 0
                    || --ctx.current_key.ipv4.ipv4_ttl == 0) {
                    return INDIGO_ERROR_NONE;
                }
            }

            if (ATTR_BITMAP_TEST(ctx.current_key.populated, OVS_KEY_ATTR_IPV6)) {
                ATTR_BITMAP_SET(ctx.modified_attrs, OVS_KEY_ATTR_IPV6);
                if (ctx.current_key.ipv6.ipv6_hlimit == 0
                    || --ctx.current_key.ipv6.ipv6_hlimit == 0) {
                    return INDIGO_ERROR_NONE;
                }
            }
            break;
        }
        case OF_ACTION_SET_NW_TTL: {
            uint8_t ttl;
            of_action_set_nw_ttl_nw_ttl_get(&act, &ttl);
            action_set_ipv4_ttl(&ctx, ttl);
            action_set_ipv6_ttl(&ctx, ttl);
            break;
        }
        case OF_ACTION_SET_QUEUE: {
            uint32_t queue_id;
            of_action_set_queue_queue_id_get(&act, &queue_id);
            action_set_priority(&ctx, queue_id);
            break;
        }
        default:
            LOG_ERROR("unsupported action %s", of_object_id_str[act.object_id]);
            return INDIGO_ERROR_COMPAT;
        }
    }

    return INDIGO_ERROR_NONE;
}
