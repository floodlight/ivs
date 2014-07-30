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
 * Translate actions from LOCI into OVS Netlink attributes.
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif
#include "action.h"
#include <byteswap.h>
#include <linux/if_ether.h>
#include <action/action.h>
#include <indigo/of_state_manager.h>
#include "group.h"

#define AIM_LOG_MODULE_NAME pipeline_standard
#include <AIM/aim_log.h>

static void process_group(struct action_context *ctx, struct group *group);

void
pipeline_standard_translate_actions(
    struct action_context *ctx,
    struct xbuf *xbuf)
{
    struct nlattr *attr;
    XBUF_FOREACH(xbuf_data(xbuf), xbuf_length(xbuf), attr) {
        switch (attr->nla_type) {
        /* Output actions */
        case IND_OVS_ACTION_CONTROLLER:
            action_controller(ctx, *XBUF_PAYLOAD(attr, uint64_t));
            break;
        case IND_OVS_ACTION_OUTPUT:
            action_output(ctx, *XBUF_PAYLOAD(attr, uint32_t));
            break;
        case IND_OVS_ACTION_LOCAL:
            action_output_local(ctx);
            break;
        case IND_OVS_ACTION_IN_PORT:
            action_output_in_port(ctx);
            break;

        /* Ethernet actions */
        case IND_OVS_ACTION_SET_ETH_DST:
            action_set_eth_dst(ctx, *XBUF_PAYLOAD(attr, of_mac_addr_t));
            break;
        case IND_OVS_ACTION_SET_ETH_SRC:
            action_set_eth_src(ctx, *XBUF_PAYLOAD(attr, of_mac_addr_t));
            break;

        /* VLAN actions */
        case IND_OVS_ACTION_SET_VLAN_VID:
            action_set_vlan_vid(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            break;
        case IND_OVS_ACTION_SET_VLAN_PCP:
            action_set_vlan_pcp(ctx, *XBUF_PAYLOAD(attr, uint8_t));
            break;
        case IND_OVS_ACTION_POP_VLAN:
            action_pop_vlan(ctx);
            break;
        case IND_OVS_ACTION_PUSH_VLAN:
            action_push_vlan(ctx);
            break;

        /* IPv4 actions */
        case IND_OVS_ACTION_SET_IPV4_DST:
            action_set_ipv4_dst(ctx, *XBUF_PAYLOAD(attr, uint32_t));
            break;
        case IND_OVS_ACTION_SET_IPV4_SRC:
            action_set_ipv4_src(ctx, *XBUF_PAYLOAD(attr, uint32_t));
            break;

        /* IPv6 actions */
        case IND_OVS_ACTION_SET_IPV6_DST:
            action_set_ipv6_dst(ctx, *XBUF_PAYLOAD(attr, of_ipv6_t));
            break;
        case IND_OVS_ACTION_SET_IPV6_SRC:
            action_set_ipv6_src(ctx, *XBUF_PAYLOAD(attr, of_ipv6_t));
            break;
        case IND_OVS_ACTION_SET_IPV6_FLABEL:
            action_set_ipv6_flabel(ctx, *XBUF_PAYLOAD(attr, uint32_t));
            break;

        /* Generic IP actions */
        case IND_OVS_ACTION_SET_IP_DSCP:
            action_set_ipv4_dscp(ctx, *XBUF_PAYLOAD(attr, uint8_t));
            action_set_ipv6_dscp(ctx, *XBUF_PAYLOAD(attr, uint8_t));
            break;
        case IND_OVS_ACTION_SET_IP_ECN:
            action_set_ipv4_ecn(ctx, *XBUF_PAYLOAD(attr, uint8_t));
            action_set_ipv6_ecn(ctx, *XBUF_PAYLOAD(attr, uint8_t));
            break;
        case IND_OVS_ACTION_DEC_NW_TTL:
            /* Special cased because it can drop the packet */
            if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV4)) {
                ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV4);
                if (ctx->current_key.ipv4.ipv4_ttl == 0
                    || --ctx->current_key.ipv4.ipv4_ttl == 0) {
                    return;
                }
            }

            if (ATTR_BITMAP_TEST(ctx->current_key.populated, OVS_KEY_ATTR_IPV6)) {
                ATTR_BITMAP_SET(ctx->modified_attrs, OVS_KEY_ATTR_IPV6);
                if (ctx->current_key.ipv6.ipv6_hlimit == 0
                    || --ctx->current_key.ipv6.ipv6_hlimit == 0) {
                    return;
                }
            }
            break;
        case IND_OVS_ACTION_SET_NW_TTL:
            action_set_ipv4_ttl(ctx, *XBUF_PAYLOAD(attr, uint8_t));
            action_set_ipv6_ttl(ctx, *XBUF_PAYLOAD(attr, uint8_t));
            break;

        /* TCP actions */
        case IND_OVS_ACTION_SET_TCP_DST:
            action_set_tcp_dst(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            break;
        case IND_OVS_ACTION_SET_TCP_SRC:
            action_set_tcp_src(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            break;

        /* UDP actions */
        case IND_OVS_ACTION_SET_UDP_DST:
            action_set_udp_dst(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            break;
        case IND_OVS_ACTION_SET_UDP_SRC:
            action_set_udp_src(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            break;

        /* Generic L4 actions */
        case IND_OVS_ACTION_SET_TP_DST:
            action_set_tcp_dst(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            action_set_udp_dst(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            break;
        case IND_OVS_ACTION_SET_TP_SRC:
            action_set_tcp_src(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            action_set_udp_src(ctx, *XBUF_PAYLOAD(attr, uint16_t));
            break;

        /* Group action */
        case IND_OVS_ACTION_GROUP:
            process_group(ctx, *XBUF_PAYLOAD(attr, struct group *));
            break;

        default:
            break;
        }
    }
}

static void
process_group_bucket(struct action_context *ctx, struct group_bucket *bucket)
{
    pipeline_standard_translate_actions(ctx, &bucket->actions);
    /* TODO update stats */
}

/* TODO handle watch_port, watch_group */
static void
process_group(struct action_context *ctx, struct group *group)
{
    if (group->value.num_buckets == 0) {
        return;
    }

    if (group->type == OF_GROUP_TYPE_SELECT) {
        uint32_t hash = 0; /* TODO */
        struct group_bucket *bucket = &group->value.buckets[hash % group->value.num_buckets];
        process_group_bucket(ctx, bucket);
    } else if (group->type == OF_GROUP_TYPE_INDIRECT) {
        process_group_bucket(ctx, &group->value.buckets[0]);
    } else if (group->type == OF_GROUP_TYPE_ALL) {
        /* TODO reset ctx after each bucket */
        int i;
        for (i = 0; i < group->value.num_buckets; i++) {
            process_group_bucket(ctx, &group->value.buckets[i]);
        }
    } else if (group->type == OF_GROUP_TYPE_FF) {
        process_group_bucket(ctx, &group->value.buckets[0]);
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
                case OF_PORT_DEST_ALL:
                    AIM_LOG_ERROR("unsupported output port OFPP_ALL");
                    return INDIGO_ERROR_COMPAT;
                case OF_PORT_DEST_FLOOD:
                    AIM_LOG_ERROR("unsupported output port OFPP_FLOOD");
                    return INDIGO_ERROR_COMPAT;
                case OF_PORT_DEST_USE_TABLE:
                    AIM_LOG_ERROR("unsupported output port OFPP_TABLE");
                    return INDIGO_ERROR_COMPAT;
                case OF_PORT_DEST_LOCAL:
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_LOCAL, NULL, 0);
                    break;
                case OF_PORT_DEST_IN_PORT:
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_IN_PORT, NULL, 0);
                    break;
                case OF_PORT_DEST_NORMAL:
                    AIM_LOG_ERROR("unsupported output port OFPP_NORMAL");
                    return INDIGO_ERROR_COMPAT;
                default: {
                    xbuf_append_attr(xbuf, IND_OVS_ACTION_OUTPUT, &port_no, sizeof(port_no));
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
                        AIM_LOG_ERROR("invalid dscp %d in action %s", ip_dscp,
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
                        AIM_LOG_ERROR("invalid ecn %d in action %s", ip_ecn,
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
                        AIM_LOG_ERROR("invalid flabel 0x%04x in action %s", flabel,
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
                default:
                    AIM_LOG_ERROR("unsupported set-field oxm %s", of_object_id_str[oxm.header.object_id]);
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
                AIM_LOG_ERROR("unsupported eth_type 0x%04x in action %s", eth_type,
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
        case OF_ACTION_GROUP: {
            uint32_t group_id;
            of_action_group_group_id_get(&act.group, &group_id);
            struct group *group = indigo_core_group_acquire(group_id);
            if (group == NULL) {
                AIM_LOG_ERROR("nonexistent group %u", group_id);
                return INDIGO_ERROR_COMPAT;
            }
            xbuf_append_attr(xbuf, IND_OVS_ACTION_GROUP, &group, sizeof(group));
            break;
        }
        default:
            AIM_LOG_ERROR("unsupported action %s", of_object_id_str[act.header.object_id]);
            return INDIGO_ERROR_COMPAT;
        }
    }

    return INDIGO_ERROR_NONE;
}

void
pipeline_standard_cleanup_actions(struct xbuf *actions)
{
    struct nlattr *attr;
    XBUF_FOREACH(xbuf_data(actions), xbuf_length(actions), attr) {
        switch (attr->nla_type) {
        case IND_OVS_ACTION_GROUP: {
            struct group *group = *XBUF_PAYLOAD(attr, struct group *);
            indigo_core_group_release(group->id);
            break;
        }
        default:
            break;
        }
    }
    xbuf_cleanup(actions);
}
