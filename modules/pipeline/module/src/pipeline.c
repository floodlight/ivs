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

#include <pipeline/pipeline.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <ivs/ivs.h>
#include <ivs/actions.h>
#include <loci/loci.h>

static int pipeline_openflow_version;
static pipeline_lookup_f pipeline_lookup;

void ind_ovs_fwd_update_cfr(struct ind_ovs_cfr *cfr, struct xbuf *actions);

void
pipeline_init(int openflow_version, pipeline_lookup_f lookup)
{
    pipeline_openflow_version = openflow_version;
    pipeline_lookup = lookup;
}

void
pipeline_finish(void)
{
}

indigo_error_t
pipeline_process(struct ind_ovs_cfr *cfr,
                 struct pipeline_result *result)
{
    uint8_t table_id = 0;

    while (table_id != (uint8_t)-1) {
        struct ind_ovs_flow_effects *effects =
            pipeline_lookup(table_id, cfr, &result->stats);
        if (effects == NULL) {
            if (pipeline_openflow_version < OF_VERSION_1_3) {
                uint8_t reason = OF_PACKET_IN_REASON_NO_MATCH;
                xbuf_append_attr(&result->actions, IND_OVS_ACTION_CONTROLLER, &reason, sizeof(reason));
            }
            break;
        }

        xbuf_append(&result->actions, xbuf_data(&effects->apply_actions),
                    xbuf_length(&effects->apply_actions));

        table_id = effects->next_table_id;

        if (table_id != (uint8_t)-1) {
            ind_ovs_fwd_update_cfr(cfr, &effects->apply_actions);
        }
    }

    return INDIGO_ERROR_NONE;
}

/*
 * Scan actions list for field modifications and update the CFR accordingly
 */
void
ind_ovs_fwd_update_cfr(struct ind_ovs_cfr *cfr, struct xbuf *actions)
{
    struct nlattr *attr;
    XBUF_FOREACH(xbuf_data(actions), xbuf_length(actions), attr) {
        switch (attr->nla_type) {
        case IND_OVS_ACTION_SET_ETH_DST:
            memcpy(&cfr->dl_dst, xbuf_payload(attr), sizeof(cfr->dl_dst));
            break;
        case IND_OVS_ACTION_SET_ETH_SRC:
            memcpy(&cfr->dl_src, xbuf_payload(attr), sizeof(cfr->dl_src));
            break;
        case IND_OVS_ACTION_SET_IPV4_DST:
            cfr->nw_dst = *XBUF_PAYLOAD(attr, uint32_t);
            break;
        case IND_OVS_ACTION_SET_IPV4_SRC:
            cfr->nw_src = *XBUF_PAYLOAD(attr, uint32_t);
            break;
        case IND_OVS_ACTION_SET_IP_DSCP:
            cfr->nw_tos &= ~IP_DSCP_MASK;
            cfr->nw_tos |= *XBUF_PAYLOAD(attr, uint8_t);
            break;
        case IND_OVS_ACTION_SET_IP_ECN:
            cfr->nw_tos &= ~IP_ECN_MASK;
            cfr->nw_tos |= *XBUF_PAYLOAD(attr, uint8_t);
            break;
        case IND_OVS_ACTION_SET_TCP_DST:
        case IND_OVS_ACTION_SET_UDP_DST:
        case IND_OVS_ACTION_SET_TP_DST:
            cfr->tp_dst = *XBUF_PAYLOAD(attr, uint16_t);
            break;
        case IND_OVS_ACTION_SET_TCP_SRC:
        case IND_OVS_ACTION_SET_UDP_SRC:
        case IND_OVS_ACTION_SET_TP_SRC:
            cfr->tp_src = *XBUF_PAYLOAD(attr, uint16_t);
            break;
        case IND_OVS_ACTION_SET_VLAN_VID: {
            uint16_t vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
            cfr->dl_vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(ntohs(cfr->dl_vlan))) | VLAN_CFI_BIT);
            break;
        }
        case IND_OVS_ACTION_SET_VLAN_PCP: {
            uint8_t vlan_pcp = *XBUF_PAYLOAD(attr, uint8_t);
            cfr->dl_vlan = htons(VLAN_TCI(VLAN_VID(ntohs(cfr->dl_vlan)), vlan_pcp) | VLAN_CFI_BIT);
            break;
        }
        case IND_OVS_ACTION_SET_IPV6_DST:
            memcpy(&cfr->ipv6_dst, xbuf_payload(attr), sizeof(cfr->ipv6_dst));
            break;
        case IND_OVS_ACTION_SET_IPV6_SRC:
            memcpy(&cfr->ipv6_src, xbuf_payload(attr), sizeof(cfr->ipv6_src));
            break;
        /* Not implemented: IND_OVS_ACTION_SET_IPV6_FLABEL */
        case IND_OVS_ACTION_SET_LAG_ID:
            memcpy(&cfr->lag_id, xbuf_payload(attr), sizeof(cfr->lag_id));
            break;
        case IND_OVS_ACTION_SET_VRF:
            memcpy(&cfr->vrf, xbuf_payload(attr), sizeof(cfr->vrf));
            break;
        case IND_OVS_ACTION_SET_L3_INTERFACE_CLASS_ID:
            memcpy(&cfr->l3_interface_class_id, xbuf_payload(attr), sizeof(cfr->l3_interface_class_id));
            break;
        case IND_OVS_ACTION_SET_L3_SRC_CLASS_ID:
            memcpy(&cfr->l3_src_class_id, xbuf_payload(attr), sizeof(cfr->l3_src_class_id));
            break;
        case IND_OVS_ACTION_SET_L3_DST_CLASS_ID:
            memcpy(&cfr->l3_dst_class_id, xbuf_payload(attr), sizeof(cfr->l3_dst_class_id));
            break;
        case IND_OVS_ACTION_SET_GLOBAL_VRF_ALLOWED: {
            uint8_t flag = *XBUF_PAYLOAD(attr, uint8_t);
            cfr->global_vrf_allowed = flag & 1;
            break;
        }
        default:
            break;
        }
    }
}

void
pipeline_result_init(struct pipeline_result *result)
{
    xbuf_init(&result->actions);
    xbuf_init(&result->stats);
}

/* Reinitialize without reallocating memory */
void
pipeline_result_reset(struct pipeline_result *result)
{
    xbuf_reset(&result->actions);
    xbuf_reset(&result->stats);
}

void
pipeline_result_cleanup(struct pipeline_result *result)
{
    xbuf_cleanup(&result->actions);
    xbuf_cleanup(&result->stats);
}
