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

#include <pipeline/pipeline.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <ivs/ivs.h>
#include <ivs/actions.h>
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <tcam/tcam.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>

#define AIM_LOG_MODULE_NAME pipeline_standard
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

#define NUM_TABLES 16

struct flowtable {
    struct tcam *tcam;
    struct ind_ovs_flow_stats matched_stats;
    struct ind_ovs_flow_stats missed_stats;
    uint8_t table_id;
};

struct flowtable_value {
    struct xbuf apply_actions;
    struct xbuf write_actions;
    uint64_t metadata;
    uint64_t metadata_mask;
    uint32_t meter_id;
    uint8_t next_table_id;
    bool clear_actions;
};

struct flowtable_entry {
    struct tcam_entry tcam_entry;
    struct flowtable_value value;

    /* Updated periodically from the kernel flows */
    struct ind_ovs_flow_stats stats;

    /* Packet stats from the last hit bit check */
    /* See indigo_fwd_table_stats_get */
    uint64_t last_hit_check_packets;

    /* Is this an OpenFlow 1.3 table-miss flow? */
    bool table_miss;
};

static void pipeline_standard_update_cfr(struct ind_ovs_cfr *cfr, struct xbuf *actions);

static int openflow_version = -1;
static struct flowtable *flowtables[NUM_TABLES];
static const indigo_core_table_ops_t table_ops;

static void
pipeline_standard_init(const char *name)
{
    if (!strcmp(name, "standard-1.0")) {
        openflow_version = OF_VERSION_1_0;
    } else if (!strcmp(name, "standard-1.3")) {
        openflow_version = OF_VERSION_1_3;
    } else {
        AIM_DIE("unexpected pipeline name '%s'", name);
    }

    int i;
    for (i = 0; i < NUM_TABLES; i++) {
        struct flowtable *flowtable = aim_zmalloc(sizeof(*flowtable));
        flowtable->table_id = i;
        flowtable->tcam = tcam_create(sizeof(struct ind_ovs_cfr), ind_ovs_salt);
        of_table_name_t name;
        snprintf(name, sizeof(name), "table %d", i);
        indigo_core_table_register(i, name, &table_ops, flowtable);
        flowtables[i] = flowtable;
    }
}

static void
pipeline_standard_finish(void)
{
    int i;
    for (i = 0; i < NUM_TABLES; i++) {
        indigo_core_table_unregister(i);
        tcam_destroy(flowtables[i]->tcam);
        aim_free(flowtables[i]);
    }
}

indigo_error_t
pipeline_standard_process(struct ind_ovs_parsed_key *key,
                          struct pipeline_result *result)
{
    struct ind_ovs_cfr cfr;
    ind_ovs_key_to_cfr(key, &cfr);

    uint8_t table_id = 0;
    if (flowtables[table_id] == NULL) {
        AIM_LOG_VERBOSE("table 0 missing, dropping packet");
        return INDIGO_ERROR_NONE;
    }

    while (table_id != (uint8_t)-1) {
        struct flowtable *flowtable = flowtables[table_id];
        AIM_ASSERT(flowtable != NULL);

        struct tcam_entry *tcam_entry = tcam_match(flowtable->tcam, &cfr);
        if (tcam_entry == NULL) {
            if (openflow_version < OF_VERSION_1_3) {
                uint64_t userdata = IVS_PKTIN_USERDATA(OF_PACKET_IN_REASON_NO_MATCH, 0);
                xbuf_append_attr(&result->actions, IND_OVS_ACTION_CONTROLLER, &userdata, sizeof(userdata));
            }
            xbuf_append_ptr(&result->stats, &flowtable->missed_stats);
            break;
        }

        struct flowtable_entry *entry = container_of(tcam_entry, tcam_entry, struct flowtable_entry);

        if (entry->table_miss) {
            xbuf_append_ptr(&result->stats, &flowtable->missed_stats);
        } else {
            xbuf_append_ptr(&result->stats, &flowtable->matched_stats);
        }

        xbuf_append_ptr(&result->stats, &entry->stats);

        xbuf_append(&result->actions, xbuf_data(&entry->value.apply_actions),
                    xbuf_length(&entry->value.apply_actions));

        table_id = entry->value.next_table_id;

        if (table_id != (uint8_t)-1) {
            pipeline_standard_update_cfr(&cfr, &entry->value.apply_actions);
        }
    }

    return INDIGO_ERROR_NONE;
}

static struct pipeline_ops pipeline_standard_ops = {
    .init = pipeline_standard_init,
    .finish = pipeline_standard_finish,
    .process = pipeline_standard_process,
};

void
__pipeline_standard_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    pipeline_register("standard-1.0", &pipeline_standard_ops);
    pipeline_register("standard-1.3", &pipeline_standard_ops);
}

/*
 * Scan actions list for field modifications and update the CFR accordingly
 */
static void
pipeline_standard_update_cfr(struct ind_ovs_cfr *cfr, struct xbuf *actions)
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
        default:
            break;
        }
    }
}

static indigo_error_t
parse_value(of_flow_add_t *flow_mod, struct flowtable_value *value,
            uint8_t table_id, bool table_miss)
{
    of_list_action_t openflow_actions;
    indigo_error_t err;

    xbuf_init(&value->apply_actions);
    xbuf_init(&value->write_actions);

    value->clear_actions = 0;
    value->meter_id = -1;
    value->next_table_id = -1;

    if (flow_mod->version == OF_VERSION_1_0) {
        of_flow_modify_actions_bind(flow_mod, &openflow_actions);
        if ((err = ind_ovs_translate_openflow_actions(&openflow_actions,
                                                      &value->apply_actions,
                                                      table_miss)) < 0) {
            return err;
        }
    } else {
        int rv;
        of_list_instruction_t insts;
        of_instruction_t inst;
        of_flow_modify_instructions_bind(flow_mod, &insts);

        uint8_t table_id;
        of_flow_modify_table_id_get(flow_mod, &table_id);

        OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
            switch (inst.header.object_id) {
            case OF_INSTRUCTION_APPLY_ACTIONS:
                of_instruction_apply_actions_actions_bind(&inst.apply_actions,
                                                          &openflow_actions);
                if ((err = ind_ovs_translate_openflow_actions(&openflow_actions,
                                                              &value->apply_actions,
                                                              table_miss)) < 0) {
                    return err;
                }
                break;
            case OF_INSTRUCTION_WRITE_ACTIONS:
                of_instruction_write_actions_actions_bind(&inst.write_actions,
                                                          &openflow_actions);
                if ((err = ind_ovs_translate_openflow_actions(&openflow_actions,
                                                              &value->write_actions,
                                                              table_miss)) < 0) {
                    return err;
                }
                break;
            case OF_INSTRUCTION_CLEAR_ACTIONS:
                value->clear_actions = 1;
                break;
            case OF_INSTRUCTION_GOTO_TABLE:
                of_instruction_goto_table_table_id_get(&inst.goto_table, &value->next_table_id);
                if (value->next_table_id <= table_id ||
                        value->next_table_id >= NUM_TABLES) {
                    AIM_LOG_WARN("invalid goto next_table_id %u", value->next_table_id);
                    return INDIGO_ERROR_RANGE;
                }
                break;
            case OF_INSTRUCTION_METER:
                of_instruction_meter_meter_id_get(&inst.meter, &value->meter_id);
                break;
            default:
                return INDIGO_ERROR_COMPAT;
            }
        }
    }

    xbuf_compact(&value->apply_actions);
    xbuf_compact(&value->write_actions);

    return INDIGO_ERROR_NONE;
}

static bool
is_table_miss(int version, const struct ind_ovs_cfr *mask, uint16_t priority)
{
    static struct ind_ovs_cfr table_miss_mask; /* all zeroes */
    return version >= OF_VERSION_1_3 &&
           priority == 0 &&
           memcmp(mask, &table_miss_mask, sizeof(table_miss_mask)) == 0;
}

static indigo_error_t
flowtable_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    struct flowtable *flowtable = table_priv;
    indigo_error_t rv;
    struct flowtable_entry *entry = aim_zmalloc(sizeof(*entry));
    of_match_t match;
    struct ind_ovs_cfr key;
    struct ind_ovs_cfr mask;
    uint16_t priority;

    if (of_flow_add_match_get(obj, &match) < 0) {
        aim_free(entry);
        return INDIGO_ERROR_UNKNOWN;
    }

    of_flow_add_priority_get(obj, &priority);

    ind_ovs_match_to_cfr(&match, &key, &mask);

    entry->table_miss = is_table_miss(openflow_version, &mask, priority);

    rv = parse_value(obj, &entry->value, flowtable->table_id, entry->table_miss);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    ind_ovs_fwd_write_lock();
    tcam_insert(flowtable->tcam, &entry->tcam_entry, &key, &mask, priority);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    struct flowtable *flowtable = table_priv;
    indigo_error_t rv;
    struct flowtable_entry *entry = entry_priv;
    struct flowtable_value value;

    rv = parse_value(obj, &value, flowtable->table_id, entry->table_miss);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    xbuf_cleanup(&entry->value.apply_actions);
    xbuf_cleanup(&entry->value.write_actions);
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct flowtable *flowtable = table_priv;
    struct flowtable_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    tcam_remove(flowtable->tcam, &entry->tcam_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();

    flow_stats->packets = entry->stats.packets;
    flow_stats->bytes = entry->stats.bytes;

    xbuf_cleanup(&entry->value.apply_actions);
    xbuf_cleanup(&entry->value.write_actions);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct flowtable_entry *entry = entry_priv;
    flow_stats->packets = entry->stats.packets;
    flow_stats->bytes = entry->stats.bytes;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit)
{
    struct flowtable_entry *entry = entry_priv;

    if (entry->stats.packets != entry->last_hit_check_packets) {
        entry->last_hit_check_packets = entry->stats.packets;
        *hit = true;
    } else {
        *hit = false;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id,
    indigo_fi_table_stats_t *table_stats)
{
    struct flowtable *flowtable = table_priv;
    table_stats->lookup_count = flowtable->matched_stats.packets +
                                flowtable->missed_stats.packets;
    table_stats->matched_count = flowtable->matched_stats.packets;
    return INDIGO_ERROR_NONE;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = flowtable_entry_create,
    .entry_modify = flowtable_entry_modify,
    .entry_delete = flowtable_entry_delete,
    .entry_stats_get = flowtable_entry_stats_get,
    .entry_hit_status_get = flowtable_entry_hit_status_get,
    .table_stats_get = flowtable_stats_get,
};
