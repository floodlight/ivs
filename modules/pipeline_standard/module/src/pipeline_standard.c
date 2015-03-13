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
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <tcam/tcam.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <murmur/murmur.h>
#include "cfr.h"
#include "action.h"
#include "group.h"

#define AIM_LOG_MODULE_NAME pipeline_standard
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

#define NUM_TABLES 16

/* Overall minimum average interval between packet-ins (in us) */
#define PKTIN_INTERVAL 3000

/* Overall packet-in burstiness tolerance. */
#define PKTIN_BURST_SIZE 32

struct flowtable {
    struct tcam *tcam;
    struct stats_handle matched_stats_handle;
    struct stats_handle missed_stats_handle;
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

    struct stats_handle stats_handle;

    /* Packet stats from the last hit bit check */
    /* See indigo_fwd_table_stats_get */
    uint64_t last_hit_check_packets;

    /* Is this an OpenFlow 1.3 table-miss flow? */
    bool table_miss;
};

static void pipeline_standard_update_cfr(struct pipeline_standard_cfr *cfr, struct xbuf *actions);
static void memor(void *_dst, const void *_src, int len);
static void translate_cfr_mask(struct ind_ovs_parsed_key *mask, const struct pipeline_standard_cfr *cfr, const struct pipeline_standard_cfr *cfr_mask);

static int openflow_version = -1;
static struct flowtable *flowtables[NUM_TABLES];
static const indigo_core_table_ops_t table_ops;

static struct ind_ovs_pktin_socket pktin_soc;

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
        flowtable->tcam = tcam_create(sizeof(struct pipeline_standard_cfr), ind_ovs_salt);
        of_table_name_t name;
        snprintf(name, sizeof(name), "table %d", i);
        indigo_core_table_register(i, name, &table_ops, flowtable);
        stats_alloc(&flowtable->matched_stats_handle);
        stats_alloc(&flowtable->missed_stats_handle);
        flowtables[i] = flowtable;
    }

    if (openflow_version == OF_VERSION_1_3) {
        pipeline_standard_group_register();
    }

    ind_ovs_pktin_socket_register(&pktin_soc, NULL, PKTIN_INTERVAL,
                                  PKTIN_BURST_SIZE);
}

static void
pipeline_standard_finish(void)
{
    int i;
    for (i = 0; i < NUM_TABLES; i++) {
        indigo_core_table_unregister(i);
        tcam_destroy(flowtables[i]->tcam);
        stats_free(&flowtables[i]->matched_stats_handle);
        stats_free(&flowtables[i]->missed_stats_handle);
        aim_free(flowtables[i]);
    }

    if (openflow_version == OF_VERSION_1_3) {
        pipeline_standard_group_unregister();
    }

    ind_ovs_pktin_socket_unregister(&pktin_soc);
}

indigo_error_t
pipeline_standard_process(struct ind_ovs_parsed_key *key,
                          struct ind_ovs_parsed_key *mask,
                          struct xbuf *stats,
                          struct action_context *actx)
{
    struct pipeline_standard_cfr cfr;
    pipeline_standard_key_to_cfr(key, &cfr);

    AIM_LOG_VERBOSE("CFR:");
    pipeline_standard_dump_cfr(&cfr);

    struct pipeline_standard_cfr cfr_mask;
    memset(&cfr_mask, 0, sizeof(cfr_mask));

    uint32_t hash = murmur_hash(&key->ethernet, sizeof(key->ethernet), 0);
    memset(&mask->ethernet, 0xff, sizeof(mask->ethernet));

    uint8_t table_id = 0;
    if (flowtables[table_id] == NULL) {
        AIM_LOG_VERBOSE("table 0 missing, dropping packet");
        return INDIGO_ERROR_NONE;
    }

    while (table_id != (uint8_t)-1) {
        struct flowtable *flowtable = flowtables[table_id];
        AIM_ASSERT(flowtable != NULL);

        struct tcam_entry *tcam_entry = tcam_match_and_mask(flowtable->tcam, &cfr, &cfr_mask);
        if (tcam_entry == NULL) {
            if (openflow_version < OF_VERSION_1_3) {
                uint64_t userdata = IVS_PKTIN_USERDATA(OF_PACKET_IN_REASON_NO_MATCH, 0);
                uint32_t netlink_port = ind_ovs_pktin_socket_lookup_netlink(&pktin_soc);
                action_userspace(actx, &userdata, sizeof(uint64_t), netlink_port);
            }
            pipeline_add_stats(stats, &flowtable->missed_stats_handle);
            break;
        }

        struct flowtable_entry *entry = container_of(tcam_entry, tcam_entry, struct flowtable_entry);

        if (entry->table_miss) {
            pipeline_add_stats(stats, &flowtable->missed_stats_handle);
        } else {
            pipeline_add_stats(stats, &flowtable->matched_stats_handle);
        }

        pipeline_add_stats(stats, &entry->stats_handle);

        pipeline_standard_translate_actions(actx, &entry->value.apply_actions,
                                            hash, stats);

        table_id = entry->value.next_table_id;

        if (table_id != (uint8_t)-1) {
            pipeline_standard_update_cfr(&cfr, &entry->value.apply_actions);
        }
    }

    translate_cfr_mask(mask, &cfr, &cfr_mask);

    return INDIGO_ERROR_NONE;
}

/* For each field in the CFR, copy the mask to the appropriate field in the OVS key */
static void
translate_cfr_mask(struct ind_ovs_parsed_key *mask,
                   const struct pipeline_standard_cfr *cfr,
                   const struct pipeline_standard_cfr *cfr_mask)
{
#define MASK(key_field, cfr_field) \
    do { \
        assert(sizeof(mask->key_field) == sizeof(cfr_mask->cfr_field)); \
        memor(&mask->key_field, &cfr_mask->cfr_field, sizeof(mask->key_field)); \
    } while(0)

    /* Some fields aren't allowed to have a partial mask by the kernel */
#define MASK_EXACT(key_field, cfr_field) \
    do { \
        if (cfr_mask->cfr_field) { \
            mask->key_field = -1; \
        } \
    } while(0)

    MASK_EXACT(in_port, in_port);
    MASK(ethernet.eth_dst, dl_dst);
    MASK(ethernet.eth_src, dl_src);
    MASK_EXACT(ethertype, dl_type);
    MASK(vlan, dl_vlan);

    if (cfr->dl_type == htons(ETH_P_IP)) {
        MASK(ipv4.ipv4_tos, nw_tos);
        MASK_EXACT(ipv4.ipv4_proto, nw_proto);
        MASK(ipv4.ipv4_src, nw_src);
        MASK(ipv4.ipv4_dst, nw_dst);
    } else if (cfr->dl_type == htons(ETH_P_IPV6)) {
        MASK(ipv6.ipv6_tclass, nw_tos);
        MASK_EXACT(ipv6.ipv6_proto, nw_proto);
        MASK(ipv6.ipv6_src, ipv6_src);
        MASK(ipv6.ipv6_dst, ipv6_dst);
    } else if (cfr->dl_type == htons(ETH_P_ARP)) {
        MASK_EXACT(arp.arp_op, nw_proto);
        MASK(arp.arp_sip, nw_src);
        MASK(arp.arp_tip, nw_dst);
    }

    if (cfr->nw_proto == IPPROTO_TCP) {
        MASK(tcp.tcp_src, tp_src);
        MASK(tcp.tcp_dst, tp_dst);
    } else if (cfr->nw_proto == IPPROTO_UDP) {
        MASK(udp.udp_src, tp_src);
        MASK(udp.udp_dst, tp_dst);
    } else if (cfr->nw_proto == IPPROTO_ICMP) {
        MASK_EXACT(icmp.icmp_type, tp_src);
        MASK_EXACT(icmp.icmp_code, tp_dst);
    } else if (cfr->nw_proto == IPPROTO_ICMPV6) {
        MASK_EXACT(icmpv6.icmpv6_type, tp_src);
        MASK_EXACT(icmpv6.icmpv6_code, tp_dst);
    }

#undef MASK
#undef MASK_EXACT
}

static void
memor(void *_dst, const void *_src, int len)
{
    char *dst = _dst;
    const char *src = _src;

    int i;
    for (i = 0; i < len; i++) {
        dst[i] |= src[i];
    }
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
pipeline_standard_update_cfr(struct pipeline_standard_cfr *cfr, struct xbuf *actions)
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
        if ((err = pipeline_standard_translate_openflow_actions(
                &openflow_actions, &value->apply_actions, table_miss)) < 0) {
            goto error;
        }
    } else {
        int rv;
        of_list_instruction_t insts;
        of_object_t inst;
        of_flow_modify_instructions_bind(flow_mod, &insts);

        uint8_t table_id;
        of_flow_modify_table_id_get(flow_mod, &table_id);

        OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
            switch (inst.object_id) {
            case OF_INSTRUCTION_APPLY_ACTIONS:
                of_instruction_apply_actions_actions_bind(&inst,
                                                          &openflow_actions);
                if ((err = pipeline_standard_translate_openflow_actions(
                        &openflow_actions, &value->apply_actions, table_miss)) < 0) {
                    goto error;
                }
                break;
            case OF_INSTRUCTION_WRITE_ACTIONS:
                of_instruction_write_actions_actions_bind(&inst,
                                                          &openflow_actions);
                if ((err = pipeline_standard_translate_openflow_actions(
                        &openflow_actions, &value->write_actions, table_miss)) < 0) {
                    goto error;
                }
                break;
            case OF_INSTRUCTION_CLEAR_ACTIONS:
                value->clear_actions = 1;
                break;
            case OF_INSTRUCTION_GOTO_TABLE:
                of_instruction_goto_table_table_id_get(&inst, &value->next_table_id);
                if (value->next_table_id <= table_id ||
                        value->next_table_id >= NUM_TABLES) {
                    AIM_LOG_WARN("invalid goto next_table_id %u", value->next_table_id);
                    err = INDIGO_ERROR_RANGE;
                    goto error;
                }
                break;
            case OF_INSTRUCTION_METER:
                of_instruction_meter_meter_id_get(&inst, &value->meter_id);
                break;
            default:
                err = INDIGO_ERROR_COMPAT;
                goto error;
            }
        }
    }

    xbuf_compact(&value->apply_actions);
    xbuf_compact(&value->write_actions);

    return INDIGO_ERROR_NONE;

error:
    pipeline_standard_cleanup_actions(&value->apply_actions);
    pipeline_standard_cleanup_actions(&value->write_actions);
    return err;
}

static bool
is_table_miss(int version, const struct pipeline_standard_cfr *mask, uint16_t priority)
{
    static struct pipeline_standard_cfr table_miss_mask; /* all zeroes */
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
    struct pipeline_standard_cfr key;
    struct pipeline_standard_cfr mask;
    uint16_t priority;

    if (of_flow_add_match_get(obj, &match) < 0) {
        aim_free(entry);
        return INDIGO_ERROR_UNKNOWN;
    }

    of_flow_add_priority_get(obj, &priority);

    pipeline_standard_match_to_cfr(&match, &key, &mask);

    entry->table_miss = is_table_miss(openflow_version, &mask, priority);

    rv = parse_value(obj, &entry->value, flowtable->table_id, entry->table_miss);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Creating flow:");
    AIM_LOG_VERBOSE("Key:");
    pipeline_standard_dump_cfr(&key);
    AIM_LOG_VERBOSE("Mask:");
    pipeline_standard_dump_cfr(&mask);

    tcam_insert(flowtable->tcam, &entry->tcam_entry, &key, &mask, priority);

    stats_alloc(&entry->stats_handle);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
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

    pipeline_standard_cleanup_actions(&entry->value.apply_actions);
    pipeline_standard_cleanup_actions(&entry->value.write_actions);
    entry->value = value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct flowtable *flowtable = table_priv;
    struct flowtable_entry *entry = entry_priv;

    tcam_remove(flowtable->tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);

    struct stats stats;
    stats_get(&entry->stats_handle, &stats);
    flow_stats->packets = stats.packets;
    flow_stats->bytes = stats.bytes;

    pipeline_standard_cleanup_actions(&entry->value.apply_actions);
    pipeline_standard_cleanup_actions(&entry->value.write_actions);
    stats_free(&entry->stats_handle);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct flowtable_entry *entry = entry_priv;
    struct stats stats;
    stats_get(&entry->stats_handle, &stats);
    flow_stats->packets = stats.packets;
    flow_stats->bytes = stats.bytes;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
flowtable_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit)
{
    struct flowtable_entry *entry = entry_priv;

    struct stats stats;
    stats_get(&entry->stats_handle, &stats);

    if (stats.packets != entry->last_hit_check_packets) {
        entry->last_hit_check_packets = stats.packets;
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
    struct stats matched_stats, missed_stats;
    stats_get(&flowtable->matched_stats_handle, &matched_stats);
    stats_get(&flowtable->missed_stats_handle, &missed_stats);
    table_stats->lookup_count = matched_stats.packets + missed_stats.packets;
    table_stats->matched_count = matched_stats.packets;
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
