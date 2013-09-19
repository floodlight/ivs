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

#include "ovs_driver_int.h"
#include "actions.h"
#include <unistd.h>
#include <indigo/memory.h>
#include <indigo/forwarding.h>
#include <indigo/of_state_manager.h>
#include "OFStateManager/ofstatemanager.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>

struct ind_ovs_table ind_ovs_tables[IND_OVS_NUM_TABLES];

static struct list_head ind_ovs_flow_id_buckets[64];

static pthread_rwlock_t ind_ovs_fwd_rwlock;

static aim_ratelimiter_t ind_ovs_pktin_limiter;

/**
 * Stats for packet in
 */
uint64_t ind_fwd_packet_in_packets;
uint64_t ind_fwd_packet_in_bytes;
uint64_t ind_fwd_packet_out_packets;
uint64_t ind_fwd_packet_out_bytes;

struct ind_ovs_pktin_suppression_cfg ind_ovs_pktin_suppression_cfg;

/** \brief Get forwarding features */

indigo_error_t
indigo_fwd_forwarding_features_get(of_features_reply_t *features)
{
    uint32_t capabilities = 0, actions = 0;

    of_features_reply_n_tables_set(features, 1);

    OF_CAPABILITIES_FLAG_FLOW_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_TABLE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_PORT_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_QUEUE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_ARP_MATCH_IP_SET(capabilities, features->version);
    of_features_reply_capabilities_set(features, capabilities);

    if (features->version < OF_VERSION_1_3) {
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_OUTPUT_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_VLAN_VID_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_VLAN_PCP_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_STRIP_VLAN_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_DL_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_DL_DST_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_DST_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_TOS_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_TP_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_TP_DST_BY_VERSION(features->version));
#if 0
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_ENQUEUE_BY_VERSION(features->version));
#endif
        of_features_reply_actions_set(features, actions);
    }

    return (INDIGO_ERROR_NONE);
}

static struct list_head *
ind_ovs_flow_id_bucket(indigo_cookie_t flow_id)
{
    uint32_t hash = ((unsigned) flow_id) &
                     (ARRAY_SIZE(ind_ovs_flow_id_buckets) - 1);
    return &ind_ovs_flow_id_buckets[hash];
}

static struct ind_ovs_flow *
ind_ovs_flow_lookup(indigo_cookie_t flow_id)
{
    struct list_head *bucket = ind_ovs_flow_id_bucket(flow_id);
    struct list_links *cur;
    LIST_FOREACH(bucket, cur) {
        struct ind_ovs_flow *flow = container_of(cur, flow_id_links, struct ind_ovs_flow);
        if (flow->flow_id == flow_id) {
            return flow;
        }
    }

    return NULL;
}

static indigo_error_t
init_effects(struct ind_ovs_flow_effects *effects,
             of_flow_modify_t *flow_mod, bool table_miss)
{
    of_list_action_t openflow_actions;
    indigo_error_t err;

    xbuf_init(&effects->apply_actions);
    xbuf_init(&effects->write_actions);

    effects->clear_actions = 0;
    effects->meter_id = -1;
    effects->next_table_id = -1;

    if (flow_mod->version == OF_VERSION_1_0) {
        of_flow_modify_actions_bind(flow_mod, &openflow_actions);
        if ((err = ind_ovs_translate_openflow_actions(&openflow_actions,
                                                      &effects->apply_actions,
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
                                                              &effects->apply_actions,
                                                              table_miss)) < 0) {
                    return err;
                }
                break;
            case OF_INSTRUCTION_WRITE_ACTIONS:
                of_instruction_write_actions_actions_bind(&inst.write_actions,
                                                          &openflow_actions);
                if ((err = ind_ovs_translate_openflow_actions(&openflow_actions,
                                                              &effects->write_actions,
                                                              table_miss)) < 0) {
                    return err;
                }
                break;
            case OF_INSTRUCTION_CLEAR_ACTIONS:
                effects->clear_actions = 1;
                break;
            case OF_INSTRUCTION_GOTO_TABLE:
                of_instruction_goto_table_table_id_get(&inst.goto_table, &effects->next_table_id);
                if (effects->next_table_id <= table_id ||
                        effects->next_table_id >= IND_OVS_NUM_TABLES) {
                    LOG_WARN("invalid goto next_table_id %u", effects->next_table_id);
                    return INDIGO_ERROR_RANGE;
                }
                break;
            case OF_INSTRUCTION_METER:
                of_instruction_meter_meter_id_get(&inst.meter, &effects->meter_id);
                break;
            default:
                return INDIGO_ERROR_COMPAT;
            }
        }
    }

    xbuf_compact(&effects->apply_actions);
    xbuf_compact(&effects->write_actions);

    return INDIGO_ERROR_NONE;
}

static void
cleanup_effects(struct ind_ovs_flow_effects *effects)
{
    xbuf_cleanup(&effects->apply_actions);
    xbuf_cleanup(&effects->write_actions);
}

static bool
is_table_miss(int version, const struct ind_ovs_cfr *mask, uint16_t priority)
{
    static struct ind_ovs_cfr table_miss_mask; /* all zeroes */
    return version >= OF_VERSION_1_3 &&
           priority == 0 &&
           memcmp(mask, &table_miss_mask, sizeof(table_miss_mask)) == 0;
}

/** \brief Create a flow */

void
indigo_fwd_flow_create(indigo_cookie_t flow_id,
                       of_flow_add_t   *flow_add,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct ind_ovs_flow *flow = NULL;

    LOG_TRACE("Flow create called");
    flow = malloc(sizeof(*flow));
    if (flow == NULL) {
        LOG_ERROR("INDIGO_MEM_ALLOC() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    flow->flow_id = flow_id;
    flow->stats.packets = 0;
    flow->stats.bytes = 0;

    of_match_t of_match;
    memset(&of_match, 0, sizeof(of_match));
    if (LOXI_FAILURE(of_flow_add_match_get(flow_add, &of_match))) {
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    struct ind_ovs_cfr fields, masks;
    ind_ovs_match_to_cfr(&of_match, &fields, &masks);

#ifndef NDEBUG
    LOG_VERBOSE("New flow fields:");
    ind_ovs_dump_cfr(&fields);
    LOG_VERBOSE("New flow masks:");
    ind_ovs_dump_cfr(&masks);
#endif

    uint16_t priority;
    of_flow_add_priority_get(flow_add, &priority);

    bool table_miss = is_table_miss(flow_add->version, &masks, priority);

    flowtable_entry_init(&flow->fte,
                         (struct flowtable_key *)&fields,
                         (struct flowtable_key *)&masks,
                         priority);

    if ((result = init_effects(&flow->effects, flow_add, table_miss)) < 0) {
        goto done;
    }

    /* N.B. No check made for duplicate flow_ids */
    struct list_head *flow_id_bucket = ind_ovs_flow_id_bucket(flow->flow_id);
    list_push(flow_id_bucket, &flow->flow_id_links);

    if (flow_add->version > OF_VERSION_1_0) {
        of_flow_add_table_id_get(flow_add, &flow->table_id);
        if (flow->table_id >= IND_OVS_NUM_TABLES) {
            LOG_WARN("Failed to add flow: invalid table_id %u", flow->table_id);
            result = INDIGO_ERROR_RANGE;
            goto done;
        }
    } else {
        flow->table_id = 0;
    }

    struct ind_ovs_table *table = &ind_ovs_tables[flow->table_id];

    ind_ovs_fwd_write_lock();
    flowtable_insert(table->ft, &flow->fte);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();

    ++table->num_flows;

 done:
    if (INDIGO_FAILURE(result)) {
        cleanup_effects(&flow->effects);
        free(flow);
    }

    indigo_core_flow_create_callback(
        result, flow_id,
        result == INDIGO_ERROR_NONE ? flow->table_id : 0,
        callback_cookie);
}


/** \brief Modify a flow */

void
indigo_fwd_flow_modify(indigo_cookie_t flow_id,
                       of_flow_modify_t *flow_modify,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t       result = INDIGO_ERROR_NONE;
    struct ind_ovs_flow *flow;

    if ((flow = ind_ovs_flow_lookup(flow_id)) == 0) {
       LOG_ERROR("Flow not found");
       result = INDIGO_ERROR_NOT_FOUND;
       goto done;
    }

    LOG_TRACE("Flow modify called\n");

    bool table_miss = is_table_miss(flow_modify->version,
                                    (struct ind_ovs_cfr *)&flow->fte.mask,
                                    flow->fte.priority);

    struct ind_ovs_flow_effects effects, old_effects;
    if ((result = init_effects(&effects, flow_modify, table_miss)) < 0) {
        cleanup_effects(&effects);
        goto done;
    }

    old_effects = flow->effects;

    ind_ovs_fwd_write_lock();
    flow->effects = effects;
    ind_ovs_fwd_write_unlock();

    cleanup_effects(&old_effects);

    ind_ovs_kflow_invalidate_all();

    /** \todo Clear flow stats? */

 done:
    indigo_core_flow_modify_callback(result, NULL, callback_cookie);
}


/** \brief Delete a flow */

void
indigo_fwd_flow_delete(indigo_cookie_t flow_id,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct ind_ovs_flow *flow;
    indigo_fi_flow_stats_t flow_stats;

    if ((flow = ind_ovs_flow_lookup(flow_id)) == 0) {
       LOG_INFO("Request to delete non-existent flow");
       result = INDIGO_ERROR_NOT_FOUND;
       goto done;
    }

    struct ind_ovs_table *table = &ind_ovs_tables[flow->table_id];

    ind_ovs_fwd_write_lock();
    flowtable_remove(table->ft, &flow->fte);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();

    flow_stats.flow_id = flow_id;
    flow_stats.packets = flow->stats.packets;
    flow_stats.bytes = flow->stats.bytes;
    flow_stats.duration_ns = 0;

    cleanup_effects(&flow->effects);

    list_remove(&flow->flow_id_links);

    INDIGO_MEM_FREE(flow);

    --table->num_flows;

done:
    indigo_core_flow_delete_callback(result, &flow_stats, callback_cookie);

}


/** \brief Get flow statistics */

void
indigo_fwd_flow_stats_get(indigo_cookie_t flow_id,
                          indigo_cookie_t callback_cookie)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct ind_ovs_flow *flow;
    indigo_fi_flow_stats_t flow_stats;

    if ((flow = ind_ovs_flow_lookup(flow_id)) == 0) {
       LOG_ERROR("Flow not found");
       result = INDIGO_ERROR_NOT_FOUND;
       goto done;
    }

    flow_stats.flow_id = flow_id;
    flow_stats.duration_ns = 0;
    flow_stats.packets = flow->stats.packets;
    flow_stats.bytes = flow->stats.bytes;

  done:
    indigo_core_flow_stats_get_callback(result, &flow_stats,
                                        callback_cookie);
}


/** \brief Get table statistics */

void
indigo_fwd_table_stats_get(of_table_stats_request_t *table_stats_request,
                           indigo_cookie_t callback_cookie)
{
    of_version_t version = table_stats_request->version;

    of_table_stats_reply_t *table_stats_reply = of_table_stats_reply_new(version);
    if (table_stats_reply == NULL) {
        indigo_core_table_stats_get_callback(INDIGO_ERROR_RESOURCE,
                                             NULL, callback_cookie);
        return;
    }

    uint32_t xid;
    of_table_stats_request_xid_get(table_stats_request, &xid);
    of_table_stats_reply_xid_set(table_stats_reply, xid);

    of_list_table_stats_entry_t list[1];
    of_table_stats_reply_entries_bind(table_stats_reply, list);

    int i;
    for (i = 0; i < IND_OVS_NUM_TABLES; i++) {
        struct ind_ovs_table *table = &ind_ovs_tables[i];

        of_table_stats_entry_t entry[1];
        of_table_stats_entry_init(entry, version, -1, 1);
        (void) of_list_table_stats_entry_append_bind(list, entry);

        of_table_stats_entry_table_id_set(entry, i);
        if (version < OF_VERSION_1_3) {
            of_table_stats_entry_name_set(entry, table->name);
            of_table_stats_entry_max_entries_set(entry, table->max_flows);
        }
        if (version < OF_VERSION_1_2) {
            of_table_stats_entry_wildcards_set(entry, 0x3fffff); /* All wildcards */
        }
        of_table_stats_entry_active_count_set(entry, table->num_flows);
        of_table_stats_entry_lookup_count_set(entry,
            table->matched_stats.packets + table->missed_stats.packets);
        of_table_stats_entry_matched_count_set(entry, table->matched_stats.packets);
    }

    indigo_core_table_stats_get_callback(INDIGO_ERROR_NONE,
                                         table_stats_reply,
                                         callback_cookie);
}

indigo_error_t
ind_fwd_pkt_in(of_port_no_t in_port,
               uint8_t *data, unsigned int len, unsigned reason,
               of_match_t *match)
{
    LOG_TRACE("Sending packet-in");

    struct ind_ovs_port *port = ind_ovs_port_lookup(in_port);
    if (port != NULL && OF_PORT_CONFIG_FLAG_NO_PACKET_IN_TEST(
                            port->config, ind_ovs_version)) {
        LOG_TRACE("Packet-in not enabled from this port");
        return INDIGO_ERROR_NONE;
    }

    if (!ind_ovs_benchmark_mode &&
        aim_ratelimiter_limit(&ind_ovs_pktin_limiter, monotonic_us()) != 0) {
        return INDIGO_ERROR_NONE;
    }

    if (ind_ovs_pktin_suppression_cfg.enabled && reason == OF_PACKET_IN_REASON_NO_MATCH) {
        LOG_TRACE("installing pktin suppression flow");
        of_flow_add_t *flow_mod = of_flow_add_new(ind_ovs_version);
        of_flow_add_hard_timeout_set(flow_mod, ind_ovs_pktin_suppression_cfg.hard_timeout);
        of_flow_add_idle_timeout_set(flow_mod, ind_ovs_pktin_suppression_cfg.idle_timeout);
        of_flow_add_cookie_set(flow_mod, ind_ovs_pktin_suppression_cfg.cookie);
        of_flow_add_priority_set(flow_mod, ind_ovs_pktin_suppression_cfg.priority);
        of_flow_add_buffer_id_set(flow_mod, -1);
        if (of_flow_add_match_set(flow_mod, match)) {
            abort();
        }
        indigo_core_receive_controller_message(INDIGO_CXN_ID_UNSPECIFIED, flow_mod);
    }

    of_octets_t of_octets = { .data = data, .bytes = len };

    of_packet_in_t *of_packet_in;
    if ((of_packet_in = of_packet_in_new(ind_ovs_version)) == NULL) {
        return INDIGO_ERROR_RESOURCE;
    }

    of_packet_in_total_len_set(of_packet_in, len);
    of_packet_in_reason_set(of_packet_in, reason);
    of_packet_in_buffer_id_set(of_packet_in, OF_BUFFER_ID_NO_BUFFER);

    if (ind_ovs_version < OF_VERSION_1_2) {
        of_packet_in_in_port_set(of_packet_in, in_port);
    } else {
        if (LOXI_FAILURE(of_packet_in_match_set(of_packet_in, match))) {
            LOG_ERROR("Failed to write match to packet-in message");
            of_packet_in_delete(of_packet_in);
            return INDIGO_ERROR_UNKNOWN;
        }
    }

    if (ind_ovs_version >= OF_VERSION_1_3) {
        of_packet_in_cookie_set(of_packet_in, 0xffffffffffffffff);
    }

    if (LOXI_FAILURE(of_packet_in_data_set(of_packet_in, &of_octets))) {
        LOG_ERROR("Failed to write packet data to packet-in message");
        of_packet_in_delete(of_packet_in);
        return INDIGO_ERROR_UNKNOWN;
    }

    ++ind_fwd_packet_in_packets;
    ind_fwd_packet_in_bytes += len;

    return indigo_core_packet_in(of_packet_in);
}

void
ind_ovs_fwd_result_init(struct ind_ovs_fwd_result *result)
{
    xbuf_init(&result->actions);
    result->num_stats_ptrs = 0;
}

/* Reinitialize without reallocating memory */
void
ind_ovs_fwd_result_reset(struct ind_ovs_fwd_result *result)
{
    xbuf_reset(&result->actions);
    result->num_stats_ptrs = 0;
}

void
ind_ovs_fwd_result_cleanup(struct ind_ovs_fwd_result *result)
{
    xbuf_cleanup(&result->actions);
}

/** \brief Handle packet out request from Core */

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *of_packet_out)
{
    of_port_no_t     of_port_num;
    of_list_action_t of_list_action[1];
    of_octets_t      of_octets[1];

    of_packet_out_in_port_get(of_packet_out, &of_port_num);
    of_packet_out_data_get(of_packet_out, of_octets);
    of_packet_out_actions_bind(of_packet_out, of_list_action);

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
    } else {
        /* Can't have an empty key. */
        nla_put_u32(msg, OVS_KEY_ATTR_PRIORITY, 0);
    }
    nla_nest_end(msg, key);

    nla_put(msg, OVS_PACKET_ATTR_PACKET, of_octets->bytes, of_octets->data);

    /* This action sends the packet back to us with the full key */
    struct nlattr *actions = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);
    struct nlattr *action_attr = nla_nest_start(msg, OVS_ACTION_ATTR_USERSPACE);
    nla_put_u32(msg, OVS_USERSPACE_ATTR_PID, nl_socket_get_local_port(ind_ovs_socket));
    nla_nest_end(msg, action_attr);
    nla_nest_end(msg, actions);

    /* Send the first message */
    int err = nl_send_auto(ind_ovs_socket, msg);
    if (err < 0) {
        LOG_ERROR("nl_send failed: %s", nl_geterror(err));
        ind_ovs_nlmsg_freelist_free(msg);
        return INDIGO_ERROR_UNKNOWN;
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
    struct xbuf xbuf;
    xbuf_init(&xbuf);
    ind_ovs_translate_openflow_actions(of_list_action, &xbuf, false);
    struct nlattr *actions_attr = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);
    ind_ovs_translate_actions(&pkey, &xbuf, msg);
    ind_ovs_nla_nest_end(msg, actions_attr);
    xbuf_cleanup(&xbuf);

    /* Send the second message */
    if (ind_ovs_transact(msg) < 0) {
        LOG_ERROR("OVS_PACKET_CMD_EXECUTE failed");
        return INDIGO_ERROR_UNKNOWN;
    }

    ++ind_fwd_packet_out_packets;
    ind_fwd_packet_out_packets += of_octets->bytes;

    return INDIGO_ERROR_NONE;
}

void
ind_ovs_fwd_read_lock(void)
{
    pthread_rwlock_rdlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_read_unlock(void)
{
    pthread_rwlock_unlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_write_lock(void)
{
    pthread_rwlock_wrlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_write_unlock(void)
{
    pthread_rwlock_unlock(&ind_ovs_fwd_rwlock);
}

struct ind_ovs_flow_effects *
ind_ovs_fwd_pipeline_lookup(int table_id, struct ind_ovs_cfr *cfr,
                            struct ind_ovs_fwd_result *result, bool update_stats)
{

    struct ind_ovs_table *table = &ind_ovs_tables[table_id];

#ifndef NDEBUG
    LOG_VERBOSE("Looking up flow in %s", table->name);
    ind_ovs_dump_cfr(cfr);
#endif

    struct flowtable_entry *fte = flowtable_match(table->ft,
                                                  (struct flowtable_key *)cfr);
    if (fte == NULL) {
        if (update_stats) {
            result->stats_ptrs[result->num_stats_ptrs++] = &table->missed_stats;
        }
        return NULL;
    }

    struct ind_ovs_flow *flow = container_of(fte, fte, struct ind_ovs_flow);

    if (update_stats) {
        result->stats_ptrs[result->num_stats_ptrs++] = &table->matched_stats;
        result->stats_ptrs[result->num_stats_ptrs++] = &flow->stats;
    }

    return &flow->effects;
}


/** \brief Intialize */

indigo_error_t
ind_ovs_fwd_init(void)
{
    int i;

    pthread_rwlock_init(&ind_ovs_fwd_rwlock, NULL);

    for (i = 0; i < ARRAY_SIZE(ind_ovs_flow_id_buckets); i++) {
        struct list_head *bucket = &ind_ovs_flow_id_buckets[i];
        list_init(bucket);
    }

    for (i = 0; i < IND_OVS_NUM_TABLES; i++) {
        struct ind_ovs_table *table = &ind_ovs_tables[i];
        memset(table, 0, sizeof(*table));
        snprintf(table->name, sizeof(table->name), "Table %d", i);
        table->max_flows = 16384; /* XXX */
        table->ft = flowtable_create();
        if (table->ft == NULL) {
            abort();
        }
    }

    aim_ratelimiter_init(&ind_ovs_pktin_limiter, PKTIN_INTERVAL,
                         PKTIN_BURST_SIZE, NULL);

    ind_ovs_pktin_suppression_cfg.enabled = false;

    return (INDIGO_ERROR_NONE);
}


/** \brief Tear down */

void
ind_ovs_fwd_finish(void)
{
    int i;

    /* Quiesce all ports */
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        if (ind_ovs_ports[i] != NULL) {
            ind_ovs_upcall_quiesce(ind_ovs_ports[i]);
        }
    }

    /* Hold this forever. */
    ind_ovs_fwd_write_lock();

    for (i = 0; i < IND_OVS_NUM_TABLES; i++) {
        struct ind_ovs_table *table = &ind_ovs_tables[i];
        flowtable_destroy(table->ft);
    }

    /* Free all the flows */
    for (i = 0; i < ARRAY_SIZE(ind_ovs_flow_id_buckets); i++) {
        struct list_head *bucket = &ind_ovs_flow_id_buckets[i];
        struct list_links *cur, *next;
        LIST_FOREACH_SAFE(bucket, cur, next) {
            struct ind_ovs_flow *flow = container_of(cur, flow_id_links, struct ind_ovs_flow);
            cleanup_effects(&flow->effects);
            free(flow);
        }
    }
}
