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

struct flowtable *ind_ovs_ft;

static struct list_head ind_ovs_flow_id_buckets[64];

static unsigned active_count;   /**< Number of flows defined */
static uint64_t lookup_count;   /**< Number of packets looked up */
static uint64_t matched_count;  /**< Number of packets matched */

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

    OF_CAPABILITIES_FLAG_FLOW_STATS_SET(capabilities, ind_ovs_version);
    OF_CAPABILITIES_FLAG_TABLE_STATS_SET(capabilities, ind_ovs_version);
    OF_CAPABILITIES_FLAG_PORT_STATS_SET(capabilities, ind_ovs_version);
    OF_CAPABILITIES_FLAG_QUEUE_STATS_SET(capabilities, ind_ovs_version);
    OF_CAPABILITIES_FLAG_ARP_MATCH_IP_SET(capabilities, ind_ovs_version);

    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_OUTPUT_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_VLAN_VID_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_VLAN_PCP_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_STRIP_VLAN_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_DL_SRC_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_DL_DST_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_NW_SRC_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_NW_DST_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_NW_TOS_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_TP_SRC_BY_VERSION(ind_ovs_version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_TP_DST_BY_VERSION(ind_ovs_version));
#if 0
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_ENQUEUE_BY_VERSION(ind_ovs_version));
#endif

    of_features_reply_n_tables_set(features, 1);
    of_features_reply_capabilities_set(features, capabilities);
    of_features_reply_actions_set(features, actions);

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

/* Invalidate all the kernel flows for the given user flow. */
static void
ind_ovs_flow_invalidate_kflows(struct ind_ovs_flow *flow)
{
    struct list_links *cur, *next;
    LIST_FOREACH_SAFE(&flow->kflows, cur, next) {
        struct ind_ovs_kflow *kflow = container_of(cur, flow_links, struct ind_ovs_kflow);
        ind_ovs_kflow_invalidate(kflow);
    }
}

/*
 * Returns true if the action list contains an output to the "all" or
 * "flood" virtual ports.
 */
static bool
actions_contain_flood(of_list_action_t *actions)
{
    of_action_t action[1];
    int rv;
    OF_LIST_ACTION_ITER(actions, action, rv) {
        if (action->header.object_id == OF_ACTION_OUTPUT) {
            of_port_no_t of_port_num;
            of_action_output_port_get(&action->output, &of_port_num);
            if (of_port_num == OF_PORT_DEST_FLOOD ||
                of_port_num == OF_PORT_DEST_ALL) {
                return true;
            }
        }
    }

    return false;
}

/** \brief Create a flow */

void
indigo_fwd_flow_create(indigo_cookie_t flow_id,
                       of_flow_add_t   *flow_add,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct ind_ovs_flow *flow = NULL;
    of_list_action_t *of_list_action = NULL;

    LOG_TRACE("Flow create called");
    flow = malloc(sizeof(*flow));
    if (flow == NULL) {
        LOG_ERROR("INDIGO_MEM_ALLOC() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    flow->flow_id = flow_id;
    list_init(&flow->kflows);
    flow->packets = 0;
    flow->bytes = 0;

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

    flowtable_entry_init(&flow->fte,
                         (struct flowtable_key *)&fields,
                         (struct flowtable_key *)&masks,
                         priority);

    if (flow_add->version == OF_VERSION_1_0) {
        of_list_action = of_flow_add_actions_get(flow_add);
    } else {
        of_list_instruction_t insts;
        of_instruction_t inst;
        of_flow_add_instructions_bind(flow_add, &insts);

        if (of_list_instruction_first(&insts, &inst) == 0) {
            if (inst.header.object_id == OF_INSTRUCTION_APPLY_ACTIONS) {
                of_list_action = of_instruction_apply_actions_actions_get(&inst.apply_actions);
            }
        }
    }

    if (of_list_action == NULL) {
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    flow->of_list_action = of_list_action;
    flow->flood = actions_contain_flood(of_list_action);

    /* N.B. No check made for duplicate flow_ids */
    struct list_head *flow_id_bucket = ind_ovs_flow_id_bucket(flow->flow_id);
    list_push(flow_id_bucket, &flow->flow_id_links);

    ind_ovs_fwd_write_lock();
    flowtable_insert(ind_ovs_ft, &flow->fte);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_overlap(&fields, &masks, flow->fte.priority);

    ++active_count;

 done:
    if (INDIGO_FAILURE(result)) {
        if (of_list_action) of_list_action_delete(of_list_action);
        free(flow);
    }

    indigo_core_flow_create_callback(result, flow_id, 0, callback_cookie);
}


/** \brief Modify a flow */

void
indigo_fwd_flow_modify(indigo_cookie_t flow_id,
                       of_flow_modify_t *flow_modify,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t       result = INDIGO_ERROR_NONE;
    struct ind_ovs_flow *flow;
    of_list_action_t     *of_list_action = 0, *old_of_list_action;

    if ((flow = ind_ovs_flow_lookup(flow_id)) == 0) {
       LOG_ERROR("Flow not found");
       result = INDIGO_ERROR_NOT_FOUND;
       goto done;
    }

    /* @todo Fill in flow_modify if non-NULL */
    LOG_TRACE("Flow modify called\n");

    of_list_action = of_flow_modify_strict_actions_get(flow_modify);
    if (of_list_action == NULL) {
        LOG_ERROR("of_flow_modify_actions_get() failed to get actions");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    old_of_list_action = flow->of_list_action;

    ind_ovs_fwd_write_lock();
    flow->of_list_action = of_list_action;
    ind_ovs_fwd_write_unlock();

    of_list_action_delete(old_of_list_action);  /* Free old action list */

    ind_ovs_flow_invalidate_kflows(flow);

    /** \todo Clear flow stats? */

 done:
    if (INDIGO_FAILURE(result)) {
        of_list_action_delete(of_list_action);
    }

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

    ind_ovs_fwd_write_lock();
    flowtable_remove(ind_ovs_ft, &flow->fte);
    ind_ovs_fwd_write_unlock();

    ind_ovs_flow_invalidate_kflows(flow);

    flow_stats.flow_id = flow_id;
    flow_stats.packets = flow->packets;
    flow_stats.bytes = flow->bytes;
    flow_stats.duration_ns = 0;

    of_list_action_delete(flow->of_list_action);

    list_remove(&flow->flow_id_links);

    INDIGO_MEM_FREE(flow);

    --active_count;

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

    flow_stats.packets = flow->packets;
    flow_stats.bytes = flow->bytes;

    LOG_VERBOSE("Getting stats for %d kernel flows", list_length(&flow->kflows));

    struct list_links *cur;
    LIST_FOREACH(&flow->kflows, cur) {
        struct ind_ovs_kflow *kflow = container_of(cur, flow_links, struct ind_ovs_kflow);
        ind_ovs_kflow_sync_stats(kflow);
        flow_stats.packets += kflow->stats.n_packets;
        flow_stats.bytes += kflow->stats.n_bytes;
    }

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

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_datapath_family, OVS_DP_CMD_GET);
    struct nlmsghdr *reply;
    if (ind_ovs_transact_reply(msg, &reply) < 0) {
        indigo_core_table_stats_get_callback(INDIGO_ERROR_UNKNOWN,
                                             NULL, callback_cookie);
        return;
    }

    struct nlattr *attrs[OVS_DP_ATTR_MAX+1];
    if (genlmsg_parse(reply, sizeof(struct ovs_header),
                      attrs, OVS_DP_ATTR_MAX,
                      NULL) < 0) {
        LOG_ERROR("failed to parse datapath message");
        abort();
    }

    assert(attrs[OVS_DP_ATTR_STATS]);
    struct ovs_dp_stats dp_stats = *(struct ovs_dp_stats *)nla_data(attrs[OVS_DP_ATTR_STATS]);
    free(reply);

    of_table_stats_reply_t *table_stats_reply = of_table_stats_reply_new(version);
    if (table_stats_reply == NULL) {
        indigo_core_table_stats_get_callback(INDIGO_ERROR_RESOURCE,
                                             NULL, callback_cookie);
        return;
    }

    of_list_table_stats_entry_t list[1];
    of_table_stats_reply_entries_bind(table_stats_reply, list);

    of_table_stats_entry_t entry[1];
    of_table_stats_entry_init(entry, version, -1, 1);
    (void) of_list_table_stats_entry_append_bind(list, entry);

    uint32_t xid;
    of_table_stats_request_xid_get(table_stats_request, &xid);
    of_table_stats_reply_xid_set(table_stats_reply, xid);
    of_table_stats_entry_table_id_set(entry, 0);
    of_table_stats_entry_name_set(entry, "Table 0");
    of_table_stats_entry_wildcards_set(entry, 0x3fffff); /* All wildcards */
    of_table_stats_entry_max_entries_set(entry, 16384);
    of_table_stats_entry_active_count_set(entry, active_count);
    of_table_stats_entry_lookup_count_set(entry, lookup_count + dp_stats.n_hit);
    of_table_stats_entry_matched_count_set(entry, matched_count + dp_stats.n_hit);

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
    of_packet_in_in_port_set(of_packet_in, in_port);
    of_packet_in_reason_set(of_packet_in, reason);
    of_packet_in_buffer_id_set(of_packet_in, OF_BUFFER_ID_NO_BUFFER);
    if (LOXI_FAILURE(of_packet_in_data_set(of_packet_in, &of_octets))) {
        LOG_ERROR("Failed to write packet data to packet-in message");
        of_packet_in_delete(of_packet_in);
        return INDIGO_ERROR_UNKNOWN;
    }

    ++ind_fwd_packet_in_packets;
    ind_fwd_packet_in_bytes += len;

    return indigo_core_packet_in(of_packet_in);
}

/*
 * Finds the flowtable entry matching the given fields.
 */
indigo_error_t
ind_ovs_lookup_flow(const struct ind_ovs_parsed_key *pkey,
                    struct ind_ovs_flow **flow)
{
    struct flowtable_entry *fte;
    struct ind_ovs_cfr cfr;
    ind_ovs_key_to_cfr(pkey, &cfr);

#ifndef NDEBUG
    LOG_VERBOSE("Looking up flow:");
    ind_ovs_dump_cfr(&cfr);
#endif

    ++lookup_count;

    fte = flowtable_match(ind_ovs_ft, (struct flowtable_key *)&cfr);
    if (fte == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *flow = container_of(fte, fte, struct ind_ovs_flow);
    ++matched_count;

    return INDIGO_ERROR_NONE;
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
    ind_ovs_translate_actions(&pkey, of_list_action, msg, OVS_PACKET_ATTR_ACTIONS);

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

    struct ind_ovs_cfr hash_mask;
    memset(&hash_mask, 0, sizeof(hash_mask));
    memset(&hash_mask.dl_dst, 0xff, sizeof(&hash_mask.dl_dst));
    memset(&hash_mask.dl_src, 0xff, sizeof(&hash_mask.dl_src));
    ind_ovs_ft = flowtable_create();
    if (!ind_ovs_ft) {
        return INDIGO_ERROR_RESOURCE;
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

    flowtable_destroy(ind_ovs_ft);

    /* Free all the flows */
    for (i = 0; i < ARRAY_SIZE(ind_ovs_flow_id_buckets); i++) {
        struct list_head *bucket = &ind_ovs_flow_id_buckets[i];
        struct list_links *cur, *next;
        LIST_FOREACH_SAFE(bucket, cur, next) {
            struct ind_ovs_flow *flow = container_of(cur, flow_id_links, struct ind_ovs_flow);
            of_list_action_delete(flow->of_list_action);
            free(flow);
        }
    }
}
