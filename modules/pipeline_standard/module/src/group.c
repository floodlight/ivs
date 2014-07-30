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
#include <ivs/ivs.h>
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include "action.h"
#include "group.h"

#define AIM_LOG_MODULE_NAME pipeline_standard
#include <AIM/aim_log.h>

static void cleanup_group_value(struct group_value *value);
static const indigo_core_group_table_ops_t group_table_ops;

void
pipeline_standard_group_register(void)
{
    indigo_core_group_table_register(0, "group", &group_table_ops, NULL);
}

void
pipeline_standard_group_unregister(void)
{
    indigo_core_group_table_unregister(0);
}

static indigo_error_t
parse_group_value(int group_type, of_list_bucket_t *of_buckets, struct group_value *value)
{
    indigo_error_t err;
    uint16_t num_buckets = 0;

    struct xbuf buckets_xbuf;
    xbuf_init(&buckets_xbuf);

    of_bucket_t of_bucket;
    int rv;
    OF_LIST_BUCKET_ITER(of_buckets, &of_bucket, rv) {
        struct group_bucket *bucket =
            xbuf_reserve(&buckets_xbuf, sizeof(*bucket));
        xbuf_init(&bucket->actions);
        stats_alloc(&bucket->stats_handle);
        num_buckets++;

        uint16_t weight;
        of_bucket_weight_get(&of_bucket, &weight);

        if (weight > 0 && group_type != OF_GROUP_TYPE_SELECT) {
            AIM_LOG_ERROR("Invalid group bucket weight");
            err = INDIGO_ERROR_COMPAT;
            goto error;
        } else if (weight == 0 && group_type == OF_GROUP_TYPE_SELECT) {
            AIM_LOG_ERROR("Invalid group bucket weight");
            err = INDIGO_ERROR_COMPAT;
            goto error;
        }

        if (group_type == OF_GROUP_TYPE_INDIRECT && num_buckets > 1) {
            AIM_LOG_ERROR("Too many buckets for an indirect group");
            err = INDIGO_ERROR_COMPAT;
            goto error;
        }

        of_list_action_t of_actions;
        of_bucket_actions_bind(&of_bucket, &of_actions);

        err = ind_ovs_translate_openflow_actions(
            &of_actions, &bucket->actions, false);
        if (err < 0) {
            goto error;
        }

        xbuf_compact(&bucket->actions);
    }

    xbuf_compact(&buckets_xbuf);

    value->buckets = xbuf_steal(&buckets_xbuf);
    value->num_buckets = num_buckets;
    return INDIGO_ERROR_NONE;

error:
    value->buckets = xbuf_steal(&buckets_xbuf);
    value->num_buckets = num_buckets;
    cleanup_group_value(value);
    return err;
}

static void
cleanup_group_value(struct group_value *value)
{
    int i;
    for (i = 0; i < value->num_buckets; i++) {
        struct group_bucket *bucket = &value->buckets[i];
        pipeline_standard_cleanup_actions(&bucket->actions);
        stats_free(&bucket->stats_handle);
    }
    aim_free(value->buckets);
}

static indigo_error_t
group_create(
    void *table_priv, indigo_cxn_id_t cxn_id,
    uint32_t group_id, uint8_t group_type, of_list_bucket_t *buckets,
    void **entry_priv)
{
    struct group_value value;

    indigo_error_t rv = parse_group_value(group_type, buckets, &value);
    if (rv < 0) {
        return rv;
    }

    struct group *group = aim_zmalloc(sizeof(*group));

    group->id = group_id;
    group->type = group_type;
    group->value = value;

    *entry_priv = group;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
group_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_list_bucket_t *buckets)
{
    struct group *group = entry_priv;
    struct group_value value;

    indigo_error_t rv = parse_group_value(group->type, buckets, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    cleanup_group_value(&group->value);
    group->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
group_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv)
{
    struct group *group = entry_priv;
    cleanup_group_value(&group->value);
    aim_free(group);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
group_stats_get(
    void *table_priv, void *entry_priv,
    of_group_stats_entry_t *stats)
{
    uint64_t total_packets = 0, total_bytes = 0;
    struct group *group = entry_priv;

    of_list_bucket_counter_t bucket_counters;
    of_group_stats_entry_bucket_stats_bind(stats, &bucket_counters);

    int i;
    for (i = 0; i < group->value.num_buckets; i++) {
        of_bucket_counter_t bucket_counter;
        of_bucket_counter_init(&bucket_counter, stats->version, -1, 1);
        (void) of_list_bucket_counter_append_bind(&bucket_counters, &bucket_counter);

        struct stats stats;
        stats_get(&group->value.buckets[i].stats_handle, &stats);

        of_bucket_counter_packet_count_set(&bucket_counter, stats.packets);
        of_bucket_counter_byte_count_set(&bucket_counter, stats.bytes);

        total_packets += stats.packets;
        total_bytes += stats.bytes;
    }

    of_group_stats_entry_packet_count_set(stats, total_packets);
    of_group_stats_entry_byte_count_set(stats, total_bytes);
    return INDIGO_ERROR_NONE;
}

static const indigo_core_group_table_ops_t group_table_ops = {
    .entry_create = group_create,
    .entry_modify = group_modify,
    .entry_delete = group_delete,
    .entry_stats_get = group_stats_get,
};
