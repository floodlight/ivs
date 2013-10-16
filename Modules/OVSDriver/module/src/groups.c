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
#include <indigo/forwarding.h>

#define TEMPLATE_NAME group_table
#define TEMPLATE_OBJ_TYPE struct ind_ovs_group
#define TEMPLATE_KEY_FIELD id
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t group_table;

static indigo_error_t
translate_buckets(of_list_bucket_t *of_buckets,
                  struct ind_ovs_group_bucket **buckets_ptr,
                  uint16_t *num_buckets_ptr)
{
    uint16_t num_buckets = 0;

    struct xbuf buckets_xbuf;
    xbuf_init(&buckets_xbuf);

    of_bucket_t of_bucket;
    int rv;
    OF_LIST_BUCKET_ITER(of_buckets, &of_bucket, rv) {
        struct ind_ovs_group_bucket *bucket =
            xbuf_reserve(&buckets_xbuf, sizeof(*bucket));
        xbuf_init(&bucket->actions);
        bucket->stats.packets = 0;
        bucket->stats.bytes = 0;
        num_buckets++;
    }

    xbuf_compact(&buckets_xbuf);

    *buckets_ptr = xbuf_steal(&buckets_xbuf);
    *num_buckets_ptr = num_buckets;
    return INDIGO_ERROR_NONE;
}

static void
free_buckets(struct ind_ovs_group_bucket *buckets, uint16_t num_buckets)
{
    int i;
    for (i = 0; i < num_buckets; i++) {
        xbuf_cleanup(&buckets[i].actions);
    }
    free(buckets);
}

indigo_error_t
indigo_fwd_group_add(uint32_t id, uint8_t group_type, of_list_bucket_t *of_buckets)
{
    indigo_error_t err;
    struct ind_ovs_group_bucket *buckets;
    uint16_t num_buckets;

    /* TODO validate */

    err = translate_buckets(of_buckets, &buckets, &num_buckets);
    if (err < 0) {
        return err;
    }

    struct ind_ovs_group *group = malloc(sizeof(*group));
    AIM_TRUE_OR_DIE(group != NULL);

    group->id = id;
    group->type = group_type;
    group->num_buckets = num_buckets;
    group->buckets = buckets;

    ind_ovs_fwd_write_lock();
    group_table_insert(&group_table, group);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();

    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_fwd_group_modify(uint32_t id, of_list_bucket_t *of_buckets)
{
    indigo_error_t err;
    struct ind_ovs_group_bucket *buckets, *old_buckets;
    uint16_t num_buckets, old_num_buckets;

    struct ind_ovs_group *group = group_table_first(&group_table, &id);
    AIM_TRUE_OR_DIE(group != NULL);

    /* TODO validate */

    err = translate_buckets(of_buckets, &buckets, &num_buckets);
    if (err < 0) {
        return err;
    }

    ind_ovs_fwd_write_lock();
    old_num_buckets = group->num_buckets;
    old_buckets = group->buckets;
    group->num_buckets = num_buckets;
    group->buckets = buckets;
    ind_ovs_fwd_write_unlock();

    free_buckets(old_buckets, old_num_buckets);

    ind_ovs_kflow_invalidate_all();

    return INDIGO_ERROR_NONE;
}

void
indigo_fwd_group_delete(uint32_t id)
{
    struct ind_ovs_group *group = group_table_first(&group_table, &id);
    AIM_TRUE_OR_DIE(group != NULL);

    ind_ovs_fwd_write_lock();
    bighash_remove(&group_table, &group->hash_entry);
    ind_ovs_fwd_write_unlock();

    free_buckets(group->buckets, group->num_buckets);
    free(group);

    ind_ovs_kflow_invalidate_all();
}

void
indigo_fwd_group_stats_get(uint32_t id, of_group_stats_entry_t *entry)
{
    uint64_t total_packets = 0, total_bytes = 0;

    struct ind_ovs_group *group = group_table_first(&group_table, &id);
    AIM_TRUE_OR_DIE(group != NULL);

    of_list_bucket_counter_t bucket_counters;
    of_group_stats_entry_bucket_stats_bind(entry, &bucket_counters);

    int i;
    for (i = 0; i < group->num_buckets; i++) {
        of_bucket_counter_t bucket_counter;
        of_bucket_counter_init(&bucket_counter, entry->version, -1, 1);
        (void) of_list_bucket_counter_append_bind(&bucket_counters, &bucket_counter);

        struct ind_ovs_flow_stats bucket_stats = group->buckets[i].stats;

        of_bucket_counter_packet_count_set(&bucket_counter, bucket_stats.packets);
        of_bucket_counter_byte_count_set(&bucket_counter, bucket_stats.bytes);

        total_packets += bucket_stats.packets;
        total_bytes += bucket_stats.bytes;
    }

    of_group_stats_entry_packet_count_set(entry, total_packets);
    of_group_stats_entry_byte_count_set(entry, total_bytes);
}

void
ind_ovs_group_module_init(void)
{
    bighash_table_init(&group_table, 64);
}
