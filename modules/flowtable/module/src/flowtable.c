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

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif
#include "flowtable/flowtable.h"
#include "murmur/murmur.h"
#include "flowtable_log.h"

#define FLOWTABLE_BUCKETS 32
#define FLOWTABLE_SPECIFIC_BUCKETS 16384

/*
 * An entry in a flowtable.
 *
 * flowtable_specific will be removed if the flow_cnt reaches zero.
 */
struct flowtable_specific {
    struct list_links links;
    struct flowtable_key flow_mask;
    struct list_head buckets[FLOWTABLE_SPECIFIC_BUCKETS];
    uint32_t flow_cnt;  /* Number of flow entries in specific flowtable*/
    uint32_t max_priority;  /* Priority of the flow that has highest priority */
};

/*
 * flowtable hash with flow entry mask as key
 */
struct flowtable {
    struct list_head buckets[FLOWTABLE_BUCKETS];
    struct flowtable_specific **fts_list;
    uint32_t fts_list_size;
    uint32_t fts_list_cnt;
};

struct list_head flowtable_specific_list;

static struct list_head *flowtable_bucket(struct flowtable *ft,
                                          const struct flowtable_key *mask);
static struct list_head *flowtable_specific_bucket(struct flowtable_specific *fts,
                                                   const struct flowtable_key *key);
static void flowtable_specific_insert(struct flowtable_specific *fts,
                                      struct flowtable_entry *new_fte);
static struct flowtable_entry *flowtable_specific_match(struct flowtable_specific *fts,
                                                        const struct flowtable_key *key,
                                                        const uint16_t cur_priority);
static bool match(const struct flowtable_key *flow_key,
                  const struct flowtable_key *flow_mask,
                  const struct flowtable_key *pkt_key);
static void flowtable_specific_list_add(struct flowtable *ft, struct flowtable_specific *fts);
static void flowtable_specific_list_del(struct flowtable *ft, struct flowtable_specific *fts);

/*
 * HACK need a random number to prevent hash collision attacks.
 */
extern uint32_t ind_ovs_salt;

/* Documented in flowtable.h */
struct flowtable *
flowtable_create()
{
    struct flowtable *ft = malloc(sizeof(*ft));
    if (ft == NULL) {
        AIM_LOG_ERROR("Failed to allocate flowtable");
        return NULL;
    }

    ft->fts_list_size = FLOWTABLE_BUCKETS;
    ft->fts_list_cnt  = 0;
    ft->fts_list = calloc(ft->fts_list_size, sizeof(ft->fts_list));

    if(ft->fts_list == NULL) {
        free(ft);
        AIM_LOG_ERROR("Failed to allocate specific flowtable list");
        return NULL;
    }

    int i;
    for (i = 0; i < FLOWTABLE_BUCKETS; i++) {
        list_init(&ft->buckets[i]);
    }

    return ft;
}

/* Documented in flowtable.h */
void
flowtable_destroy(struct flowtable *ft)
{
    struct list_links *cur;
    int i;

    for(i = 0; i < FLOWTABLE_BUCKETS; i++) {
        while((cur = list_pop(&ft->buckets[i])) != NULL) {
            struct flowtable_specific *cur_fts =
                container_of(cur, links, struct flowtable_specific);

            free(cur_fts);
        }
    }

    free(ft->fts_list);
    free(ft);
    return;
}

/* Documented in flowtable.h */
void
flowtable_entry_init(struct flowtable_entry *fte,
                     const struct flowtable_key *key,
                     const struct flowtable_key *mask,
                     uint16_t priority)
{
    fte->key = *key;
    fte->mask = *mask;
    fte->priority = priority;
}

/* Documented in flowtable.h */
void
flowtable_insert(struct flowtable *ft, struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct list_head *ft_bucket = flowtable_bucket(ft, &fte->mask);

    /* Check if flow table entry is present for the new flow entry mask */
    LIST_FOREACH(ft_bucket, cur) {
        struct flowtable_specific *cur_fts =
            container_of(cur, links, struct flowtable_specific);
        if (memcmp(&cur_fts->flow_mask, &fte->mask, sizeof(struct flowtable_key)) == 0) {
            /* If present, insert the new flow entry */
            flowtable_specific_insert(cur_fts, fte);
            cur_fts->flow_cnt++;

            if(fte->priority > cur_fts->max_priority)
                cur_fts->max_priority = fte->priority;
            return;
        }
    }

    /* If not present, then create a specific flowtable */
    struct flowtable_specific *new_fts = calloc(1, sizeof(*new_fts));
    if(new_fts == NULL) {
        AIM_LOG_ERROR("Failed to allocate specific flowtable");
        return;
    }

    int i;
    for (i = 0; i < FLOWTABLE_SPECIFIC_BUCKETS; i++) {
        list_init(&new_fts->buckets[i]);
    }

    new_fts->max_priority = fte->priority;
    new_fts->flow_mask = fte->mask;
    flowtable_specific_insert(new_fts, fte);
    new_fts->flow_cnt = 1;
    flowtable_specific_list_add(ft, new_fts);

    list_push(ft_bucket, &new_fts->links);
    return;
}

/* Documented in flowtable.h */
void
flowtable_remove(struct flowtable *ft, struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct flowtable_specific *cur_fts = NULL;
    struct list_head *bucket = flowtable_bucket(ft, &fte->mask);

    /* Find the flow table entry to update the flow_cnt */
    LIST_FOREACH(bucket, cur) {
        cur_fts = container_of(cur, links, struct flowtable_specific);
        if (memcmp(&cur_fts->flow_mask, &fte->mask, sizeof(struct flowtable_key)) == 0) {
            break;
        }
        cur_fts = NULL;
    }

    if(cur_fts) {
        cur_fts->flow_cnt--;
        list_remove(&fte->links);

        /* If no flows are present then free the specific flowtable */
        if(!cur_fts->flow_cnt) {
            list_remove(&cur_fts->links);
            flowtable_specific_list_del(ft, cur_fts);
            free(cur_fts);
        }
    }

    return;
}

/* Documented in flowtable.h */
struct flowtable_entry *
flowtable_match(struct flowtable *ft, const struct flowtable_key *key)
{
    struct flowtable_entry *found = NULL;
    struct flowtable_entry *new_found = NULL;
    uint32_t i = 0;

    /* Check all the specific flowtables for the flow entry with highest priority */
    for(i = 0; i < ft->fts_list_cnt; i++) {
        if(found && (found->priority > ft->fts_list[i]->max_priority)) {
            continue;
        }

        new_found = flowtable_specific_match(ft->fts_list[i], key, (found ? found->priority : 0));

        if(new_found != NULL) {
            found = new_found;
        }
    }

    return found;
}

/*
 * Return the flowtable bucket for the given flow entry mask
 */
static struct list_head *
flowtable_bucket(struct flowtable *ft, const struct flowtable_key *mask)
{
    struct flowtable_key hash_key;
    memcpy(&hash_key, mask, sizeof(struct flowtable_key));
    uint32_t hash = murmur_hash(&hash_key, sizeof(hash_key), ind_ovs_salt);
    return &ft->buckets[hash % FLOWTABLE_BUCKETS];
}

/*
 * Return the bucket where flow entry should be added in specific flow hash table
 */
static struct list_head *
flowtable_specific_bucket(struct flowtable_specific *fts,
                          const struct flowtable_key *key)
{
    struct flowtable_key masked_key;
    int i;
    for (i = 0; i < FLOWTABLE_KEY_SIZE/8; i++) {
        masked_key.data[i] = key->data[i] & fts->flow_mask.data[i];
    }

    uint32_t hash = murmur_hash(&masked_key, sizeof(masked_key), ind_ovs_salt);
    return &fts->buckets[hash % FLOWTABLE_SPECIFIC_BUCKETS];
}

/*
 * Insert the flowtable entry in the specific flow hash table
 */
static void
flowtable_specific_insert(struct flowtable_specific *fts,
                          struct flowtable_entry *new_fte)
{
    struct list_links *cur;
    struct list_head *bucket = flowtable_specific_bucket(fts, &new_fte->key);

    LIST_FOREACH(bucket, cur) {
        struct flowtable_entry *cur_fte = container_of(cur, links, struct flowtable_entry);
        if (cur_fte->priority <= new_fte->priority) {
            list_insert_before(&cur_fte->links, &new_fte->links);
            return;
        }
    }

    list_push(bucket, &new_fte->links);
}

/*
 * Find the flow in the specific flow hashtable
 */
static struct flowtable_entry *
flowtable_specific_match(struct flowtable_specific *fts,
                         const struct flowtable_key *key,
                         const uint16_t cur_priority)
{
    struct list_links *cur = NULL;
    struct list_head *bucket= flowtable_specific_bucket(fts, key);

    LIST_FOREACH(bucket, cur) {
        struct flowtable_entry *fte =
            container_of(cur, links, struct flowtable_entry);

        if(cur_priority > fte->priority) {
            return NULL;
        }

        if (match(&fte->key, &fts->flow_mask, key)) {
            return fte;
        }
    }
    return NULL;
}

/*
 * Check whether the masked portions of 'flow_key' and 'pkt_key' are
 * identical. 'flow_key' must have zero bits where 'flow_mask' has
 * zero bits.
 */
static bool
match(const struct flowtable_key *flow_key,
      const struct flowtable_key *flow_mask,
      const struct flowtable_key *pkt_key)
{
    uint64_t *f = (uint64_t *)flow_key;
    uint64_t *m = (uint64_t *)flow_mask;
    uint64_t *p = (uint64_t *)pkt_key;
    int i;

    /* The compiler will unroll this loop */
    for (i = 0; i < FLOWTABLE_KEY_SIZE/8; i++) {
        if ((p[i] & m[i]) != f[i]) {
            return false;
        }
    }

    return true;
}

/* Add new specific flowtable to the list */
static void
flowtable_specific_list_add(struct flowtable *ft, struct flowtable_specific *fts)
{
    /* If list is full, allocate twice the size of current list */
    if(ft->fts_list_cnt >= ft->fts_list_size) {
        struct flowtable_specific **new_fts_list =
            realloc(ft->fts_list, 2*ft->fts_list_size*(sizeof(ft->fts_list[0])));

        if(new_fts_list == NULL) {
            AIM_LOG_ERROR("Failed to allocate more specific flowtable list");
            return;
        }

        ft->fts_list = new_fts_list;
        ft->fts_list_size *= 2;
    }

    ft->fts_list[ft->fts_list_cnt++] = fts;
    return;
}

/* Delete specific flowtable from list */
static void
flowtable_specific_list_del(struct flowtable *ft, struct flowtable_specific *fts)
{
    uint32_t i;
    for(i = 0; (i < ft->fts_list_cnt) && (ft->fts_list[i] != fts); i++);

    if(i >= ft->fts_list_cnt) {
        AIM_LOG_ERROR("Specific flow table not found in the list");
        return;
    }

    ft->fts_list[i] = ft->fts_list[--ft->fts_list_cnt];
    ft->fts_list[ft->fts_list_cnt] = NULL;
    return;
}
