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

#pragma GCC optimize (4)
#include "flowtable/flowtable.h"
#include "murmur/murmur.h"
#include "flowtable_log.h"

#define FLOWTABLE_GENERIC_BUCKETS 32
#define FLOWTABLE_BUCKETS 16384

/*
 * Generic flowtable hash with flowtable_entry mask as key
 */
struct flowtable {
    struct list_head generic_buckets[FLOWTABLE_GENERIC_BUCKETS];
};

/*
 * An entry in a generic flowtable.
 *
 * flowtable_generic_entry will be removed if the flow_cnt reaches zero.
 */
struct flowtable_generic_entry {
    struct list_links links;
    struct flowtable_key flow_mask;
    struct list_head specific_buckets[FLOWTABLE_BUCKETS];
    uint32_t flow_cnt;  /* Number of flow entries in all specific_buckets */
};

static struct list_head *flowtable_generic_bucket(struct flowtable *ft,
                                                  const struct flowtable_key *mask);
static struct list_head *flowtable_specific_bucket(struct flowtable_generic_entry *ftge,
                                                    const struct flowtable_key *key);
static void flowtable_specific_insert(struct flowtable_generic_entry *ftge,
                                      struct flowtable_entry *new_fte);
static struct flowtable_entry *flowtable_specific_match(struct flowtable_generic_entry *ftge,
                                                         const struct flowtable_key *key);
static bool match(const struct flowtable_key *flow_key,
                  const struct flowtable_key *flow_mask,
                  const struct flowtable_key *pkt_key);

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
        return NULL;
    }

    int i;
    for (i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        list_init(&ft->generic_buckets[i]);
    }

    return ft;
}

/* Documented in flowtable.h */
void
flowtable_destroy(struct flowtable *ft)
{
    struct list_links *cur;
    int i;

    for(i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        while((cur = list_pop(&ft->generic_buckets[i])) != NULL) {
            struct flowtable_generic_entry *cur_ftge =
                container_of(cur, links, struct flowtable_generic_entry);

            free(cur_ftge);
        }
    }

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
    struct list_head *ft_bucket = flowtable_generic_bucket(ft, &fte->mask);

    /* Check if generic flow table entry is present for the new flow entry mask */
    LIST_FOREACH(ft_bucket, cur) {
        struct flowtable_generic_entry *cur_ftge =
            container_of(cur, links, struct flowtable_generic_entry);
        if (memcmp(&cur_ftge->flow_mask, &fte->mask, sizeof(struct flowtable_key)) == 0) {
            /* If present, insert the new flow entry */
            flowtable_specific_insert(cur_ftge, fte);
            cur_ftge->flow_cnt++;
            return;
        }
    }

    /* If not present, then create a generic flow table entry */
    struct flowtable_generic_entry *new_ftge = calloc(1, sizeof(*new_ftge));
    if(new_ftge == NULL) {
        AIM_LOG_ERROR("Failed to allocate generic flowtable entry");
        return;
    }

    int i;
    for (i = 0; i < FLOWTABLE_BUCKETS; i++) {
        list_init(&new_ftge->specific_buckets[i]);
    }

    new_ftge->flow_mask = fte->mask;
    flowtable_specific_insert(new_ftge, fte);
    new_ftge->flow_cnt = 1;

    list_push(ft_bucket, &new_ftge->links);
    return;
}

/* Documented in flowtable.h */
void
flowtable_remove(struct flowtable *ft, struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct flowtable_generic_entry *cur_ftge = NULL;
    struct list_head *bucket = flowtable_generic_bucket(ft, &fte->mask);

    /* Find the generic flow table entry to update the flow_cnt */
    LIST_FOREACH(bucket, cur) {
        cur_ftge = container_of(cur, links, struct flowtable_generic_entry);
        if (memcmp(&cur_ftge->flow_mask, &fte->mask, sizeof(struct flowtable_key)) == 0) {
            break;
        }
        cur_ftge = NULL;
    }

    if(cur_ftge) {
        cur_ftge->flow_cnt--;
        list_remove(&fte->links);

        /* If no flows are present then free the generic flowtable entry */
        if(!cur_ftge->flow_cnt) {
            list_remove(&cur_ftge->links);
            free(cur_ftge);
        }
    }

    return;
}

/* Documented in flowtable.h */
struct flowtable_entry *
flowtable_match(struct flowtable *ft, const struct flowtable_key *key)
{
    struct flowtable_generic_entry *cur_ftge = NULL;
    struct list_links *cur = NULL;
    struct flowtable_entry *found = NULL;
    struct flowtable_entry *new_found = NULL;
    int i = 0;

    /* Check all the specific flowtables for the flow entry with highest priority */
    for(i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        LIST_FOREACH(&ft->generic_buckets[i], cur) {
            cur_ftge = container_of(cur, links, struct flowtable_generic_entry);
            new_found = flowtable_specific_match(cur_ftge, key);

            if(new_found != NULL) {
                if(found == NULL) {
                    found = new_found;
                    continue;
                }
                else if(found->priority < new_found->priority){
                    found = new_found;
                }
            }
        }
    }

    return found;
}

/*
 * Return the generic flowtable bucket for the given flow entry mask
 */
static struct list_head *
flowtable_generic_bucket(struct flowtable *ft, const struct flowtable_key *mask)
{
    struct flowtable_key hash_key;
    memcpy(&hash_key, mask, sizeof(struct flowtable_key));
    uint32_t hash = murmur_hash(&hash_key, sizeof(hash_key), ind_ovs_salt);
    return &ft->generic_buckets[hash % FLOWTABLE_GENERIC_BUCKETS];
}

/*
 * Return the bucket where flow entry should be added in specific flow hash table
 */
static struct list_head *
flowtable_specific_bucket(struct flowtable_generic_entry *ftge,
                          const struct flowtable_key *key)
{
    struct flowtable_key masked_key;
    int i;
    for (i = 0; i < FLOWTABLE_KEY_SIZE/8; i++) {
        masked_key.data[i] = key->data[i] & ftge->flow_mask.data[i];
    }

    uint32_t hash = murmur_hash(&masked_key, sizeof(masked_key), ind_ovs_salt);
    return &ftge->specific_buckets[hash % FLOWTABLE_BUCKETS];
}

/*
 * Insert the flowtable entry in the specific flow hash table
 */
static void
flowtable_specific_insert(struct flowtable_generic_entry *ftge,
                          struct flowtable_entry *new_fte)
{
    struct list_links *cur;
    struct list_head *bucket = flowtable_specific_bucket(ftge, &new_fte->key);

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
flowtable_specific_match(struct flowtable_generic_entry *ftge, const struct flowtable_key *key)
{
    struct list_links *cur = NULL;
    struct list_head *bucket= flowtable_specific_bucket(ftge, key);

    LIST_FOREACH(bucket, cur) {
        struct flowtable_entry *fte =
            container_of(cur, links, struct flowtable_entry);
        if (match(&fte->key, &ftge->flow_mask, key)) {
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
