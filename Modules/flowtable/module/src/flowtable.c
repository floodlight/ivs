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
 * Hash table to maintain flow entries
 *
 * Entries in each bucket are maintained in descending priority order.
 */
struct flowtable_specific {
    struct flowtable_key hash_mask;
    struct list_head wildcard_bucket;
    struct list_head buckets[FLOWTABLE_BUCKETS];
};

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
    struct flowtable_specific *fts;
    uint32_t flow_cnt;  /* Number of flow entries in flowtable_specific */
};

static struct list_head *flowtable_generic_bucket(struct flowtable *ftg, const struct flowtable_key mask);
static struct flowtable_specific * flowtable_specific_create(void);
static void flowtable_specific_destroy(struct flowtable_specific *fts);
static struct list_head *flowtable_specific_bucket(struct flowtable_specific *fts,
                                                   const struct flowtable_key *mask,
                                                   const struct flowtable_key *key);
static struct flowtable_entry *flowtable_specific_match(struct flowtable_specific *fts,
                                                        const struct flowtable_key *mask,
                                                        const struct flowtable_key *key);
static void flowtable_specific_insert(struct flowtable_specific *fts,
                                      const struct flowtable_key *flow_mask,
                                      struct flowtable_entry *fte);
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
    struct flowtable *ftg = malloc(sizeof(*ftg));
    if (ftg == NULL) {
        return NULL;
    }

    int i;
    for (i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        list_init(&ftg->generic_buckets[i]);
    }

    return ftg;
}

/* Documented in flowtable.h */
void
flowtable_destroy(struct flowtable *ftg)
{
    struct list_links *cur;
    int i;

    for(i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        while((cur = list_pop(&ftg->generic_buckets[i])) != NULL) {
            struct flowtable_generic_entry *cur_ftge =
                container_of(cur, links, struct flowtable_generic_entry);

            flowtable_specific_destroy(cur_ftge->fts);
            free(cur_ftge);
        }
    }

    free(ftg);
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
flowtable_insert(struct flowtable *ftg, struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct list_head *ftg_bucket = flowtable_generic_bucket(ftg, fte->mask);

    /* Check if generic flow table entry is present for the new flow entry mask */
    LIST_FOREACH(ftg_bucket, cur) {
        struct flowtable_generic_entry *cur_ftge =
            container_of(cur, links, struct flowtable_generic_entry);
        if (memcmp(&cur_ftge->flow_mask, &fte->mask, sizeof(struct flowtable_key)) == 0) {
            /* If present, insert the new flow entry */
            flowtable_specific_insert(cur_ftge->fts, &cur_ftge->flow_mask, fte);
            cur_ftge->flow_cnt++;
            return;
        }
    }

    /* If not present, then create a generic flow table entry and specific flowtable */
    struct flowtable_specific *fts = flowtable_specific_create();
    if(fts == NULL) {
        AIM_LOG_ERROR("Failed to allocate flowtable");
        return;
    }

    struct flowtable_generic_entry *ftge_new = calloc(1, sizeof(*ftge_new));
    if(ftge_new == NULL) {
        AIM_LOG_ERROR("Failed to allocate generic flowtable entry");
        free(fts);
        return;
    }

    ftge_new->flow_mask = fte->mask;
    ftge_new->fts = fts;
    flowtable_specific_insert(fts, &ftge_new->flow_mask, fte);
    ftge_new->flow_cnt = 1;

    list_push(ftg_bucket, &ftge_new->links);
    return;
}

/* Documented in flowtable.h */
void
flowtable_remove(struct flowtable *ftg, struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct flowtable_generic_entry *cur_ftge = NULL;
    struct list_head *bucket = flowtable_generic_bucket(ftg, fte->mask);

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

        /* If no flows are present then destroy the specific flow table and
           free the flowtable_genric entry */
        if(!cur_ftge->flow_cnt) {
            flowtable_specific_destroy(cur_ftge->fts);
            list_remove(&cur_ftge->links);
            free(cur_ftge);
        }
    }

    return;
}

/* Documented in flowtable.h */
struct flowtable_entry *
flowtable_match(struct flowtable *ftg, const struct flowtable_key *key)
{
    struct flowtable_generic_entry *cur_ftge = NULL;
    struct list_links *cur = NULL;
    struct flowtable_entry *found = NULL;
    struct flowtable_entry *new_found = NULL;
    int i = 0;

    /* Check all the specific flowtables for the flow table entry with highest priority */
    for(i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        LIST_FOREACH(&ftg->generic_buckets[i], cur) {
            cur_ftge = container_of(cur, links, struct flowtable_generic_entry);
            new_found = flowtable_specific_match(cur_ftge->fts, &cur_ftge->flow_mask, key);

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
flowtable_generic_bucket(struct flowtable *ftg, const struct flowtable_key mask)
{
    struct flowtable_key hash_key;
    memcpy(&hash_key, &mask, sizeof(struct flowtable_key));
    uint32_t hash = murmur_hash(&hash_key, sizeof(hash_key), ind_ovs_salt);
    return &ftg->generic_buckets[hash % FLOWTABLE_GENERIC_BUCKETS];
}

/*
 * Create specific flowtable
 */
static struct flowtable_specific *
flowtable_specific_create(void)
{
    struct flowtable_specific *fts = malloc(sizeof(*fts));
    if (fts == NULL) {
        return NULL;
    }

    int i;
    for (i = 0; i < FLOWTABLE_BUCKETS; i++) {
        list_init(&fts->buckets[i]);
    }

    return fts;
}

/*
 * Destroy specific flowtable
 */
static void
flowtable_specific_destroy(struct flowtable_specific *fts)
{
    free(fts);
}

/*
 * Return the bucket where flow entry should be added in given flowtable_specific
 */
static struct list_head *
flowtable_specific_bucket(struct flowtable_specific *fts,
                          const struct flowtable_key *mask,
                          const struct flowtable_key *key)
{
    struct flowtable_key masked_key;
    int i;
    for (i = 0; i < FLOWTABLE_KEY_SIZE/8; i++) {
        masked_key.data[i] = key->data[i] & mask->data[i];
    }

    uint32_t hash = murmur_hash(&masked_key, sizeof(masked_key), ind_ovs_salt);
    return &fts->buckets[hash % FLOWTABLE_BUCKETS];
}

/*
 * Insert the flowtable entry in the flowtable_specific
 */
static void
flowtable_specific_insert(struct flowtable_specific *fts,
                          const struct flowtable_key *flow_mask,
                          struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct list_head *bucket = flowtable_specific_bucket(fts, flow_mask, &fte->key);

    LIST_FOREACH(bucket, cur) {
        struct flowtable_entry *cur_fte = container_of(cur, links, struct flowtable_entry);
        if (cur_fte->priority <= fte->priority) {
            list_insert_before(&cur_fte->links, &fte->links);
            return;
        }
    }

    list_push(bucket, &fte->links);
}

/*
 * Find the flow in the flowtable_specific
 */
static struct flowtable_entry *
flowtable_specific_match(struct flowtable_specific *fts,
                         const struct flowtable_key *mask,
                         const struct flowtable_key *key)
{
    struct list_links *cur = NULL;
    struct list_head *bucket= flowtable_specific_bucket(fts, mask, key);

    LIST_FOREACH(bucket, cur) {
        struct flowtable_entry *fte =
            container_of(cur, links, struct flowtable_entry);
        if (match(&fte->key, mask, key)) {
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
