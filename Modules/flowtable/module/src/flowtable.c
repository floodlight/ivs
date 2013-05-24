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

#define FLOWTABLE_BUCKETS 16384

/*
 * Entries in each bucket are maintained in descending priority order.
 */
struct flowtable {
    struct flowtable_key hash_mask;
    struct list_head wildcard_bucket;
    struct list_head buckets[FLOWTABLE_BUCKETS];
};

static struct list_head *flow_bucket(struct flowtable *ft, const struct flowtable_entry *fte);
static struct list_head *pkt_bucket(struct flowtable *ft, const struct flowtable_key *key);
static struct flowtable_entry *search_bucket(const struct list_head *head, const struct flowtable_key *key, uint16_t min_priority);
static bool match(const struct flowtable_key *flow_fields, const struct flowtable_key *flow_masks, const struct flowtable_key *pkt_fields);

/*
 * HACK need a random number to prevent hash collision attacks.
 */
extern uint32_t ind_ovs_salt;

/* Documented in flowtable.h */
struct flowtable *
flowtable_create(const struct flowtable_key *hash_mask)
{
    struct flowtable *ft = malloc(sizeof(*ft));
    if (ft == NULL) {
        return NULL;
    }

    ft->hash_mask = *hash_mask;

    int i;
    for (i = 0; i < FLOWTABLE_BUCKETS; i++) {
        list_init(&ft->buckets[i]);
    }
    list_init(&ft->wildcard_bucket);

    return ft;
}

/* Documented in flowtable.h */
void
flowtable_destroy(struct flowtable *ft)
{
    free(ft);
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
    struct list_head *bucket = flow_bucket(ft, fte);

    LIST_FOREACH(bucket, cur) {
        struct flowtable_entry *cur_fte = container_of(cur, links, struct flowtable_entry);
        if (cur_fte->priority <= fte->priority) {
            list_insert_before(&cur_fte->links, &fte->links);
            return;
        }
    }

    list_push(bucket, &fte->links);
}

/* Documented in flowtable.h */
void
flowtable_remove(struct flowtable *ft, struct flowtable_entry *fte)
{
    (void) ft;
    list_remove(&fte->links);
}

/* Documented in flowtable.h */
struct flowtable_entry *
flowtable_match(struct flowtable *ft,
                const struct flowtable_key *key)
{
    struct flowtable_entry *found = search_bucket(pkt_bucket(ft, key), key, 0);
    uint16_t min_priority = found ? found->priority : 0;
    struct flowtable_entry *wc_found = search_bucket(&ft->wildcard_bucket, key, min_priority);
    if (found && wc_found && wc_found->priority > found->priority) {
        return wc_found;
    } else if (!found) {
        return wc_found;
    } else {
        return found;
    }
}

/*
 * Return the bucket the given flowtable entry should be added to.
 */
static struct list_head *
flow_bucket(struct flowtable *ft, const struct flowtable_entry *fte)
{
    /*
     * Check if the new flow is at least as specific as the hash mask.
     */
    if (match(&fte->mask, &ft->hash_mask, &ft->hash_mask)) {
        return pkt_bucket(ft, &fte->key);
    } else {
        return &ft->wildcard_bucket;
    }
}

/*
 * Return the hash bucket computed from the packet key.
 *
 * There may also be matching flows in the wildcard bucket.
 */
static struct list_head *
pkt_bucket(struct flowtable *ft, const struct flowtable_key *key)
{
    struct flowtable_key masked_key;
    int i;
    for (i = 0; i < FLOWTABLE_KEY_SIZE/8; i++) {
        masked_key.data[i] = key->data[i] & ft->hash_mask.data[i];
    }

    uint32_t hash = murmur_hash(&masked_key, sizeof(masked_key), ind_ovs_salt);
    return &ft->buckets[hash % FLOWTABLE_BUCKETS];
}

/*
 * Search the given bucket for a matching flow.
 *
 * Entries within a bucket are sorted by priority, so we can exit early if
 * we see a lower priority than 'min_priority'.
 */
static struct flowtable_entry *
search_bucket(const struct list_head *head, const struct flowtable_key *key,
              uint16_t min_priority)
{
    struct list_links *cur;
    LIST_FOREACH(head, cur) {
        struct flowtable_entry *fte =
            container_of(cur, links, struct flowtable_entry);
        if (fte->priority < min_priority) {
            return NULL;
        }
        if (match(&fte->key, &fte->mask, key)) {
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
