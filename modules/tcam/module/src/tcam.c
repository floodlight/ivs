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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

/*
 * See the comments in tcam.h for a high level description.
 *
 * A tcam is split into a number of 'shards'. Each shard contains all the
 * entries for one particular mask. A shard maintains a hashtable mapping
 * a key to a list of entries, sorted by priority.
 *
 * On a lookup we iterate over all shards. For each shard, we create a
 * masked copy of the lookup key and search for that in the shard's
 * hashtable. If there are multiple entries matching the key then the
 * first (highest priority) one is returned.
 *
 * TODO handle lots identical keys with different priorities
 * TODO optimize single-entry shards
 */

#include <AIM/aim.h>
#include <BigHash/bighash.h>
#include <tcam/tcam.h>
#include <murmur/murmur.h>
#include <bloom_filter/bloom_filter.h>
#include "tcam_log.h"

#define TCAM_INITIAL_ENTRY_BUCKETS 16
#define TCAM_LOAD_FACTOR 0.5f
#define TCAM_BLOOM_BITS_PER_ENTRY 8

/*
 * A 'shard' contains all entries with a particular mask.
 */
struct tcam_shard {
    list_links_t links;
    bighash_entry_t hash_entry;
    void *mask;
    uint32_t count; /* number of entries in this shard */
    uint32_t buckets_size;
    struct tcam_entry **buckets;
    bloom_filter_t *bloom_filter;
};

/*
 * Top-level tcam object.
 */
struct tcam {
    bighash_table_t *shard_hashtable; /* contains tcam_shard through hash_entry */
    list_head_t shard_list; /* contains tcam_shard through links */
    uint16_t key_size;
    uint32_t salt;
};

static struct tcam_shard *tcam_find_shard(struct tcam *tcam, const void *mask);
static struct tcam_shard *tcam_shard_create(struct tcam *tcam, const void *mask);
static void tcam_shard_destroy(struct tcam *tcam, struct tcam_shard *shard);
static void tcam_shard_grow(struct tcam_shard *shard);
static int memcmp_masked(const void *a, const void *b, const void *mask, int len);
static void memor(void *dst, const void *src, int len);
static uint32_t hash_key(const struct tcam *tcam, const void *key, const void *mask);

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif

/* Documented in tcam.h */
struct tcam *
tcam_create(uint16_t key_size, uint32_t salt)
{
    AIM_ASSERT(key_size % 4 == 0, "tcam key size must be a multiple of 4");

    struct tcam *tcam = aim_malloc(sizeof(*tcam));

    tcam->shard_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    list_init(&tcam->shard_list);
    tcam->key_size = key_size;
    tcam->salt = salt;

    return tcam;
}

/* Documented in tcam.h */
void
tcam_destroy(struct tcam *tcam)
{
    AIM_ASSERT(list_empty(&tcam->shard_list), "attempted to destroy a non-empty tcam");
    bighash_table_destroy(tcam->shard_hashtable, NULL);
    aim_free(tcam);
}

/* Documented in tcam.h */
void
tcam_insert(struct tcam *tcam, struct tcam_entry *entry,
            const void *key, const void *mask, uint16_t priority)
{
    entry->key = aim_memdup((void *)key, tcam->key_size);
    entry->priority = priority;
    entry->hash = hash_key(tcam, entry->key, mask);

    struct tcam_shard *shard = tcam_find_shard(tcam, mask);

    /* Check if a shard exists for the given mask */
    if (shard == NULL) {
        /* If not present, then create a shard */
        shard = tcam_shard_create(tcam, mask);
    }

    entry->mask = shard->mask;

    /* Find insertion point */
    struct tcam_entry **prev_ptr = &shard->buckets[entry->hash & (shard->buckets_size - 1)];
    while (*prev_ptr != NULL && entry->priority < (*prev_ptr)->priority) {
        prev_ptr = &(*prev_ptr)->next;
    }

    entry->next = *prev_ptr;
    *prev_ptr = entry;

    shard->count++;

    bloom_filter_add(shard->bloom_filter, entry->hash);

    if (shard->count > shard->buckets_size * TCAM_LOAD_FACTOR) {
        tcam_shard_grow(shard);
    }
}

/* Documented in tcam.h */
void
tcam_remove(struct tcam *tcam, struct tcam_entry *entry)
{
    struct tcam_shard *shard = tcam_find_shard(tcam, entry->mask);

    AIM_ASSERT(shard != NULL, "shard does not exist during remove");

    /* Find the previous entry in the list to update its next pointer */
    uint32_t hash = hash_key(tcam, entry->key, entry->mask);
    struct tcam_entry **prev_ptr = &shard->buckets[hash & (shard->buckets_size - 1)];
    while (prev_ptr != NULL && *prev_ptr != entry) {
        prev_ptr = &(*prev_ptr)->next;
    }

    AIM_ASSERT(prev_ptr != NULL, "entry does not exist during remove");

    *prev_ptr = entry->next;
    shard->count--;

    bloom_filter_remove(shard->bloom_filter, entry->hash);

    /* If no flows are present then free the shard */
    if (shard->count == 0) {
        tcam_shard_destroy(tcam, shard);
    }

    aim_free(entry->key);
}

/* Documented in tcam.h */
struct tcam_entry *
tcam_match(struct tcam *tcam, const void *key)
{
    return tcam_match_and_mask(tcam, key, NULL);
}

/* Documented in tcam.h */
struct tcam_entry *
tcam_match_and_mask(struct tcam *tcam, const void *key, void *mask)
{
    struct tcam_entry *found = NULL;
    list_links_t *cur;
    uint16_t cur_priority = 0;

    /* Check all shards for the matching entry with highest priority */
    LIST_FOREACH(&tcam->shard_list, cur) {
        struct tcam_shard *shard = container_of(cur, links, struct tcam_shard);

        uint32_t hash = hash_key(tcam, key, shard->mask);

        if (mask) {
            memor(mask, shard->mask, tcam->key_size);
        }

        if (!bloom_filter_lookup(shard->bloom_filter, hash)) {
            continue;
        }

        struct tcam_entry *entry = shard->buckets[hash & (shard->buckets_size - 1)];

        while (entry != NULL && entry->priority >= cur_priority) {
            if (entry->hash == hash &&
                    !memcmp_masked(key, entry->key, shard->mask, tcam->key_size)) {
                found = entry;
                cur_priority = entry->priority;
                break;
            }

            entry = entry->next;
        }
    }

    return found;
}

/*
 * Return the shard for a given mask
 */
static struct tcam_shard *
tcam_find_shard(struct tcam *tcam, const void *mask)
{
    uint32_t hash = hash_key(tcam, mask, mask);
    bighash_entry_t *cur;

    for (cur = bighash_first(tcam->shard_hashtable, hash);
         cur != NULL; cur = bighash_next(cur)) {
        struct tcam_shard *shard = container_of(cur, hash_entry, struct tcam_shard);
        if (memcmp(shard->mask, mask, tcam->key_size) == 0) {
            return shard;
        }
    }

    return NULL;
}

/*
 * Create a new shard for the given mask
 */
static struct tcam_shard *
tcam_shard_create(struct tcam *tcam, const void *mask)
{
    struct tcam_shard *shard = aim_zmalloc(sizeof(*shard));
    shard->mask = aim_memdup((void *)mask, tcam->key_size);

    uint32_t hash = hash_key(tcam, mask, mask);
    bighash_insert(tcam->shard_hashtable, &shard->hash_entry, hash);

    list_push(&tcam->shard_list, &shard->links);

    shard->buckets_size = TCAM_INITIAL_ENTRY_BUCKETS;
    shard->buckets = aim_zmalloc(sizeof(shard->buckets[0]) * shard->buckets_size);
    shard->bloom_filter = bloom_filter_create(shard->buckets_size*TCAM_BLOOM_BITS_PER_ENTRY);

    return shard;
}

/*
 * Remove the given shard
 */
static void
tcam_shard_destroy(struct tcam *tcam, struct tcam_shard *shard)
{
    AIM_ASSERT(shard->count == 0, "attempted to destroy a non-empty shard");

    bighash_remove(tcam->shard_hashtable, &shard->hash_entry);

    list_remove(&shard->links);

    aim_free(shard->mask);
    aim_free(shard->buckets);
    bloom_filter_destroy(shard->bloom_filter);
    aim_free(shard);
}

/*
 * Grow the given shard's lookup buckets
 *
 * Because we double the bucket array each time, there are only two possible
 * destination buckets for each source bucket. For each entry in the old
 * bucket, move it to one of the new buckets depending on the hash value.
 * Priority order is maintained.
 */
static void
tcam_shard_grow(struct tcam_shard *shard)
{
    int new_buckets_size = shard->buckets_size * 2;
    struct tcam_entry **new_buckets = aim_malloc(sizeof(new_buckets[0]) * new_buckets_size);

    bloom_filter_destroy(shard->bloom_filter);
    shard->bloom_filter = bloom_filter_create(new_buckets_size*TCAM_BLOOM_BITS_PER_ENTRY);

    /* Bit that decides whether we go in the hi or lo bucket */
    uint32_t bit = shard->buckets_size;

    unsigned i;
    for (i = 0; i < shard->buckets_size; i++) {
        struct tcam_entry *cur = shard->buckets[i];
        struct tcam_entry **new_tail_lo = &new_buckets[i];
        struct tcam_entry **new_tail_hi = &new_buckets[bit + i];

        /* Initialize new buckets to an empty list */
        *new_tail_lo = NULL;
        *new_tail_hi = NULL;

        while (cur != NULL) {
            /* Get the new tail */
            struct tcam_entry ***new_tail_ptr = cur->hash & bit ? &new_tail_hi
                                                                : &new_tail_lo;
            struct tcam_entry **new_tail = *new_tail_ptr;
            struct tcam_entry *next = cur->next;

            /* Add cur to the end of the list */
            *new_tail = cur;
            cur->next = NULL;

            bloom_filter_add(shard->bloom_filter, cur->hash);

            /* Advance local list pointers */
            *new_tail_ptr = &cur->next;
            cur = next;
        }
    }

    aim_free(shard->buckets);
    shard->buckets_size = new_buckets_size;
    shard->buckets = new_buckets;
}

/*
 * Compare 'a' and 'b' on the bits where 'mask' is set
 *
 * Returns 0 if the keys compare equal, 1 otherwise
 */
static int
memcmp_masked(const void *_a, const void *_b, const void *mask, int len)
{
    const uint32_t *__attribute__((__may_alias__)) a = _a;
    const uint32_t *__attribute__((__may_alias__)) b = _b;
    const uint32_t *__attribute__((__may_alias__)) m = mask;

    int i;
    for (i = 0; i < len/4; i++) {
        if ((a[i] ^ b[i]) & m[i]) {
            return 1;
        }
    }

    return 0;
}

/*
 * Binary OR src into dst
 */
static void
memor(void *_dst, const void *_src, int len)
{
    uint32_t *__attribute__((__may_alias__)) dst = _dst;
    const uint32_t *__attribute__((__may_alias__)) src = _src;

    int i;
    for (i = 0; i < len/4; i++) {
        dst[i] |= src[i];
    }
}

static uint32_t
hash_key(const struct tcam *tcam, const void *key, const void *mask)
{
    const uint32_t *__attribute__((__may_alias__)) k = key;
    const uint32_t *__attribute__((__may_alias__)) m = mask;

    uint32_t state = tcam->salt;
    unsigned i;
    for (i = 0; i < tcam->key_size/sizeof(uint32_t); i += 1) {
        /*
         * Only hash words where the mask is nonzero. Most masks are
         * sparse so this is a significant speedup. This could allow
         * a malicious controller to create hash collisions by permuting
         * the zero-mask words, so also mix in the index.
         */
        if (m[i]) {
            state = murmur_round(state, (k[i] & m[i]) ^ i);
        }
    }

    return murmur_finish(state, tcam->key_size);
}
