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

/*
 * Implemented as an open-addressed hashtable with quadratic probing.
 *
 * As usual for an open-addressed (aka no chaining) hashtable, entries
 * may be in a DELETED state where they are skipped by searches and
 * reused by insertions.
 */

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif
#include <l2table/l2table.h>
#include <stdbool.h>
#include <murmur/murmur.h>
#include <AIM/aim_memory.h>

/*
 * Highest 4 key bits are reserved for flags
 *
 * A key may be FREE without being DELETED, but a DELETED key is always FREE.
 */
#define KEY_FREE (1ULL << 63)
#define KEY_DELETED (3ULL << 62)
#define KEY_IS_UNOCCUPIED(key) ((key) & KEY_FREE)

struct l2table_entry {
    uint64_t key; /* See l2table_encode_key__ and l2table_decode_key__ */
    uint32_t out_port;
    uint32_t metadata;
};
AIM_STATIC_ASSERT(l2table_entry_size, sizeof(struct l2table_entry) == 16);

struct l2table {
    struct l2table_entry *entries;
    int size;
    int num_occupied;
    int num_deleted;
    uint32_t salt;
};

static aim_error_t l2table_resize__(struct l2table *t);
static uint64_t l2table_encode_key__(const uint8_t mac[L2TABLE_MAC_LEN], uint16_t vlan_id);
static void l2table_decode_key__(uint64_t key, uint8_t mac[L2TABLE_MAC_LEN], uint16_t *vlan_id);

struct l2table *
l2table_create(uint32_t salt)
{
    struct l2table *t = aim_malloc(sizeof(*t));
    t->size = 1;
    t->num_occupied = 0;
    t->num_deleted = 0;
    t->salt = salt;

    t->entries = aim_malloc(sizeof(*t->entries));

    int i;
    for (i = 0; i < t->size; i++) {
        t->entries[i].key = KEY_FREE;
    }

    return t;
}

void
l2table_destroy(struct l2table *t)
{
    aim_free(t->entries);
    aim_free(t);
}

static uint32_t
l2table_hash__(struct l2table *t,
               const uint8_t mac[L2TABLE_MAC_LEN], uint16_t vlan_id)
{
    union {
        uint8_t u8[8];
        uint16_t u16[4];
    } buf;
    buf.u16[0] = vlan_id;
    memcpy(&buf.u8[2], mac, L2TABLE_MAC_LEN);
    return murmur_hash(buf.u8, sizeof(buf.u8), t->salt);
}

/*
 * Find a slot in the hashtable for the given MAC/VLAN
 *
 * The logic is substantially different depending on whether
 * we're trying to find an occupied (for lookup) or unoccupied
 * (for insert) slot. This function contains both sets of code
 * so that the probing is centralized, and the wrapper functions
 * below inline this function to specialize it.
 */
static inline struct l2table_entry *
l2table_find_internal__(struct l2table *t,
                        const uint8_t mac[L2TABLE_MAC_LEN],
                        uint16_t vlan_id,
                        bool find_unoccupied)
{
    uint64_t key = l2table_encode_key__(mac, vlan_id);
    uint32_t h = l2table_hash__(t, mac, vlan_id);
    uint32_t mask = t->size - 1; /* Assumes size is a power of 2 */
    int step_size = 0;
    int step_num = 0;

    struct l2table_entry *found = NULL;

    while (1) {
        uint32_t idx = (h + step_size) & mask;
        struct l2table_entry *e = &t->entries[idx];

        if (!find_unoccupied) {
            /* Lookup case */
            if (e->key == key) {
                return e;
            } else if (e->key == KEY_FREE) {
                return NULL;
            }
        } else {
            /* Insertion case */
            if (e->key == key) {
                /* Duplicate */
                return NULL;
            } else if (KEY_IS_UNOCCUPIED(e->key)) {
                if (!found) {
                    /* Take the first unoccupied slot we find */
                    found = e;
                }

                if (e->key == KEY_FREE) {
                    return found;
                } else {
                    /* Key is deleted. Need to continue probing. */
                }
            }
        }

        /* Triangular numbers: 0, 1, 3, 6, ... */
        /* Guaranteed to hit every slot in a 2^n sized hashtable */
        step_num += 1;
        step_size += step_num;
    }
}

/*
 * Return the entry with the given MAC/VLAN, or NULL if it does not exist.
 */
static struct l2table_entry *
l2table_find__(struct l2table *t,
               const uint8_t mac[L2TABLE_MAC_LEN],
               uint16_t vlan_id)
{
    return l2table_find_internal__(t, mac, vlan_id, false);
}

/*
 * Return an unoccupied slot for the given MAC/VLAN, or NULL if it already
 * exists.
 */
static struct l2table_entry *
l2table_find_unoccupied__(struct l2table *t,
               const uint8_t mac[L2TABLE_MAC_LEN],
               uint16_t vlan_id)
{
    return l2table_find_internal__(t, mac, vlan_id, true);
}

aim_error_t
l2table_lookup(struct l2table *t,
               const uint8_t mac[L2TABLE_MAC_LEN],
               uint16_t vlan_id,
               uint32_t *out_port,
               uint32_t *metadata)
{
    struct l2table_entry *e = l2table_find__(t, mac, vlan_id);
    if (e == NULL) {
        return AIM_ERROR_NOT_FOUND;
    }

    *out_port = e->out_port;
    *metadata = e->metadata;

    return AIM_ERROR_NONE;
}

aim_error_t
l2table_insert(struct l2table *t,
               const uint8_t mac[L2TABLE_MAC_LEN],
               uint16_t vlan_id,
               uint32_t out_port,
               uint32_t metadata)
{
    /*
     * Ensure that at least half of all entries after the insertion are in
     * state FREE.
     */
    if (2 * (t->num_occupied + t->num_deleted + 1) > t->size) {
        aim_error_t err = l2table_resize__(t);
        if (err < 0) {
            return err;
        }
    }

    struct l2table_entry *e = l2table_find_unoccupied__(t, mac, vlan_id);
    if (e == NULL) { /* duplicate */
        return AIM_ERROR_PARAM; /* XXX AIM_ERROR_EXISTS */
    }

    if (e->key == KEY_DELETED) {
        t->num_deleted--;
    }
    t->num_occupied++;

    e->key = l2table_encode_key__(mac, vlan_id);
    e->out_port = out_port;
    e->metadata = metadata;

    return AIM_ERROR_NONE;
}

aim_error_t
l2table_remove(struct l2table *t,
               const uint8_t mac[L2TABLE_MAC_LEN],
               uint16_t vlan_id)
{
    struct l2table_entry *e = l2table_find__(t, mac, vlan_id);
    if (e == NULL) {
        return AIM_ERROR_NOT_FOUND;
    }

    t->num_deleted++;
    t->num_occupied--;
    e->key = KEY_DELETED;

    return AIM_ERROR_NONE;
}

static aim_error_t
l2table_resize__(struct l2table *t)
{
    int i;
    int old_size = t->size;
    int new_size = t->size * 2;
    struct l2table_entry *old_entries = t->entries;
    struct l2table_entry *new_entries = aim_malloc(new_size * sizeof(*new_entries));

    for (i = 0; i < new_size; i++) {
        new_entries[i].key = KEY_FREE;
    }

    t->size = new_size;
    t->entries = new_entries;
    t->num_occupied = 0;
    t->num_deleted = 0;

    for (i = 0; i < old_size; i++) {
        struct l2table_entry *e = &old_entries[i];
        if (!KEY_IS_UNOCCUPIED(e->key)) {
            uint8_t mac[6];
            uint16_t vlan_id;
            l2table_decode_key__(e->key, mac, &vlan_id);
            aim_error_t err = l2table_insert(t, mac, vlan_id,
                                             e->out_port, e->metadata);
            AIM_TRUE_OR_DIE(err == AIM_ERROR_NONE, "unexpected error inserting during resize");
        }
    }

    aim_free(old_entries);

    return AIM_ERROR_NONE;
}

/*
 * Key format (MSB to LSB):
 *  - 4 bits flags (0 for a occupied entry)
 *  - 12 bits VLAN ID
 *  - 48 bits MAC
 */

static uint64_t
l2table_encode_key__(const uint8_t mac[L2TABLE_MAC_LEN], uint16_t vlan_id)
{
    union {
        uint8_t u8[8];
        uint64_t u64[1];
    } buf;
    memcpy(buf.u8, mac, L2TABLE_MAC_LEN);
    buf.u8[6] = vlan_id & 0xff;
    buf.u8[7] = vlan_id >> 8;
    return buf.u64[0];
}

static void
l2table_decode_key__(uint64_t key,
                     uint8_t mac[L2TABLE_MAC_LEN], uint16_t *vlan_id)
{
    uint8_t *buf = (uint8_t *)&key;
    memcpy(mac, buf, L2TABLE_MAC_LEN);
    *vlan_id = buf[6] | (buf[7] << 8);
}
