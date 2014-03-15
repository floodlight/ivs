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
 * Hash-based flowtable.
 *
 * The struct flowtable_key is used for both fields and masks. This
 * is abstract to ease code organization, but typically it is a
 * reinterpreted struct ind_ovs_cfr.
 *
 * The 'hash mask', which defines which portions of the key are used for
 * hashing, is set when the flowtable is created.
 *
 * Flows that are not at least as specific as the hash mask go into the
 * wildcard bucket, which must be searched as well as the relevant hash
 * bucket.
 */

#ifndef FLOWTABLE_H
#define FLOWTABLE_H

#include <AIM/aim_list.h>
#include <stdbool.h>

/*
 * Size of the flowtable key in bytes.
 */
#define FLOWTABLE_KEY_SIZE 112

struct flowtable;

/*
 * Opaque data used to search for a flow.
 *
 * This struct is used for both the fields of a flow or packet and
 * the mask of a flow.
 */
struct flowtable_key {
    uint64_t data[FLOWTABLE_KEY_SIZE/8];
};

/*
 * An entry in a flowtable.
 *
 * This struct is intended to be embedded in a containing object.
 *
 * It must not currently be in a flowtable when the containing object
 * is freed.
 *
 * It should be treated as opaque and initialized with flowtable_entry_init.
 */
struct flowtable_entry {
    struct list_links links; /* struct flowtable buckets */
    struct flowtable_key key;
    struct flowtable_key mask;
    uint16_t priority;
};

/* Create a flowtable */
struct flowtable *flowtable_create();

/*
 * Destroy a flowtable.
 *
 * All entries should have been removed.
 */
void flowtable_destroy(struct flowtable *ft);

/*
 * Initialize a flowtable entry.
 *
 * @param key Field values. Must be zero where mask is zero (bitwise).
 * @param mask Portion of key to match against packet.
 * @param priority Higher priority entries match first.
 */
void flowtable_entry_init(struct flowtable_entry *fte,
                          const struct flowtable_key *key,
                          const struct flowtable_key *mask,
                          uint16_t priority);

/*
 * Insert an entry into a flowtable.
 */
void flowtable_insert(struct flowtable *ft, struct flowtable_entry *fte);

/*
 * Remove an entry from a flowtable.
 */
void flowtable_remove(struct flowtable *ft, struct flowtable_entry *fte);

/*
 * Search for a matching entry in a flowtable.
 *
 * @param key Fields from the packet.
 */
struct flowtable_entry *flowtable_match(struct flowtable *ft,
                                        const struct flowtable_key *key);

#endif
