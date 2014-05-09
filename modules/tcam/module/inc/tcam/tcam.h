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

/*
 * Software TCAM
 *
 * This datastructure supports matching an arbitrarily-sized key against
 * a set of keys and masks. Where the corresponding mask bit is zero,
 * the key and entry do not need to match. The highest priority matching
 * entry will be returned.
 *
 * Matching performance is proportional to the number of unique masks times
 * the size of the key.
 */

#ifndef TCAM_H
#define TCAM_H

#include <AIM/aim_list.h>
#include <stdbool.h>

struct tcam;

/*
 * An entry in a tcam.
 *
 * This struct is intended to be embedded in a containing object.
 *
 * It must not currently be in a tcam when the containing object
 * is freed.
 *
 * It should be treated as opaque. It is initialized by tcam_insert.
 */
struct tcam_entry {
    struct tcam_entry *next;
    uint32_t hash;
    uint16_t priority;
    void *key;
    void *mask;
};

/*
 * Create a tcam
 *
 * @param key_size Size in bytes of the key
 * @param salt Random number to prevent hash-collision attacks
 */
struct tcam *tcam_create(uint16_t key_size, uint32_t salt);

/*
 * Destroy a tcam.
 *
 * All entries should have been removed.
 */
void tcam_destroy(struct tcam *tcam);

/*
 * Insert an entry into a tcam.
 *
 * @param key Field values. Must be zero where mask is zero (bitwise).
 * @param mask Portion of key to match against packet.
 * @param priority Higher priority entries match first.
 */
void tcam_insert(struct tcam *tcam,
                 struct tcam_entry *entry,
                 const void *key,
                 const void *mask,
                 uint16_t priority);

/*
 * Remove an entry from a tcam.
 */
void tcam_remove(struct tcam *tcam, struct tcam_entry *entry);

/*
 * Search for a matching entry in a tcam.
 *
 * @param key Fields from the packet.
 */
struct tcam_entry *tcam_match(struct tcam *tcam, const void *key);

#endif
