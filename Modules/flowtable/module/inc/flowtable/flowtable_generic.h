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
 * Hash-based flowtable generic.
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

#ifndef FLOWTABLE_GENERIC_H
#define FLOWTABLE_GENERIC_H
#include "flowtable/flowtable.h"
#include <AIM/aim_list.h>
#include <stdbool.h>

struct flowtable_generic;

/*
 * Create a flowtable generic.
 *
 * @param hash_mask The portion of the key to use for hashing. Flow masks that
 *                  are less specific than this use linear-search.
 */
struct flowtable_generic *flowtable_generic_create();

/*
 * Destroy a flowtable.
 *
 * All flow entries should have been removed.
 */
void flowtable_generic_destroy(struct flowtable_generic *ftg);

/*
 * Insert an entry into a flowtable generic.
 */
void flowtable_generic_insert(struct flowtable_generic *ftg, struct flowtable_entry *fte);

/*
 * Remove an entry from a flowtablei generic.
 */
void flowtable_generic_remove(struct flowtable_generic *ftg, struct flowtable_entry *fte);

/*
 * Search for a matching entry in a flowtable generic.
 *
 * @param key Fields from the packet.
 */
struct flowtable_entry *flowtable_generic_match(struct flowtable_generic *ftg,
                                        const struct flowtable_key *key);

#endif
