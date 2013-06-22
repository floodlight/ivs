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
 * Key for the flowtable generic hash table is the mask of the flow entry.
 * Insertion of the new flow entry need fist level look up in the flowtable
 * generic and second lookup in the flowtable hash.
 *
 * In caseof match on flow key, highest priority flow table entry from all
 * the flowtables will be returned.
 */

#ifndef FLOWTABLE_GENERIC_H
#define FLOWTABLE_GENERIC_H
#include "flowtable/flowtable.h"
#include <AIM/aim_list.h>
#include <stdbool.h>

struct flowtable_generic;

/*
 * Create a flowtable generic.
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
