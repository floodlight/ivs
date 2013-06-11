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
 * l2table - Efficiently map MAC/VLAN to metadata and out port.
 */

#ifndef L2TABLE_H
#define L2TABLE_H

#include <AIM/aim.h>

#define L2TABLE_MAC_LEN 6

struct l2table;

/**
 * Create a l2table
 *
 * @param salt  Random number used to seed hash function.
 */
struct l2table *l2table_create(uint32_t salt);

/**
 * Destroy a l2table
 */
void l2table_destroy(struct l2table *t);

/**
 * Lookup a MAC/VLAN pair
 *
 * Returns the associated output port and metadata.
 *
 * Returns AIM_ERROR_NOT_FOUND if the entry does not exist.
 */
aim_error_t l2table_lookup(struct l2table *t,
                           const uint8_t mac[L2TABLE_MAC_LEN],
                           uint16_t vlan_id,
                           uint32_t *out_port,
                           uint32_t *metadata);

/**
 * Insert an entry
 *
 * Returns AIM_ERROR_PARAM if the entry already exists.
 */
aim_error_t l2table_insert(struct l2table *t,
                           const uint8_t mac[L2TABLE_MAC_LEN],
                           uint16_t vlan_id,
                           uint32_t out_port,
                           uint32_t metadata);

/**
 * Remove an entry
 *
 * Returns AIM_ERROR_NOT_FOUND if the entry does not exist.
 */
aim_error_t l2table_remove(struct l2table *t,
                           const uint8_t mac[L2TABLE_MAC_LEN],
                           uint16_t vlan_id);

#endif
