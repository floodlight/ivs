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
 * This module implements lazily aggregated stats. Multiple threads can
 * increment stats concurrently without bouncing cache lines between them.
 */
#ifndef STATS_H
#define STATS_H

#include <stdint.h>

struct stats {
   uint64_t packets;
   uint64_t bytes;
};

/*
 * Reference to an allocated stats slot
 *
 * Treat as private.
 */
struct stats_handle {
    uint32_t slot;
};

/*
 * A stats_writer is used to increment stats. Only a single thread may use a
 * particular stats_writer at a time, but multiple stats_writers can
 * concurrently increment the same stats slots.
 */
struct stats_writer;

/*
 * Allocate a stats slot
 *
 * Initializes 'handle'.
 */
void stats_alloc(struct stats_handle *handle);

/*
 * Free a stats slot
 */
void stats_free(struct stats_handle *handle);

/*
 * Increment stats
 */
void stats_inc(const struct stats_writer *stats_writer,
               const struct stats_handle *handle,
               uint64_t packets, uint64_t bytes);

/*
 * Retrieve stats
 *
 * Stores the result in 'result'.
 */
void stats_get(const struct stats_handle *handle, struct stats *result);

/*
 * Clear stats
 */
void stats_clear(struct stats_handle *handle);

/*
 * Create a stats_writer
 */
struct stats_writer *stats_writer_create(void);

/*
 * Destroy a stats_writer
 */
void stats_writer_destroy(struct stats_writer *stats_writer);

#endif
