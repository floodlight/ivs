/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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
 * Wrapper around the stats module that keeps track of allocated handles so
 * they can be freed when the Lua VM is reset.
 */

#include <stats/stats.h>
#include <slot_allocator/slot_allocator.h>
#include <pipeline/pipeline.h>

#include "pipeline_lua_int.h"

#define AIM_LOG_MODULE_NAME pipeline_lua
#include <AIM/aim_log.h>

#define NUM_STATS 10000

static struct slot_allocator *stats_allocator;
static struct stats_handle stats[NUM_STATS];

void
pipeline_lua_stats_init(void)
{
    stats_allocator = slot_allocator_create(NUM_STATS);
    int i;
    for (i = 0; i < NUM_STATS; i++) {
        stats_alloc(&stats[i]);
    }
}

void
pipeline_lua_stats_finish(void)
{
    slot_allocator_destroy(stats_allocator);
    int i;
    for (i = 0; i < NUM_STATS; i++) {
        stats_free(&stats[i]);
    }
}

void
pipeline_lua_stats_reset(void)
{
    struct slot_allocator_iter iter;
    slot_allocator_iter_init(stats_allocator, &iter);

    uint32_t slot;
    while ((slot = slot_allocator_iter_next(&iter)) != SLOT_INVALID) {
        slot_allocator_free(stats_allocator, slot);
    }
}

/* Will return SLOT_INVALID if allocation fails */
uint32_t
pipeline_lua_stats_alloc(void)
{
    uint32_t slot = slot_allocator_alloc(stats_allocator);
    if (slot != SLOT_INVALID) {
        stats_clear(&stats[slot]);
    }
    return slot;
}

void
pipeline_lua_stats_free(uint32_t slot)
{
    if (slot < NUM_STATS) {
        slot_allocator_free(stats_allocator, slot);
    }
}

void
pipeline_lua_stats_append(struct xbuf *xbuf, uint32_t slot)
{
    if (slot < NUM_STATS && xbuf_length(xbuf) < 128) {
        pipeline_add_stats(xbuf, &stats[slot]);
    } else {
        AIM_LOG_WARN("Failed to append stats");
    }
}

void
pipeline_lua_stats_get(uint32_t slot, struct stats *result)
{
    if (slot < NUM_STATS) {
        stats_get(&stats[slot], result);
    } else {
        memset(result, 0xff, sizeof(*result));
    }
}
