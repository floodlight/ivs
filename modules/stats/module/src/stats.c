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
 * TODO per-thread stats writers
 */

#include <stats/stats.h>
#include <AIM/aim.h>

#define AIM_LOG_MODULE_NAME stats
#include <AIM/aim_log.h>

#define MAX_STATS 262144

struct stats_writer {
    struct stats *stats;
};

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT,
                      AIM_LOG_BITS_DEFAULT,
                      NULL, 0);
/*
 * Free slots are tracked in this stack
 */
static uint32_t *free_stack;
static uint32_t num_free;

/*
 * stats_writer shared among all threads (for now)
 */
static struct stats_writer *singleton_stats_writer;

void
__stats_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();

    free_stack = aim_zmalloc(sizeof(*free_stack) * MAX_STATS);

    /* Init the free stack in descending order */
    for (num_free = 0; num_free < MAX_STATS; num_free++) {
        free_stack[num_free] = MAX_STATS-num_free-1;
    }

    singleton_stats_writer = aim_zmalloc(sizeof(*singleton_stats_writer));
    singleton_stats_writer->stats = aim_malloc(sizeof(struct stats) * MAX_STATS);
}

void
stats_alloc(struct stats_handle *handle)
{
    AIM_TRUE_OR_DIE(num_free > 0);
    handle->slot = free_stack[--num_free];
    struct stats *stats = &singleton_stats_writer->stats[handle->slot];
    stats->bytes = 0;
    stats->packets = 0;
    AIM_LOG_TRACE("allocated stats slot %u", handle->slot);
}

void
stats_free(struct stats_handle *handle)
{
    AIM_TRUE_OR_DIE(num_free < MAX_STATS);
    free_stack[num_free++] = handle->slot;
    AIM_LOG_TRACE("freed stats slot %u", handle->slot);
}

void
stats_inc(const struct stats_writer *stats_writer,
          const struct stats_handle *handle,
          uint64_t packets, uint64_t bytes)
{
    struct stats *stats = &stats_writer->stats[handle->slot];
    __sync_fetch_and_add(&stats->packets, packets);
    __sync_fetch_and_add(&stats->bytes, bytes);
    AIM_LOG_TRACE("increment stats slot %u by %u/%u", handle->slot, (uint32_t)packets, (uint32_t)bytes);
}

void
stats_get(const struct stats_handle *handle, struct stats *result)
{
    *result = singleton_stats_writer->stats[handle->slot];
}

struct stats_writer *
stats_writer_create(void)
{
    return singleton_stats_writer;
}

void
stats_writer_destroy(struct stats_writer *stats_writer)
{
}
