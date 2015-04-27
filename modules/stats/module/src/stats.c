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

#include <stats/stats.h>
#include <AIM/aim.h>
#include <AIM/aim_list.h>
#include <sys/mman.h>
#include <errno.h>

#define AIM_LOG_MODULE_NAME stats
#include <AIM/aim_log.h>

#define MAX_STATS 262144

struct stats_writer {
    list_links_t links;
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

/* List of all stats_writers */
static list_head_t stats_writers;

void
__stats_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();

    free_stack = aim_zmalloc(sizeof(*free_stack) * MAX_STATS);

    /* Init the free stack in descending order */
    for (num_free = 0; num_free < MAX_STATS; num_free++) {
        free_stack[num_free] = MAX_STATS-num_free-1;
    }

    list_init(&stats_writers);
}

void
stats_alloc(struct stats_handle *handle)
{
    AIM_TRUE_OR_DIE(num_free > 0);
    handle->slot = free_stack[--num_free];
    stats_clear(handle);
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
    stats->packets += packets;
    stats->bytes += bytes;
    AIM_LOG_TRACE("increment stats slot %u by %u/%u", handle->slot, (uint32_t)packets, (uint32_t)bytes);
}

void
stats_get(const struct stats_handle *handle, struct stats *result)
{
    result->bytes = 0;
    result->packets = 0;

    list_links_t *cur;
    LIST_FOREACH(&stats_writers, cur) {
        struct stats_writer *stats_writer = container_of(cur, links, struct stats_writer);
        struct stats *stats = &stats_writer->stats[handle->slot];
        result->bytes += stats->bytes;
        result->packets += stats->packets;
    }
}

void
stats_clear(struct stats_handle *handle)
{
    list_links_t *cur;
    LIST_FOREACH(&stats_writers, cur) {
        struct stats_writer *stats_writer = container_of(cur, links, struct stats_writer);
        struct stats *stats = &stats_writer->stats[handle->slot];
        stats->bytes = 0;
        stats->packets = 0;
    }
}

struct stats_writer *
stats_writer_create(void)
{
    struct stats_writer *stats_writer = aim_zmalloc(sizeof(*stats_writer));
    stats_writer->stats = mmap(NULL, MAX_STATS*sizeof(struct stats),
                               PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
    if (stats_writer->stats == MAP_FAILED) {
        AIM_DIE("Failed to allocate stats writer: %s", strerror(errno));
    }
    list_push(&stats_writers, &stats_writer->links);
    return stats_writer;
}

void
stats_writer_destroy(struct stats_writer *stats_writer)
{
    list_remove(&stats_writer->links);
    munmap(stats_writer->stats, MAX_STATS*sizeof(struct stats));
    aim_free(stats_writer);
}
