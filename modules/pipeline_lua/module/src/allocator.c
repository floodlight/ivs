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
 * Bump allocator
 *
 * This allocator is used for safety, not speed. We don't want to give
 * Lua code pointers to the normal heap because it could save them
 * and use them later when they refer to a different object.
 *
 * Instead, we dedicate memory for communication with Lua. Even if
 * Lua code tries to access this memory after it's been freed, it
 * won't be able to read or write datastructures that it doesn't
 * already own. The corollary is that C code can't trust anything
 * it reads from this memory.
 *
 * The lifetime of these allocations is limited to a single "event",
 * whether it's a gentable operation, upcall processing, etc. This
 * assumption enables us to reset the heap all at once instead of
 * freeing allocations individually.
 */

#include <stdlib.h>
#include "pipeline_lua_int.h"

#define AIM_LOG_MODULE_NAME pipeline_lua
#include <AIM/aim_log.h>

/*
 * We only expect to need 2*64K for the worst case of the
 * bsn_lua_command_request message.
 */
#define ALLOCATOR_SIZE (1024*1024)

static char allocator_heap[ALLOCATOR_SIZE];
static uint32_t allocator_offset;

void *
pipeline_lua_allocator_alloc(uint32_t size)
{
    if (size > ALLOCATOR_SIZE || allocator_offset + size > ALLOCATOR_SIZE) {
        AIM_DIE("Exceeded Lua allocator maximum size");
    }

    void *ptr = allocator_heap + allocator_offset;
    allocator_offset += size;
    return ptr;
}

void *
pipeline_lua_allocator_dup(void *src, uint32_t size)
{
    void *dst = pipeline_lua_allocator_alloc(size);
    memcpy(dst, src, size);
    return dst;
}

void
pipeline_lua_allocator_reset(void)
{
    allocator_offset = 0;
}
