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

#include <shared_debug_counter/shared_debug_counter.h>
#include <AIM/aim.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

#define AIM_LOG_MODULE_NAME shared_debug_counter
#include <AIM/aim_log.h>

void __attribute__((noinline))
shared_debug_counter_init(void)
{
    extern char shared_debug_counter_start[], shared_debug_counter_end[];
    int len = shared_debug_counter_end - shared_debug_counter_start;

    if (len == 0) {
        return;
    }

    void *copy = aim_memdup(shared_debug_counter_start, len);

    if (mmap(shared_debug_counter_start, len, PROT_READ|PROT_WRITE,
             MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) {
        AIM_DIE("mmap failed: %s", strerror(errno));
    }

    memcpy(shared_debug_counter_start, copy, len);
    aim_free(copy);
}
