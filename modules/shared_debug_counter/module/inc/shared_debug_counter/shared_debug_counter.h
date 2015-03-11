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
 * This module is a wrapper around debug counters which places them in shared
 * memory. This is necessary for debug counter updates from upcall processes to
 * be persistent and visible to the controller.
 *
 * It's implemented by placing the debug counters in a special section, which
 * is aligned and padded to the page size. When shared_debug_counter_init is
 * called it replaces these pages (which were private mappings) with a shared
 * mapping. When a child process is forked it will be able to write to these
 * pages without triggering COW.
 *
 * One potential downside is that all upcall processes are contending for the
 * same cachelines when incrementing debug counters. If we find this is a real
 * performance problem then we could allocate a shared memory region per-process
 * and periodically synchronize them in the main process.
 */

#ifndef SHARED_DEBUG_COUNTER_H
#define SHARED_DEBUG_COUNTER_H

#include <debug_counter/debug_counter.h>

/* Modified from debug_counter.h */
#define SHARED_DEBUG_COUNTER(ident, name, description) \
    static __attribute__((section(".shared_debug_counter"))) debug_counter_t ident; \
    static void __attribute__((constructor)) ident ## _constructor(void) \
    { \
        debug_counter_register(&ident, name, description); \
    }

/* Must be called before any processes are forked */
void shared_debug_counter_init(void);

#endif
