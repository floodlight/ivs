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
 * This module allows the user to see logs from the forwarding pipeline for a
 * subset of packets.
 */

#ifndef PACKET_TRACE_H
#define PACKET_TRACE_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <AIM/aim_bitmap.h>

void packet_trace_init(const char *name);

void packet_trace_begin(uint32_t in_port);
void packet_trace_end(void);
void packet_trace_internal(const char *fmt, va_list vargs);
void packet_trace_set_fd_bitmap(aim_bitmap_t *bitmap);

extern bool packet_trace_enabled;

static inline void
packet_trace(const char *fmt, ...)
{
    if (__builtin_expect(packet_trace_enabled, false)) {
        va_list vargs;
        va_start(vargs, fmt);
        packet_trace_internal(fmt, vargs);
        va_end(vargs);
    }
}

#endif
