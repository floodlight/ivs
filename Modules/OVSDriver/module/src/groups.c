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

#include "ovs_driver_int.h"
#include <unistd.h>
#include <indigo/forwarding.h>

indigo_error_t
indigo_fwd_group_add(uint32_t id, uint8_t group_type, of_list_bucket_t *buckets)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

indigo_error_t
indigo_fwd_group_modify(uint32_t id, of_list_bucket_t *buckets)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

void
indigo_fwd_group_delete(uint32_t id)
{
}

void
indigo_fwd_group_stats_get(uint32_t id, of_group_stats_entry_t *entry)
{
}
