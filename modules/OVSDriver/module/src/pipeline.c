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
#include <indigo/memory.h>

void
indigo_fwd_pipeline_get(of_desc_str_t pipeline)
{
    const char *name = pipeline_get();
    memset(pipeline, 0, sizeof(of_desc_str_t));
    strncpy(pipeline, name, sizeof(of_desc_str_t));
}

indigo_error_t
indigo_fwd_pipeline_set(of_desc_str_t pipeline)
{
    return pipeline_set(pipeline);
}

void
indigo_fwd_pipeline_stats_get(of_desc_str_t **pipelines, int *num_pipelines)
{
    pipeline_list(pipelines, num_pipelines);
}
