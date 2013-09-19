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

/*
 * pipeline - Packet processing pipeline
 */

#ifndef PIPELINE_H
#define PIPELINE_H

#include <stdbool.h>
#include "indigo/error.h"

struct pipeline;
struct ind_ovs_fwd_result;
struct ind_ovs_cfr;

/*
 * Function provided to the pipeline to lookup in flowtables.
 */
typedef struct ind_ovs_flow_effects *(* pipeline_lookup_f)(
        int table_id, struct ind_ovs_cfr *cfr,
        struct ind_ovs_fwd_result *result, bool update_stats);

struct pipeline *pipeline_create(int openflow_version, pipeline_lookup_f lookup);
void pipeline_destroy(struct pipeline *pipeline);

/*
 * Send a packet through the pipeline.
 *
 * 'result' should be initialized with ind_ovs_fwd_result_init.
 */
indigo_error_t
pipeline_process(struct pipeline *pipeline,
                 struct ind_ovs_cfr *cfr,
                 struct ind_ovs_fwd_result *result);

#endif
