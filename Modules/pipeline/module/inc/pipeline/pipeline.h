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

#include "indigo/error.h"

struct pipeline;
struct ind_ovs_parsed_key;
struct ind_ovs_fwd_result;

struct pipeline *pipeline_create(void);
void pipeline_destroy(struct pipeline *pipeline);

/*
 * Send a packet through the pipeline.
 *
 * 'result' should be initialized with ind_ovs_fwd_result_init.
 */
indigo_error_t
pipeline_process(struct pipeline *pipeline,
                 const struct ind_ovs_parsed_key *pkey,
                 struct ind_ovs_fwd_result *result);

#endif
