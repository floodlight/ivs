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
#include <xbuf/xbuf.h>

struct pipeline_result;
struct ind_ovs_cfr;

/*
 * Function provided to the pipeline to lookup in flowtables.
 */
typedef struct ind_ovs_flow_effects *(* pipeline_lookup_f)(
        int table_id, struct ind_ovs_cfr *cfr,
        struct xbuf *stats);

/*
 * Result of the forwarding pipeline (ind_ovs_pipeline_process)
 *
 * See pipeline_result_{init,reset,cleanup}.
 */
struct pipeline_result {
    /*
     * List of IVS actions.
     */
    struct xbuf actions;

    /*
     * This xbuf contains an array of pointers to struct ind_ovs_flow_stats.
     *
     * These stats objects may belong to flows or tables (and in the future
     * meters or groups). For example, every table a packet matched in will
     * have its matched_stats field added here.
     */
    struct xbuf stats;
};

void pipeline_init(int openflow_version, pipeline_lookup_f lookup);
void pipeline_finish(void);

/*
 * Send a packet through the pipeline.
 *
 * 'result' should be initialized with pipeline_result_init.
 */
indigo_error_t
pipeline_process(struct ind_ovs_cfr *cfr,
                 struct pipeline_result *result);

/* Operations on a struct pipeline_result */
void pipeline_result_init(struct pipeline_result *result);
void pipeline_result_reset(struct pipeline_result *result);
void pipeline_result_cleanup(struct pipeline_result *result);

#endif
