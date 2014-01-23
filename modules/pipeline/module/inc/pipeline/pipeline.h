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
#include <indigo/indigo.h>
#include <xbuf/xbuf.h>

struct pipeline_result;
struct ind_ovs_cfr;

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

struct pipeline_ops {
    void (*init)(const char *name);
    void (*finish)(void);
    indigo_error_t (*process)(struct ind_ovs_cfr *cfr, struct pipeline_result *result);
};

/*
 * Register a pipeline implementation
 *
 * 'name' must be unique.
 */
void pipeline_register(const char *name, const struct pipeline_ops *ops);

/*
 * Choose a pipeline implementation
 *
 * Returns an error and has no effect if 'name' is not a valid pipeline name.
 *
 * Cleans up the old pipeline and initializes the new one. This happens even if
 * 'name' matches the current pipeline.
 *
 * Initially no pipeline is current. Attempting to process packets will cause
 * an abort until this function is used to choose a pipeline.
 *
 * If name is NULL then the current pipeline is cleaned up and no new pipeline
 * is initialized.
 */
indigo_error_t pipeline_set(const char *name);

/*
 * Get the name of the current pipeline
 */
const char *pipeline_get(void);

/*
 * Get a list of supported pipelines
 */
void pipeline_list(of_desc_str_t **ret_pipelines, int *num_pipelines);

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
