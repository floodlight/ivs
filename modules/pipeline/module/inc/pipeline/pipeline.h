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
#include <action/action.h>

struct ind_ovs_parsed_key;

struct pipeline_ops {
    void (*init)(const char *name);
    void (*finish)(void);
    indigo_error_t (*process)(
        struct ind_ovs_parsed_key *key,
        struct xbuf *stats,
        struct action_context *actx);
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
 * 'stats' should be an initialized, empty xbuf. It will be be filled with
 * pointers to struct ind_ovs_flow_stats. These stats objects may belong to
 * flows or tables (and in the future meters or groups). For example, every
 * table a packet matched in will have its matched_stats field added here.
 *
 * 'actx' should be an initialized action_context.
 */
indigo_error_t
pipeline_process(struct ind_ovs_parsed_key *key,
                 struct xbuf *stats,
                 struct action_context *actx);

#endif
