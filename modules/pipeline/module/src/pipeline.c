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

#include <pipeline/pipeline.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <ivs/ivs.h>
#include <ivs/actions.h>
#include <loci/loci.h>

#define AIM_LOG_MODULE_NAME pipeline
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

#define MAX_PIPELINES 16

struct pipeline {
    const char *name;
    const struct pipeline_ops *ops;
};

static struct pipeline pipelines[MAX_PIPELINES];

static struct pipeline *current_pipeline;

void
pipeline_register(const char *name, const struct pipeline_ops *ops)
{
    int i;
    for (i = 0; i < MAX_PIPELINES; i++) {
        struct pipeline *p = &pipelines[i];
        if (p->name == NULL) {
            p->name = name;
            p->ops = ops;
            return;
        }
    }

    AIM_DIE("attempted to register more than %d pipelines", MAX_PIPELINES);
}

indigo_error_t
pipeline_set(const char *name)
{
    struct pipeline *new_pipeline = NULL;

    if (name != NULL) {
        int i;
        for (i = 0; i < MAX_PIPELINES; i++) {
            struct pipeline *p = &pipelines[i];
            if (p->name != NULL && !strcmp(p->name, name)) {
                new_pipeline = p;
            }
        }

        if (new_pipeline == NULL) {
            return INDIGO_ERROR_NOT_FOUND;
        }
    }

    if (current_pipeline != NULL) {
        current_pipeline->ops->finish();
        current_pipeline = NULL;
    }

    if (name == NULL) {
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_INFO("Initializing pipeline %s", name);
    new_pipeline->ops->init(name);
    current_pipeline = new_pipeline;
    return INDIGO_ERROR_NONE;
}

indigo_error_t
pipeline_process(struct ind_ovs_cfr *cfr,
                 struct pipeline_result *result)
{
    AIM_TRUE_OR_DIE(current_pipeline != NULL);
    return current_pipeline->ops->process(cfr, result);
}

void
pipeline_result_init(struct pipeline_result *result)
{
    xbuf_init(&result->actions);
    xbuf_init(&result->stats);
}

/* Reinitialize without reallocating memory */
void
pipeline_result_reset(struct pipeline_result *result)
{
    xbuf_reset(&result->actions);
    xbuf_reset(&result->stats);
}

void
pipeline_result_cleanup(struct pipeline_result *result)
{
    xbuf_cleanup(&result->actions);
    xbuf_cleanup(&result->stats);
}
