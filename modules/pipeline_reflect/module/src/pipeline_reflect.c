/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
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

#define AIM_LOG_MODULE_NAME pipeline_reflect
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

static uint64_t delay_ns;

static void
pipeline_reflect_init(const char *name)
{
    if (getenv("IVS_REFLECT_DELAY")) {
        delay_ns = atoi(getenv("IVS_REFLECT_DELAY"));
        AIM_LOG_INFO("Adding delay of %"PRIu64" ns");
    } else {
        delay_ns = 0;
    }
}

static void
pipeline_reflect_finish(void)
{
}

static uint64_t
monotonic_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return ((uint64_t)tp.tv_sec * 1000*1000*1000) + tp.tv_nsec;
}

indigo_error_t
pipeline_reflect_process(struct ind_ovs_parsed_key *key,
                         struct xbuf *stats,
                         struct action_context *actx)
{
    if (delay_ns > 0) {
        uint64_t end_time = monotonic_ns() + delay_ns;
        while (monotonic_ns() <= end_time);
    }

    action_output(actx, key->in_port);
    return INDIGO_ERROR_NONE;
}

static struct pipeline_ops pipeline_reflect_ops = {
    .init = pipeline_reflect_init,
    .finish = pipeline_reflect_finish,
    .process = pipeline_reflect_process,
};

void
__pipeline_reflect_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    pipeline_register("reflect", &pipeline_reflect_ops);
}
