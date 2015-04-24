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

#include "pipeline_lua_int.h"

#define AIM_LOG_MODULE_NAME pipeline_lua
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

void
pipeline_lua_log_verbose(const char *str)
{
    AIM_LOG_VERBOSE("%s", str);
}

void
pipeline_lua_log_info(const char *str)
{
    AIM_LOG_INFO("%s", str);
}

void
pipeline_lua_log_warn(const char *str)
{
    AIM_LOG_WARN("%s", str);
}

void
pipeline_lua_log_error(const char *str)
{
    AIM_LOG_ERROR("%s", str);
}
