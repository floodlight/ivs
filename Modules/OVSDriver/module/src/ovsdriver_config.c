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

/**************************************************************************//**
 * 
 * 
 * 
 *****************************************************************************/
#include <OVSDriver/ovsdriver_config.h>


/* <auto.start.cdefs(OVSDRIVER_CONFIG_HEADER).source> */
#define __ovsdriver_config_STRINGIFY_NAME(_x) #_x
#define __ovsdriver_config_STRINGIFY_VALUE(_x) __ovsdriver_config_STRINGIFY_NAME(_x)
ovsdriver_config_settings_t ovsdriver_config_settings[] =
{
#ifdef OVSDRIVER_CONFIG_INCLUDE_LOGGING
    { __ovsdriver_config_STRINGIFY_NAME(OVSDRIVER_CONFIG_INCLUDE_LOGGING), __ovsdriver_config_STRINGIFY_VALUE(OVSDRIVER_CONFIG_INCLUDE_LOGGING) },
#else
{ OVSDRIVER_CONFIG_INCLUDE_LOGGING(__ovsdriver_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OVSDRIVER_CONFIG_LOG_OPTIONS_DEFAULT
    { __ovsdriver_config_STRINGIFY_NAME(OVSDRIVER_CONFIG_LOG_OPTIONS_DEFAULT), __ovsdriver_config_STRINGIFY_VALUE(OVSDRIVER_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ OVSDRIVER_CONFIG_LOG_OPTIONS_DEFAULT(__ovsdriver_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OVSDRIVER_CONFIG_LOG_BITS_DEFAULT
    { __ovsdriver_config_STRINGIFY_NAME(OVSDRIVER_CONFIG_LOG_BITS_DEFAULT), __ovsdriver_config_STRINGIFY_VALUE(OVSDRIVER_CONFIG_LOG_BITS_DEFAULT) },
#else
{ OVSDRIVER_CONFIG_LOG_BITS_DEFAULT(__ovsdriver_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OVSDRIVER_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __ovsdriver_config_STRINGIFY_NAME(OVSDRIVER_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __ovsdriver_config_STRINGIFY_VALUE(OVSDRIVER_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ OVSDRIVER_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__ovsdriver_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OVSDRIVER_CONFIG_PORTING_STDLIB
    { __ovsdriver_config_STRINGIFY_NAME(OVSDRIVER_CONFIG_PORTING_STDLIB), __ovsdriver_config_STRINGIFY_VALUE(OVSDRIVER_CONFIG_PORTING_STDLIB) },
#else
{ OVSDRIVER_CONFIG_PORTING_STDLIB(__ovsdriver_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OVSDRIVER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __ovsdriver_config_STRINGIFY_NAME(OVSDRIVER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __ovsdriver_config_STRINGIFY_VALUE(OVSDRIVER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ OVSDRIVER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__ovsdriver_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef OVSDRIVER_CONFIG_INCLUDE_UCLI
    { __ovsdriver_config_STRINGIFY_NAME(OVSDRIVER_CONFIG_INCLUDE_UCLI), __ovsdriver_config_STRINGIFY_VALUE(OVSDRIVER_CONFIG_INCLUDE_UCLI) },
#else
{ OVSDRIVER_CONFIG_INCLUDE_UCLI(__ovsdriver_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __ovsdriver_config_STRINGIFY_VALUE
#undef __ovsdriver_config_STRINGIFY_NAME

const char*
ovsdriver_config_lookup(const char* setting)
{
    int i;
    for(i = 0; ovsdriver_config_settings[i].name; i++) {
        if(strcmp(ovsdriver_config_settings[i].name, setting)) {
            return ovsdriver_config_settings[i].value;
        }
    }
    return NULL;
}

int
ovsdriver_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; ovsdriver_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", ovsdriver_config_settings[i].name, ovsdriver_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(OVSDRIVER_CONFIG_HEADER).source> */

