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
 * @file
 * @brief OVSDriver Porting Macros.
 * 
 * @addtogroup ovsdriver_porting
 * @{
 * 
 *****************************************************************************/
#ifndef __OVSDRIVER_PORTING_H__
#define __OVSDRIVER_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if OVSDRIVER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef OVSDRIVER_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define OVSDRIVER_MALLOC GLOBAL_MALLOC
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_MALLOC malloc
    #else
        #error The macro OVSDRIVER_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef OVSDRIVER_FREE
    #if defined(GLOBAL_FREE)
        #define OVSDRIVER_FREE GLOBAL_FREE
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_FREE free
    #else
        #error The macro OVSDRIVER_FREE is required but cannot be defined.
    #endif
#endif

#ifndef OVSDRIVER_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define OVSDRIVER_MEMSET GLOBAL_MEMSET
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_MEMSET memset
    #else
        #error The macro OVSDRIVER_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef OVSDRIVER_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define OVSDRIVER_MEMCPY GLOBAL_MEMCPY
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_MEMCPY memcpy
    #else
        #error The macro OVSDRIVER_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef OVSDRIVER_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define OVSDRIVER_STRNCPY GLOBAL_STRNCPY
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_STRNCPY strncpy
    #else
        #error The macro OVSDRIVER_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef OVSDRIVER_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define OVSDRIVER_VSNPRINTF GLOBAL_VSNPRINTF
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_VSNPRINTF vsnprintf
    #else
        #error The macro OVSDRIVER_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef OVSDRIVER_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define OVSDRIVER_SNPRINTF GLOBAL_SNPRINTF
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_SNPRINTF snprintf
    #else
        #error The macro OVSDRIVER_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef OVSDRIVER_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define OVSDRIVER_STRLEN GLOBAL_STRLEN
    #elif OVSDRIVER_CONFIG_PORTING_STDLIB == 1
        #define OVSDRIVER_STRLEN strlen
    #else
        #error The macro OVSDRIVER_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __OVSDRIVER_PORTING_H__ */
/* @} */
