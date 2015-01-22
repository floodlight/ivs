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

#include "pipeline_lua_int.h"

/* The build system automatically picks up Lua files in this directory, but to
 * load them into the VM they need to be specified here */
#define BUILTIN_LUA \
    X(base) \
    X(actions) \
    X(xdr) \
    X(murmur) \
    X(hashtable)

#define BUILTIN_LUA_START(name) _binary_ ## name ## _lua_start
#define BUILTIN_LUA_END(name) _binary_ ## name ## _lua_end

#define X(name) \
    extern const char BUILTIN_LUA_START(name)[]; \
    extern const char BUILTIN_LUA_END(name)[];
BUILTIN_LUA
#undef X

const struct builtin_lua pipeline_lua_builtin_lua[] = {
#define X(name) { \
        AIM_STRINGIFY(name) ".lua", \
        BUILTIN_LUA_START(name), \
        BUILTIN_LUA_END(name), \
    },
    BUILTIN_LUA
#undef X
    { NULL, NULL, 0 }
};
