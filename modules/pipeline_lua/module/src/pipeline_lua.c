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
#include <stdlib.h>

#include <ivs/ivs.h>
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <pthread.h>

#include "pipeline_lua_int.h"

#define AIM_LOG_MODULE_NAME pipeline_lua
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

/* Per-packet information shared with Lua */
struct context {
    struct xbuf *stats;
    struct action_context *actx;
    struct fields fields;
};

static void pipeline_lua_finish(void);

static lua_State *lua;
static pthread_mutex_t lua_lock = PTHREAD_MUTEX_INITIALIZER;
static struct context context;
static int process_ref;

static void
pipeline_lua_init(const char *name)
{
    pipeline_lua_code_gentable_init();

    lua = luaL_newstate();
    if (lua == NULL) {
        AIM_DIE("failed to allocate Lua state");
    }

    luaL_openlibs(lua);

    /* Give Lua a pointer to the static context struct */
    lua_pushlightuserdata(lua, &context);
    lua_setglobal(lua, "_context");

    /* Give Lua the names of all fields */
    lua_newtable(lua);
    int i = 0;
    while (pipeline_lua_field_names[i]) {
        lua_pushstring(lua, pipeline_lua_field_names[i]);
        lua_rawseti(lua, -2, i+1);
        i++;
    }
    lua_setglobal(lua, "field_names");

    lua_pushcfunction(lua, pipeline_lua_table_register);
    lua_setglobal(lua, "register_table");

    /*
     * We can't save a reference to ingress() because it will change when the
     * controller uploads new versions of code. Instead, we create a wrapper
     * function that does the global variable lookup to allow the JIT to
     * optimize it.
     */
    if (luaL_dostring(lua,
            "function ingress() end\n"
            "local function process()\n"
            "ingress()\n"
            "end\n"
            "return process\n") != 0) {
        AIM_DIE("Failed to load built-in Lua code");
    }

    /* Store a reference to process() so we can efficiently retrieve it */
    process_ref = luaL_ref(lua, LUA_REGISTRYINDEX);
}

static void
pipeline_lua_finish(void)
{
    lua_close(lua);
    lua = NULL;

    pipeline_lua_code_gentable_finish();
}

indigo_error_t
pipeline_lua_process(struct ind_ovs_parsed_key *key,
                     struct xbuf *stats,
                     struct action_context *actx)
{
    pthread_mutex_lock(&lua_lock);

    pipeline_lua_fields_from_key(key, &context.fields);
    context.stats = stats;
    context.actx = actx;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, process_ref);

    if (lua_pcall(lua, 0, 0, 0) != 0) {
        AIM_LOG_ERROR("Failed to execute script: %s", lua_tostring(lua, -1));
    }

    pthread_mutex_unlock(&lua_lock);

    return INDIGO_ERROR_NONE;
}

static struct pipeline_ops pipeline_lua_ops = {
    .init = pipeline_lua_init,
    .finish = pipeline_lua_finish,
    .process = pipeline_lua_process,
};

void
pipeline_lua_load_code(const char *filename, const uint8_t *data, uint32_t size)
{
    ind_ovs_fwd_write_lock();

    if (luaL_loadbuffer(lua, (char *)data, size, filename) != 0) {
        AIM_LOG_ERROR("Failed to load code: %s", lua_tostring(lua, -1));
        ind_ovs_fwd_write_unlock();
        return;
    }

    if (lua_pcall(lua, 0, 0, 0) != 0) {
        AIM_LOG_ERROR("Failed to execute code %s: %s", filename, lua_tostring(lua, -1));
    }

    ind_ovs_fwd_write_unlock();
}

void
__pipeline_lua_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    pipeline_register("lua", &pipeline_lua_ops);
}
