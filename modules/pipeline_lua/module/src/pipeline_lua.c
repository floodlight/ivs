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
#include <string.h>

#include <ivs/ivs.h>
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <pthread.h>
#include <murmur/murmur.h>

#include "pipeline_lua_int.h"

#define AIM_LOG_MODULE_NAME pipeline_lua
#include <AIM/aim_log.h>

#define MAX_UPLOAD_SIZE (2*1024*2014)

/* Per-packet information shared with Lua */
struct context {
    bool valid;
    struct xbuf *stats;
    struct action_context *actx;
    struct fields fields;
};

struct upload_chunk {
    of_str64_t filename;
    uint32_t size;
    char data[];
};

static void pipeline_lua_finish(void);
static indigo_core_listener_result_t message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg);
static void commit_lua_upload(indigo_cxn_id_t cxn_id, of_object_t *msg);
static void cleanup_lua_upload(void);
static void reset_lua(void);

static lua_State *lua;
static struct context context;
static int process_ref;
static int command_ref;

/* List of struct upload_chunk */
struct xbuf upload_chunks;

/* Offset of the last chunk in the list */
uint32_t last_uploaded_chunk_offset;

/* Hash of the currently running code */
uint32_t checksum;

/* Overall minimum average interval between packet-ins (in us) */
#define PKTIN_INTERVAL 3000

/* Overall packet-in burstiness tolerance. */
#define PKTIN_BURST_SIZE 32

static struct ind_ovs_pktin_socket pktin_soc;

static void
pipeline_lua_init(const char *name)
{
    indigo_core_message_listener_register(message_listener);
    xbuf_init(&upload_chunks);
    pipeline_lua_stats_init();

    ind_ovs_pktin_socket_register(&pktin_soc, NULL, PKTIN_INTERVAL,
                                  PKTIN_BURST_SIZE);

    reset_lua();
}

static void
reset_lua(void)
{
    if (lua) {
        pipeline_lua_table_reset();
        pipeline_lua_stats_reset();
        lua_close(lua);
    }

    lua = luaL_newstate();
    if (lua == NULL) {
        AIM_DIE("failed to allocate Lua state");
    }

    luaL_openlibs(lua);

    /* Give Lua a pointer to the static context struct */
    context.valid = false;
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

    const struct builtin_lua *builtin_lua;
    for (builtin_lua = &pipeline_lua_builtin_lua[0];
            builtin_lua->name; builtin_lua++) {
        AIM_LOG_VERBOSE("Loading builtin Lua code %s", builtin_lua->name);

        char name[64];
        snprintf(name, sizeof(name), "=%s", builtin_lua->name);

        /* Parse */
        if (luaL_loadbuffer(lua, builtin_lua->start,
                builtin_lua->end-builtin_lua->start,
                name) != 0) {
            AIM_DIE("Failed to load built-in Lua code %s: %s",
                    builtin_lua->name, lua_tostring(lua, -1));
        }

        /* Execute */
        if (lua_pcall(lua, 0, 0, 0) != 0) {
            AIM_DIE("Failed to execute built-in Lua code %s: %s",
                    builtin_lua->name, lua_tostring(lua, -1));
        }
    }

    /* Store a reference to process() so we can efficiently retrieve it */
    lua_getglobal(lua, "process");
    AIM_ASSERT(lua_isfunction(lua, -1));
    process_ref = luaL_ref(lua, LUA_REGISTRYINDEX);

    /* Store a reference to command() so we can efficiently retrieve it */
    lua_getglobal(lua, "command");
    AIM_ASSERT(lua_isfunction(lua, -1));
    command_ref = luaL_ref(lua, LUA_REGISTRYINDEX);

    lua_pushinteger(lua, ind_ovs_pktin_socket_netlink_port(&pktin_soc));
    lua_setglobal(lua, "netlink_port");
}

static void
pipeline_lua_finish(void)
{
    lua_close(lua);
    pipeline_lua_table_reset();
    pipeline_lua_stats_finish();
    lua = NULL;

    indigo_core_message_listener_unregister(message_listener);
    cleanup_lua_upload();
    xbuf_cleanup(&upload_chunks);
    ind_ovs_pktin_socket_unregister(&pktin_soc);
}

indigo_error_t
pipeline_lua_process(struct ind_ovs_parsed_key *key,
                     struct ind_ovs_parsed_key *mask,
                     struct xbuf *stats,
                     struct action_context *actx)
{
    uint64_t populated = mask->populated;
    memset(mask, 0xff, sizeof(*mask));
    mask->populated = populated;

    pipeline_lua_fields_from_key(key, &context.fields);
    context.stats = stats;
    context.actx = actx;
    context.valid = true;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, process_ref);

    if (lua_pcall(lua, 0, 0, 0) != 0) {
        AIM_LOG_ERROR("Failed to execute script: %s", lua_tostring(lua, -1));
    }

    context.valid = false;

    return INDIGO_ERROR_NONE;
}

static struct pipeline_ops pipeline_lua_ops = {
    .init = pipeline_lua_init,
    .finish = pipeline_lua_finish,
    .process = pipeline_lua_process,
};

static void
handle_lua_upload(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    of_octets_t data;
    uint16_t flags;
    of_str64_t filename;
    of_bsn_lua_upload_data_get(msg, &data);
    of_bsn_lua_upload_flags_get(msg, &flags);
    of_bsn_lua_upload_filename_get(msg, &filename);

    /* Ensure filename is null terminated */
    filename[63] = 0;

    if (xbuf_length(&upload_chunks) + sizeof(struct upload_chunk) + data.bytes > MAX_UPLOAD_SIZE) {
        AIM_LOG_ERROR("Attempted to upload more than %u bytes", MAX_UPLOAD_SIZE);
        indigo_cxn_send_error_reply(
            cxn_id, msg, OF_ERROR_TYPE_BAD_REQUEST, OF_REQUEST_FAILED_EPERM);
        cleanup_lua_upload();
        return;
    }

    /* If the list isn't empty, get a pointer to the last uploaded chunk */
    struct upload_chunk *prev = NULL;
    if (xbuf_length(&upload_chunks) > 0) {
        AIM_ASSERT(last_uploaded_chunk_offset < xbuf_length(&upload_chunks));
        prev = xbuf_data(&upload_chunks) + last_uploaded_chunk_offset;
    }

    if (prev && !memcmp(filename, prev->filename, sizeof(filename))) {
        /* Concatenate consecutive messages with the same filename */
        prev->size += data.bytes;
        xbuf_append(&upload_chunks, (char *)data.data, data.bytes);

        AIM_LOG_VERBOSE("Appended to Lua chunk %s, now %u bytes", prev->filename, prev->size);
    } else if (data.bytes > 0) {
        last_uploaded_chunk_offset = xbuf_length(&upload_chunks);

        struct upload_chunk *chunk = xbuf_reserve(&upload_chunks, sizeof(*chunk) + data.bytes);
        chunk->size = data.bytes;
        memcpy(chunk->filename, filename, sizeof(of_str64_t));
        memcpy(chunk->data, data.data, data.bytes);

        AIM_LOG_VERBOSE("Uploaded Lua chunk %s, %u bytes", chunk->filename, chunk->size);
    }

    if (!(flags & OFP_BSN_LUA_UPLOAD_MORE)) {
        commit_lua_upload(cxn_id, msg);
    }
}

static void
commit_lua_upload(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    uint16_t flags;
    of_bsn_lua_upload_flags_get(msg, &flags);

    /* TODO use stronger hash function */
    uint32_t new_checksum = murmur_hash(xbuf_data(&upload_chunks),
                                        xbuf_length(&upload_chunks),
                                        0);
    if (!(flags & OFP_BSN_LUA_UPLOAD_FORCE) && checksum == new_checksum) {
        AIM_LOG_VERBOSE("Skipping Lua commit, checksums match");
        goto cleanup;
    }

    checksum = 0;

    reset_lua();

    uint32_t offset = 0;
    while (offset < xbuf_length(&upload_chunks)) {
        struct upload_chunk *chunk = xbuf_data(&upload_chunks) + offset;
        offset += sizeof(*chunk) + chunk->size;

        AIM_LOG_VERBOSE("Loading Lua chunk %s, %u bytes", chunk->filename, chunk->size);

        char name[64];
        snprintf(name, sizeof(name), "=%s", chunk->filename);

        if (luaL_loadbuffer(lua, chunk->data, chunk->size, name) != 0) {
            AIM_LOG_ERROR("Failed to load code: %s", lua_tostring(lua, -1));
            indigo_cxn_send_error_reply(
                cxn_id, msg, OF_ERROR_TYPE_BAD_REQUEST, OF_REQUEST_FAILED_EPERM);
            goto cleanup;
        }

        /* Set the environment of the new chunk to the sandbox */
        lua_getglobal(lua, "sandbox");
        lua_setfenv(lua, -2);

        if (lua_pcall(lua, 0, 1, 0) != 0) {
            AIM_LOG_ERROR("Failed to execute code %s: %s", chunk->filename, lua_tostring(lua, -1));
            indigo_cxn_send_error_reply(
                cxn_id, msg, OF_ERROR_TYPE_BAD_REQUEST, OF_REQUEST_FAILED_EPERM);
            goto cleanup;
        }

        /* Save the return value in the "modules" table, used by require */
        char *module_name = aim_strdup(chunk->filename);
        char *dot = strrchr(module_name, '.');
        if (dot) *dot = 0; /* strip file extension */
        lua_getglobal(lua, "modules");
        lua_pushstring(lua, module_name);
        lua_pushvalue(lua, -3); /* return value from pcall */
        lua_rawset(lua, -3); /* modules[filename] = return_value */
        lua_pop(lua, 2); /* pop modules and return value */
        free(module_name);
    }

    checksum = new_checksum;

cleanup:
    cleanup_lua_upload();
    return;
}

static void
cleanup_lua_upload(void)
{
    xbuf_reset(&upload_chunks);
}

static void
handle_lua_command_request(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    const int max_reply_size = UINT16_MAX -
        of_object_fixed_len[msg->version][OF_BSN_LUA_COMMAND_REPLY];
    uint32_t xid;
    of_octets_t request_data;
    of_bsn_lua_command_request_xid_get(msg, &xid);
    of_bsn_lua_command_request_data_get(msg, &request_data);

    pipeline_lua_allocator_reset();
    void *request_buf = pipeline_lua_allocator_dup(request_data.data, request_data.bytes);
    void *reply_buf = pipeline_lua_allocator_alloc(max_reply_size);

    lua_rawgeti(lua, LUA_REGISTRYINDEX, command_ref);
    lua_pushlightuserdata(lua, request_buf);
    lua_pushinteger(lua, request_data.bytes);
    lua_pushlightuserdata(lua, reply_buf);
    lua_pushinteger(lua, max_reply_size);

    if (lua_pcall(lua, 4, 1, 0) != 0) {
        AIM_LOG_ERROR("Failed to execute command xid=%#x: %s", xid, lua_tostring(lua, -1));
        indigo_cxn_send_error_reply(
            cxn_id, msg, OF_ERROR_TYPE_BAD_REQUEST, OF_REQUEST_FAILED_EPERM);
        return;
    }

    int reply_size = lua_tointeger(lua, 0);
    AIM_TRUE_OR_DIE(reply_size >= 0 && reply_size < max_reply_size);
    lua_settop(lua, 0);

    of_object_t *reply = of_bsn_lua_command_reply_new(msg->version);
    of_bsn_lua_command_reply_xid_set(reply, xid);
    of_octets_t reply_data = { .data = reply_buf, .bytes = reply_size };
    if (of_bsn_lua_command_reply_data_set(reply, &reply_data) < 0) {
        AIM_DIE("Unexpectedly failed to set data in of_bsn_lua_command_reply");
    }

    indigo_cxn_send_controller_message(cxn_id, reply);
}

static indigo_core_listener_result_t
message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    switch (msg->object_id) {
    case OF_BSN_LUA_UPLOAD:
        handle_lua_upload(cxn_id, msg);
        return INDIGO_CORE_LISTENER_RESULT_DROP;

    case OF_BSN_LUA_COMMAND_REQUEST:
        handle_lua_command_request(cxn_id, msg);
        return INDIGO_CORE_LISTENER_RESULT_DROP;

    default:
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
}

void
__pipeline_lua_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    pipeline_register("lua", &pipeline_lua_ops);
}
