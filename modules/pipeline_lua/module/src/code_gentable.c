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

/*
 * A gentable is limited to ~ 64 KB of data per entry, so it's not ideal for
 * uploading files.
 */

#include <indigo/of_state_manager.h>
#include <AIM/aim_list.h>
#include <AIM/aim.h>

#include "pipeline_lua_int.h"

#define AIM_LOG_MODULE_NAME pipeline_lua
#include <AIM/aim_log.h>

struct code_entry_key {
    char name[128];
};

struct code_entry_value {
    uint8_t *data;
    uint32_t size;
};

struct code_entry {
    struct code_entry_key key;
    struct code_entry_value value;
};

static indigo_core_gentable_t *code_gentable;
static const indigo_core_gentable_ops_t code_ops;

void
pipeline_lua_code_gentable_init(void)
{
    indigo_core_gentable_register("pipeline_lua_code", &code_ops, NULL, 16, 16,
                                  &code_gentable);
}

void
pipeline_lua_code_gentable_finish(void)
{
    indigo_core_gentable_unregister(code_gentable);
}

/* code table operations */

static indigo_error_t
code_parse_key(of_list_bsn_tlv_t *tlvs, struct code_entry_key *key)
{
    of_object_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_NAME) {
        of_octets_t name;
        of_bsn_tlv_name_value_get(&tlv, &name);
        if (name.bytes >= sizeof(key->name)) {
            AIM_LOG_ERROR("name key TLV too long");
            return INDIGO_ERROR_PARAM;
        }
        strncpy(key->name, (char *)name.data, name.bytes);
    } else {
        AIM_LOG_ERROR("expected name key TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
code_parse_value(of_list_bsn_tlv_t *tlvs, struct code_entry_value *value)
{
    of_object_t tlv;

    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_DATA) {
        of_octets_t data;
        of_bsn_tlv_data_value_get(&tlv, &data);
        value->data = aim_memdup(data.data, data.bytes);
        value->size = data.bytes;
    } else {
        AIM_LOG_ERROR("expected data value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
code_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct code_entry_key key;
    struct code_entry_value value;
    struct code_entry *entry;

    rv = code_parse_key(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = code_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    AIM_LOG_VERBOSE("uploaded %s, %u bytes", key.name, value.size);

    pipeline_lua_load_code(entry->key.name, entry->value.data, entry->value.size);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
code_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct code_entry_value value;
    struct code_entry *entry = entry_priv;

    rv = code_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    entry->value = value;

    AIM_LOG_VERBOSE("uploaded %s, %u bytes", entry->key.name, entry->value.size);

    pipeline_lua_load_code(entry->key.name, entry->value.data, entry->value.size);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
code_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct code_entry *entry = entry_priv;
    aim_free(entry->value.data);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
code_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
}

static const indigo_core_gentable_ops_t code_ops = {
    .add2 = code_add,
    .modify2 = code_modify,
    .del2 = code_delete,
    .get_stats = code_get_stats,
};
