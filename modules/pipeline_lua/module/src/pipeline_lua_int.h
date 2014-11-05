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

#ifndef PIPELINE_LUA_INT_H
#define PIPELINE_LUA_INT_H

#include <ivs/ivs.h>

#define FIELDS \
    field(in_port) \
    field(eth_dst_lo) \
    field(eth_dst_hi) \
    field(eth_src_lo) \
    field(eth_src_hi) \
    field(eth_type) \
    field(vlan_vid) \
    field(vlan_pcp) \
    field(ip_dscp) \
    field(ip_ecn) \
    field(ip_proto) \
    field(ipv4_src) \
    field(ipv4_dst) \
    field(tp_src) \
    field(tp_dst)

struct fields {
#define field(name) uint32_t name;
    FIELDS
#undef field
};

void pipeline_lua_code_gentable_init(void);
void pipeline_lua_code_gentable_finish(void);

void pipeline_lua_load_code(const char *filename, const uint8_t *data, uint32_t size);

void pipeline_lua_fields_from_key(struct ind_ovs_parsed_key *key, struct fields *fields);

extern const char *pipeline_lua_field_names[];

#endif
