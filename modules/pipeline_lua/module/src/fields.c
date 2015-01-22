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
#include <byteswap.h>
#include <arpa/inet.h>

const char *pipeline_lua_field_names[] = {
#define field(name) AIM_STRINGIFY(name),
    FIELDS
#undef field
    NULL,
};

void
pipeline_lua_fields_from_key(struct ind_ovs_parsed_key *key,
                             struct fields *fields)
{
    memset(fields, 0, sizeof(*fields));

    fields->in_port = key->in_port;

    {
        uint8_t *m = key->ethernet.eth_dst;
        fields->eth_dst_lo = (m[2] << 24) | (m[3] << 16) | (m[4] << 8) | m[5];
        fields->eth_dst_hi = (m[0] << 8) | m[1];
    }

    {
        uint8_t *m = key->ethernet.eth_src;
        fields->eth_src_lo = (m[2] << 24) | (m[3] << 16) | (m[4] << 8) | m[5];
        fields->eth_src_hi = (m[0] << 8) | m[1];
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ETHERTYPE)) {
        fields->eth_type = ntohs(key->ethertype);
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_VLAN)) {
        fields->vlan_vid = VLAN_VID(ntohs(key->vlan));
        fields->vlan_pcp = VLAN_PCP(ntohs(key->vlan));
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_IPV4)) {
        fields->ip_dscp = (key->ipv4.ipv4_tos & IP_DSCP_MASK) >> IP_DSCP_SHIFT;
        fields->ip_ecn = key->ipv4.ipv4_tos & IP_ECN_MASK;
        fields->ip_proto = key->ipv4.ipv4_proto;
        fields->ipv4_src = ntohl(key->ipv4.ipv4_src);
        fields->ipv4_dst = ntohl(key->ipv4.ipv4_dst);
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_TCP)) {
        fields->tp_src = ntohs(key->tcp.tcp_src);
        fields->tp_dst = ntohs(key->tcp.tcp_dst);
    } else if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_UDP)) {
        fields->tp_src = ntohs(key->udp.udp_src);
        fields->tp_dst = ntohs(key->udp.udp_dst);
    }
}
