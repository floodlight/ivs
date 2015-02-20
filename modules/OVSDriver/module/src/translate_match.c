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

/*
 * Translate between OpenFlow matches (of_match_t)
 * and OVS flow key (struct ind_ovs_parsed_key / nlattrs).
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize (4)
#endif
#include "ovs_driver_int.h"
#include <byteswap.h>
#include <linux/if_ether.h>

/* Recursive (for encap) helper for ind_ovs_parse_key */
static void
ind_ovs_parse_key__(struct nlattr *key, struct ind_ovs_parsed_key *pkey)
{
    struct nlattr *attrs[OVS_KEY_ATTR_MAX+1];
    if (nla_parse_nested(attrs, OVS_KEY_ATTR_MAX, key, NULL) < 0) {
        abort();
    }

#define field(attr, name, type) \
    if (attrs[attr]) { \
        assert(sizeof(type) == sizeof(pkey->name)); \
        memcpy(&pkey->name, nla_data(attrs[attr]), sizeof(type)); \
        ATTR_BITMAP_SET(pkey->populated, (attr)); \
    }
    OVS_KEY_FIELDS
#undef field

    if (attrs[OVS_KEY_ATTR_ENCAP]) {
        ind_ovs_parse_key__(attrs[OVS_KEY_ATTR_ENCAP], pkey);
    }

    if (attrs[OVS_KEY_ATTR_TUNNEL]) {
        struct nlattr *tunnel_attrs[OVS_TUNNEL_KEY_ATTR_MAX+1];
        if (nla_parse_nested(tunnel_attrs, OVS_TUNNEL_KEY_ATTR_MAX,
                             attrs[OVS_KEY_ATTR_TUNNEL], NULL) < 0) {
            abort();
        }

#define field(attr, name, type) \
        if (tunnel_attrs[attr]) { \
            assert(sizeof(type) == sizeof(pkey->tunnel.name)); \
            memcpy(&pkey->tunnel.name, nla_data(tunnel_attrs[attr]), sizeof(type)); \
        }
        OVS_TUNNEL_KEY_FIELDS
#undef field
    }
}

void
ind_ovs_parse_key(struct nlattr *key, struct ind_ovs_parsed_key *pkey)
{
    memset(pkey, 0, sizeof(*pkey));
    pkey->populated = 0;
    pkey->in_port = -1;
    pkey->tunnel.id = 0;
    pkey->tunnel.ipv4_src = 0;
    pkey->tunnel.ipv4_dst = 0;
    pkey->tunnel.tos = 0;
    pkey->tunnel.ttl = 64;
    ind_ovs_parse_key__(key, pkey);
    assert(ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ETHERNET));
}

void
ind_ovs_emit_key(const struct ind_ovs_parsed_key *key, struct nl_msg *msg, bool omit_zero)
{
    static uint8_t zeroes[sizeof(*key)];
#define field(attr, name, type) \
    if (ATTR_BITMAP_TEST(key->populated, attr) && \
            (!omit_zero || memcmp(&key->name, zeroes, sizeof(type)))) { \
        nla_put(msg, attr, sizeof(type), &key->name); \
    }
    OVS_KEY_FIELDS
#undef field
}

/* Should only be used when creating the match for a packet-in */
void
ind_ovs_key_to_match(const struct ind_ovs_parsed_key *pkey,
                     of_version_t version,
                     of_match_t *match)
{
    memset(match, 0, sizeof(*match));

    /* We only populate the masks for this OF version */
    match->version = version;

    of_match_fields_t *fields = &match->fields;

    assert(ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_IN_PORT));
    if (pkey->in_port == OVSP_LOCAL) {
        fields->in_port = OF_PORT_DEST_LOCAL;
    } else {
        fields->in_port = pkey->in_port;
    }
    OF_MATCH_MASK_IN_PORT_EXACT_SET(match);

    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_ETHERTYPE)) {
        fields->eth_type = ntohs(pkey->ethertype);
        if (fields->eth_type <= OF_DL_TYPE_NOT_ETH_TYPE) {
            fields->eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
        }
    } else {
        fields->eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
    }
    OF_MATCH_MASK_ETH_TYPE_EXACT_SET(match);
}
