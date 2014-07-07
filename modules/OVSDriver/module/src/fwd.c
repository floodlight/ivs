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

#include "ovs_driver_int.h"
#include <unistd.h>
#include <indigo/memory.h>
#include <indigo/forwarding.h>
#include <indigo/of_state_manager.h>
#include "OFStateManager/ofstatemanager.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>

static pthread_rwlock_t ind_ovs_fwd_rwlock;

static aim_ratelimiter_t ind_ovs_pktin_limiter;

indigo_error_t
indigo_fwd_forwarding_features_get(of_features_reply_t *features)
{
    uint32_t capabilities = 0, actions = 0;

    of_features_reply_n_tables_set(features, 1);

    OF_CAPABILITIES_FLAG_FLOW_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_TABLE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_PORT_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_QUEUE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_ARP_MATCH_IP_SET(capabilities, features->version);
    of_features_reply_capabilities_set(features, capabilities);

    if (features->version == OF_VERSION_1_0) {
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_OUTPUT_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_VLAN_VID_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_VLAN_PCP_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_STRIP_VLAN_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_DL_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_DL_DST_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_DST_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_TOS_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_TP_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_TP_DST_BY_VERSION(features->version));
#if 0
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_ENQUEUE_BY_VERSION(features->version));
#endif
        of_features_reply_actions_set(features, actions);
    }

    return (INDIGO_ERROR_NONE);
}

indigo_error_t
ind_fwd_pkt_in(of_port_no_t in_port,
               uint8_t *data, unsigned int len, uint8_t reason, uint64_t metadata,
               struct ind_ovs_parsed_key *pkey)
{
    LOG_TRACE("Sending packet-in");

    struct ind_ovs_port *port = ind_ovs_port_lookup(in_port);
    of_version_t ctrlr_of_version;

    if (indigo_cxn_get_async_version(&ctrlr_of_version) != INDIGO_ERROR_NONE) {
        LOG_TRACE("No active controller connection");
        return INDIGO_ERROR_NONE;
    }

    if (port != NULL && port->no_packet_in) {
        LOG_TRACE("Packet-in not enabled from this port");
        return INDIGO_ERROR_NONE;
    }

    if (!ind_ovs_benchmark_mode &&
        aim_ratelimiter_limit(&ind_ovs_pktin_limiter, monotonic_us()) != 0) {
        return INDIGO_ERROR_NONE;
    }

    of_match_t match;
    ind_ovs_key_to_match(pkey, ctrlr_of_version, &match);
    match.fields.metadata = metadata;
    OF_MATCH_MASK_METADATA_EXACT_SET(&match);

    of_octets_t of_octets = { .data = data, .bytes = len };

    of_packet_in_t *of_packet_in;
    if ((of_packet_in = of_packet_in_new(ctrlr_of_version)) == NULL) {
        return INDIGO_ERROR_RESOURCE;
    }

    of_packet_in_total_len_set(of_packet_in, len);
    of_packet_in_reason_set(of_packet_in, reason);
    of_packet_in_buffer_id_set(of_packet_in, OF_BUFFER_ID_NO_BUFFER);

    if (of_packet_in->version < OF_VERSION_1_2) {
        of_packet_in_in_port_set(of_packet_in, in_port);
    } else {
        if (LOXI_FAILURE(of_packet_in_match_set(of_packet_in, &match))) {
            LOG_ERROR("Failed to write match to packet-in message");
            of_packet_in_delete(of_packet_in);
            return INDIGO_ERROR_UNKNOWN;
        }
    }

    if (of_packet_in->version >= OF_VERSION_1_3) {
        of_packet_in_cookie_set(of_packet_in, UINT64_C(0xffffffffffffffff));
    }

    if (LOXI_FAILURE(of_packet_in_data_set(of_packet_in, &of_octets))) {
        LOG_ERROR("Failed to write packet data to packet-in message");
        of_packet_in_delete(of_packet_in);
        return INDIGO_ERROR_UNKNOWN;
    }

    return indigo_core_packet_in(of_packet_in);
}

void
ind_ovs_fwd_read_lock(void)
{
    pthread_rwlock_rdlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_read_unlock(void)
{
    pthread_rwlock_unlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_write_lock(void)
{
    pthread_rwlock_wrlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_write_unlock(void)
{
    pthread_rwlock_unlock(&ind_ovs_fwd_rwlock);
}

indigo_error_t
ind_ovs_fwd_init(void)
{
    pthread_rwlock_init(&ind_ovs_fwd_rwlock, NULL);

    aim_ratelimiter_init(&ind_ovs_pktin_limiter, PKTIN_INTERVAL,
                         PKTIN_BURST_SIZE, NULL);

    return (INDIGO_ERROR_NONE);
}

void
ind_ovs_fwd_finish(void)
{
    int i;

    /* Quiesce all ports */
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        if (ind_ovs_ports[i] != NULL) {
            ind_ovs_upcall_quiesce(ind_ovs_ports[i]);
        }
    }

    /* Hold this forever. */
    ind_ovs_fwd_write_lock();
}
