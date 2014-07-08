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

#include "ovs_driver_int.h"
#include <indigo/of_state_manager.h>

static aim_ratelimiter_t ind_ovs_pktin_limiter;

indigo_error_t
ind_ovs_pktin(of_port_no_t in_port,
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
ind_ovs_pktin_init(void)
{
    aim_ratelimiter_init(&ind_ovs_pktin_limiter, PKTIN_INTERVAL,
                         PKTIN_BURST_SIZE, NULL);
}
