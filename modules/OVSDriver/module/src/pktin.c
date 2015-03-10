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
#include <SocketManager/socketmanager.h>

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

static int
ind_ovs_pktin_recv(struct nl_msg *msg, void *arg)
{
    struct ind_ovs_port *port = arg;

    if (!ind_ovs_benchmark_mode && aim_ratelimiter_limit(&port->pktin_limiter, monotonic_us()) != 0) {
        if (aim_ratelimiter_limit(&port->upcall_log_limiter, monotonic_us()) == 0) {
            LOG_WARN("rate limiting packet-ins from port %s", port->ifname);
        }
        return NL_OK;
    }

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    assert(nlh->nlmsg_type == ovs_packet_family);

    struct nlattr *attrs[OVS_PACKET_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                      attrs, OVS_PACKET_ATTR_MAX,
                      NULL) < 0) {
        LOG_ERROR("failed to parse packet message");
        abort();
    }

    LOG_VERBOSE("Received packet-in message:");
    ind_ovs_dump_msg(nlmsg_hdr(msg));

    struct nlattr *key = attrs[OVS_PACKET_ATTR_KEY];
    struct nlattr *packet = attrs[OVS_PACKET_ATTR_PACKET];
    struct nlattr *userdata_nla = attrs[OVS_PACKET_ATTR_USERDATA];
    assert(key && packet && userdata_nla);

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key(key, &pkey);

    uint64_t userdata = nla_get_u64(userdata_nla);

    ind_ovs_pktin(pkey.in_port,
                  nla_data(packet), nla_len(packet),
                  IVS_PKTIN_REASON(userdata),
                  IVS_PKTIN_METADATA(userdata),
                  &pkey);

    return NL_OK;
}

static void
ind_ovs_pktin_ready(int socket_id, void *cookie,
                    int read_ready, int write_ready, int error_seen)
{
    struct ind_ovs_port *port = cookie;
    nl_recvmsgs_default(port->pktin_socket);
}

void
ind_ovs_pktin_register(struct ind_ovs_port *port)
{
    if (ind_soc_socket_register(nl_socket_get_fd(port->pktin_socket),
                                ind_ovs_pktin_ready, port) < 0) {
        LOG_ERROR("failed to register socket");
        abort();
    }

    nl_socket_modify_cb(port->pktin_socket, NL_CB_VALID, NL_CB_CUSTOM,
                        ind_ovs_pktin_recv, port);
}

void
ind_ovs_pktin_unregister(struct ind_ovs_port *port)
{
    ind_soc_socket_unregister(nl_socket_get_fd(port->pktin_socket));
}

void
ind_ovs_pktin_init(void)
{
    aim_ratelimiter_init(&ind_ovs_pktin_limiter, PKTIN_INTERVAL,
                         PKTIN_BURST_SIZE, NULL);
}
