/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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

DEBUG_COUNTER(pktin_ratelimited, "ovsdriver.pktin.ratelimited",
              "Dropped packet-in because of the ratelimiter");

static int
ind_ovs_pktin_socket_recv(struct nl_msg *msg, void *arg)
{
    struct ind_ovs_pktin_socket *soc = arg;

    if (!ind_ovs_benchmark_mode && aim_ratelimiter_limit(&soc->pktin_limiter, monotonic_us()) != 0) {
        debug_counter_inc(&pktin_ratelimited);
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

    if (soc->callback) {
        soc->callback(nla_data(packet), nla_len(packet),
                      IVS_PKTIN_REASON(userdata),
                      IVS_PKTIN_METADATA(userdata), &pkey);
    } else {
        ind_ovs_pktin(pkey.in_port,
                      nla_data(packet), nla_len(packet),
                      IVS_PKTIN_REASON(userdata),
                      IVS_PKTIN_METADATA(userdata),
                      &pkey);
    }

    return NL_OK;
}

static void
ind_ovs_pktin_socket_ready(int socket_id, void *cookie,
                           int read_ready, int write_ready, int error_seen)
{
    struct ind_ovs_pktin_socket *soc = cookie;
    nl_recvmsgs_default(soc->pktin_socket);
}

void
ind_ovs_pktin_socket_register(struct ind_ovs_pktin_socket *soc)
{
    /* Create the netlink socket */
    soc->pktin_socket = ind_ovs_create_nlsock();
    if (soc->pktin_socket == NULL) {
        LOG_ERROR("failed to create netlink socket");
        return;
    }

    /* Set it to non-blocking */
    if (nl_socket_set_nonblocking(soc->pktin_socket) < 0) {
        LOG_ERROR("failed to set netlink socket nonblocking");
        nl_socket_free(soc->pktin_socket);
        return;
    }

    /* Register with socket manager */
    if (ind_soc_socket_register(nl_socket_get_fd(soc->pktin_socket),
                                ind_ovs_pktin_socket_ready, soc) < 0) {
        LOG_ERROR("failed to register socket");
        abort();
    }

    nl_socket_modify_cb(soc->pktin_socket, NL_CB_VALID, NL_CB_CUSTOM,
                        ind_ovs_pktin_socket_recv, soc);
}

void
ind_ovs_pktin_socket_unregister(struct ind_ovs_pktin_socket *soc)
{
    ind_soc_socket_unregister(nl_socket_get_fd(soc->pktin_socket));
    nl_socket_free(soc->pktin_socket);
}
