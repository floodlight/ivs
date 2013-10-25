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
#include <indigo/of_state_manager.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <errno.h>

/*
 * The controller only wants to see the tunnel endpoint in
 * bsn_get_interfaces_reply. Hardcode its name.
 */
static const char *tunnel_ifname = "tun-loopback";

/*
 * This code uses getifaddrs to get both the IPv4 (AF_INET family) and MAC
 * (AF_PACKET family) addresses for each interface. Since getifaddrs returns
 * these separately, we first add list entries for each AF_INET address and
 * then for each entry find the AF_PACKET address with the same name.
 */
static indigo_error_t
ind_ovs_handle_bsn_get_interfaces_request(
    of_bsn_get_interfaces_request_t *request,
    indigo_cxn_id_t cxn_id)
{
    of_bsn_get_interfaces_reply_t *reply;
    uint32_t xid;
    struct ifaddrs *ifaddr, *ifa;
    of_list_bsn_interface_t list[1];
    of_bsn_interface_t entry[1];
    int rv;

    reply = of_bsn_get_interfaces_reply_new(request->version);
    if (reply == NULL) {
        return INDIGO_ERROR_RESOURCE;
    }

    of_bsn_get_interfaces_request_xid_get(request, &xid);
    of_bsn_get_interfaces_reply_xid_set(reply, xid);

    of_bsn_get_interfaces_reply_interfaces_bind(reply, list);

    if (getifaddrs(&ifaddr) == -1) {
        abort();
    }

    /* Add each interface with an IP */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        struct sockaddr_in *sa, *sa_mask;
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (strncmp(tunnel_ifname, ifa->ifa_name, sizeof(of_port_name_t))) {
            continue;
        }
        sa = (struct sockaddr_in *)ifa->ifa_addr;
        sa_mask = (struct sockaddr_in *)ifa->ifa_netmask;

        of_bsn_interface_init(entry, request->version, -1, 1);
        if (of_list_bsn_interface_append_bind(list, entry) < 0) {
            LOG_WARN("unable to reply with all interfaces");
            break;
        }

        of_bsn_interface_name_set(entry, ifa->ifa_name);
        of_bsn_interface_ipv4_addr_set(entry, ntohl(sa->sin_addr.s_addr));
        of_bsn_interface_ipv4_netmask_set(entry, ntohl(sa_mask->sin_addr.s_addr));
    }

    /* Fill in MAC addrs from AF_PACKET addresses */
    OF_LIST_BSN_INTERFACE_ITER(list, entry, rv) {
        of_port_name_t entry_name;
        of_bsn_interface_name_get(entry, &entry_name);
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            struct sockaddr_ll *sa;
            of_mac_addr_t hw_addr;
            if (ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != AF_PACKET ||
                strncmp(ifa->ifa_name, entry_name, sizeof(of_port_name_t))) {
                continue;
            }
            sa = (struct sockaddr_ll *)ifa->ifa_addr;
            memcpy(hw_addr.addr, sa->sll_addr, OF_MAC_ADDR_BYTES);
            of_bsn_interface_hw_addr_set(entry, hw_addr);
            break;
        }
    }

    freeifaddrs(ifaddr);

    return indigo_cxn_send_controller_message(cxn_id, reply);
}

indigo_error_t
ind_ovs_handle_bsn_set_pktin_suppression_request(of_experimenter_t *experimenter,
                                                 indigo_cxn_id_t cxn_id)
{
    of_bsn_set_pktin_suppression_request_t *obj = experimenter;
    of_bsn_set_pktin_suppression_request_enabled_get(obj, &ind_ovs_pktin_suppression_cfg.enabled);
    of_bsn_set_pktin_suppression_request_idle_timeout_get(obj, &ind_ovs_pktin_suppression_cfg.idle_timeout);
    of_bsn_set_pktin_suppression_request_hard_timeout_get(obj, &ind_ovs_pktin_suppression_cfg.hard_timeout);
    of_bsn_set_pktin_suppression_request_priority_get(obj, &ind_ovs_pktin_suppression_cfg.priority);
    of_bsn_set_pktin_suppression_request_cookie_get(obj, &ind_ovs_pktin_suppression_cfg.cookie);

    if (ind_ovs_pktin_suppression_cfg.idle_timeout == 0 &&
        ind_ovs_pktin_suppression_cfg.hard_timeout == 0 &&
        ind_ovs_pktin_suppression_cfg.enabled == 1) {
        ind_ovs_pktin_suppression_cfg.enabled = 0;
        LOG_ERROR("Ignoring pktin_suppression request with zero timeouts");
    }

    of_bsn_set_pktin_suppression_reply_t *reply = of_bsn_set_pktin_suppression_reply_new(obj->version);
    if (reply == NULL) {
        return INDIGO_ERROR_RESOURCE;
    }

    uint32_t xid;
    of_bsn_set_pktin_suppression_request_xid_get(obj, &xid);
    of_bsn_set_pktin_suppression_reply_xid_set(reply, xid);

    of_bsn_set_pktin_suppression_reply_status_set(reply, 0);

    return indigo_cxn_send_controller_message(cxn_id, reply);
}

indigo_error_t
indigo_fwd_experimenter(of_experimenter_t *experimenter,
                        indigo_cxn_id_t cxn_id)
{
    switch (experimenter->object_id) {
    case OF_BSN_GET_INTERFACES_REQUEST:
        return ind_ovs_handle_bsn_get_interfaces_request(experimenter, cxn_id);
    case OF_BSN_SET_PKTIN_SUPPRESSION_REQUEST:
        return ind_ovs_handle_bsn_set_pktin_suppression_request(experimenter, cxn_id);
    default:
        return INDIGO_ERROR_NOT_SUPPORTED;
    }
}

indigo_error_t
indigo_port_experimenter(of_experimenter_t *experimenter,
                         indigo_cxn_id_t cxn_id)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}
