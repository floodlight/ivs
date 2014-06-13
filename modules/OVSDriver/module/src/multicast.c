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
#include "indigo/forwarding.h"
#include "indigo/port_manager.h"
#include "indigo/of_state_manager.h"
#include "indigo/types.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "SocketManager/socketmanager.h"

static struct nl_sock *ind_ovs_multicast_socket;

static void
ind_ovs_handle_vport_multicast(struct nlmsghdr *nlh)
{
    struct genlmsghdr *gnlh = (void *)(nlh + 1);
    struct nlattr *attrs[OVS_VPORT_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                attrs, OVS_VPORT_ATTR_MAX,
                NULL) < 0) {
        abort();
    }

    assert(attrs[OVS_VPORT_ATTR_PORT_NO]);
    uint32_t port_no = nla_get_u32(attrs[OVS_VPORT_ATTR_PORT_NO]);

    assert(attrs[OVS_VPORT_ATTR_NAME]);
    const char *ifname = nla_get_string(attrs[OVS_VPORT_ATTR_NAME]);

    of_mac_addr_t mac_addr = of_mac_addr_all_zeros;
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!strcmp(ifname, ifa->ifa_name)) {
                struct sockaddr_ll *sa = (struct sockaddr_ll *)ifa->ifa_addr;
                if (sa != NULL && sa->sll_family == AF_PACKET) {
                    memcpy(mac_addr.addr, &sa->sll_addr, OF_MAC_ADDR_BYTES);
                    LOG_INFO("Using MAC from interface %s", ifa->ifa_name);
                    break;
                }
            }
        }
    }
    freeifaddrs(ifaddr);

    if (gnlh->cmd == OVS_VPORT_CMD_NEW) {
        ind_ovs_port_added(port_no, ifname, mac_addr);
    } else if (gnlh->cmd == OVS_VPORT_CMD_DEL) {
        ind_ovs_port_deleted(port_no);
    }
}

static void
ind_ovs_handle_datapath_multicast(struct nlmsghdr *nlh)
{
    struct genlmsghdr *gnlh = (void *)(nlh + 1);
    struct nlattr *attrs[OVS_DP_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                attrs, OVS_DP_ATTR_MAX,
                NULL) < 0) {
        abort();
    }

    if (gnlh->cmd == OVS_DP_CMD_DEL) {
        LOG_INFO("kernel datapath deleted, exiting");
        exit(0);
    }
}

static int
ind_ovs_recv_multicast(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (void *)(nlh + 1);
    struct ovs_header *ovs_header = (void *)(gnlh + 1);

    if (ovs_header->dp_ifindex != ind_ovs_dp_ifindex) {
        /* Not our datapath */
        return NL_OK;
    }

    LOG_VERBOSE("Received multicast message:");
    ind_ovs_dump_msg(nlmsg_hdr(msg));

    if (nlh->nlmsg_type == ovs_vport_family) {
        ind_ovs_handle_vport_multicast(nlh);
    } else if (nlh->nlmsg_type == ovs_datapath_family) {
        ind_ovs_handle_datapath_multicast(nlh);
    } else {
        abort();
    }

    return NL_OK;
}

static void
ind_ovs_handle_multicast(void)
{
    nl_recvmsgs_default(ind_ovs_multicast_socket);
}

void
ind_ovs_multicast_init(void)
{
    int ret;

    ind_ovs_multicast_socket = ind_ovs_create_nlsock();
    if (ind_ovs_multicast_socket == NULL) {
        LOG_ERROR("failed to allocate netlink socket");
        abort();
    }

    /* Resolve multicast group names to integer ids */

    if ((ret = genl_ctrl_resolve_grp(ind_ovs_multicast_socket, OVS_VPORT_FAMILY, OVS_VPORT_MCGROUP)) < 0) {
        LOG_ERROR("failed to resolve netlink multicast group: %s", nl_geterror(ret));
        abort();
    }

    int vport_mcgroup = ret;

    if ((ret = genl_ctrl_resolve_grp(ind_ovs_multicast_socket, OVS_DATAPATH_FAMILY, OVS_DATAPATH_MCGROUP)) < 0) {
        LOG_ERROR("failed to resolve netlink multicast group: %s", nl_geterror(ret));
        abort();
    }

    int datapath_mcgroup = ret;

    /*
     * Join multicast groups
     *
     * Must be done after we're finished resolving so that multicast messages
     * don't interfere with the resolve process.
     */

    if ((ret = nl_socket_add_memberships(ind_ovs_multicast_socket, vport_mcgroup, 0)) < 0) {
        LOG_ERROR("failed to join netlink multicast group: %s", nl_geterror(ret));
        abort();
    }

    if ((ret = nl_socket_add_memberships(ind_ovs_multicast_socket, datapath_mcgroup, 0)) < 0) {
        LOG_ERROR("failed to join netlink multicast group: %s", nl_geterror(ret));
        abort();
    }

    if ((ret = nl_socket_modify_cb(ind_ovs_multicast_socket, NL_CB_VALID, NL_CB_CUSTOM,
                                   ind_ovs_recv_multicast, NULL)) < 0) {
        LOG_ERROR("failed to set netlink callback: %s", nl_geterror(ret));
        abort();
    }

    if (ind_soc_socket_register(nl_socket_get_fd(ind_ovs_multicast_socket),
                                (ind_soc_socket_ready_callback_f)ind_ovs_handle_multicast,
                                NULL) < 0) {
        LOG_ERROR("failed to register socket");
        abort();
    }
}
