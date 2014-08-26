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
#include "OVSDriver/ovsdriver_config.h"
#include <stdlib.h>
#include <assert.h>
#include <net/if.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include "indigo/types.h"
#include "murmur/murmur.h"
#include "SocketManager/socketmanager.h"
#include "indigo/of_state_manager.h"

static int ind_ovs_create_datapath(const char *name);
static int ind_ovs_destroy_datapath(void);
static void setup_inband(void);

/* Log module "ovsdriver" */
AIM_LOG_STRUCT_DEFINE(
    OVSDRIVER_CONFIG_LOG_OPTIONS_DEFAULT,
    OVSDRIVER_CONFIG_LOG_BITS_DEFAULT,
    NULL, /* Custom log map */
    OVSDRIVER_CONFIG_LOG_CUSTOM_BITS_DEFAULT);

int ind_ovs_dp_ifindex = 0;
struct nl_sock *ind_ovs_socket;
int ovs_datapath_family, ovs_packet_family, ovs_vport_family, ovs_flow_family;
bool ind_ovs_benchmark_mode = false;
bool ind_ovs_disable_kflows = false;
uint32_t ind_ovs_salt;
uint16_t ind_ovs_inband_vlan = VLAN_INVALID;

static int
ind_ovs_create_datapath(const char *name)
{
    int ret;

    assert(ind_ovs_dp_ifindex == 0);
    assert(strlen(name) < 256);

    if ((ind_ovs_dp_ifindex = if_nametoindex(name)) != 0) {
        /* Destroy existing datapath. */
        (void) ind_ovs_destroy_datapath();
    }

    LOG_INFO("Creating kernel datapath %s", name);
    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_datapath_family, OVS_DP_CMD_NEW);
    nla_put_string(msg, OVS_DP_ATTR_NAME, name);
    nla_put_u32(msg, OVS_DP_ATTR_UPCALL_PID, 0);
    ret = ind_ovs_transact(msg);
    if (ret != 0) {
        return ret;
    }

    ind_ovs_dp_ifindex = if_nametoindex(name);
    assert(ind_ovs_dp_ifindex > 0);

    if (ind_ovs_inband_vlan != VLAN_INVALID) {
        setup_inband();
    }

    return ret;
}

static int
ind_ovs_destroy_datapath(void)
{
    assert(ind_ovs_dp_ifindex != 0);
    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_datapath_family, OVS_DP_CMD_DEL);
    ind_ovs_dp_ifindex = 0;
    return ind_ovs_transact(msg);
}

/*
 * Generate a DPID.
 *
 * The upper 48 bits are the MAC address of the first NIC.
 * The lower 16 bits are the hash of the datapath name.
 */
static void
ind_ovs_dpid_set(const char *datapath_name)
{
    bool found = false;
    uint8_t mac[6];
    uint64_t dpid = 0; /* big endian */
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        abort();
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        struct sockaddr_ll *sa = (struct sockaddr_ll *)ifa->ifa_addr;
        if (sa != NULL && sa->sll_family == AF_PACKET
            && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            memcpy(mac, &sa->sll_addr, sizeof(mac));
            found = true;
            LOG_INFO("using MAC from interface %s", ifa->ifa_name);
            break;
        }
    }

    if (!found) {
        uint32_t x = get_entropy();
        LOG_WARN("no NICs found, generating a random MAC address");
        mac[0] = 0x02; /* locally administered address */
        mac[1] = 0;
        mac[2] = x;
        mac[3] = x >> 8;
        mac[4] = x >> 16;
        mac[5] = x >> 24;
    }

    memcpy(&dpid, mac, sizeof(mac));
    dpid |= htobe64(murmur_hash(datapath_name, strlen(datapath_name), 0) & 0xFFFF);
    LOG_INFO("DPID: %016"PRIx64, be64toh(dpid));
    indigo_core_dpid_set(be64toh(dpid));

    freeifaddrs(ifaddr);
}

static void
setup_inband(void)
{
    const char *ifname = "inband";

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_NEW);
    nla_put_u32(msg, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_INTERNAL);
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, ifname);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, IVS_INBAND_PORT);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID, 0);
    indigo_error_t ret = ind_ovs_transact(msg);
    if (ret != 0) {
        AIM_DIE("Failed to create %s internal port: %s", ifname, indigo_strerror(ret));
    }

    (void) ind_ovs_set_interface_flags(ifname, IFF_UP);

    /* Enable IPv6 */
    char filename[1024];
    snprintf(filename, sizeof(filename), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);
    if (write_file(filename, "0") < 0) {
        AIM_LOG_WARN("Failed to enable IPv6 on the local interface");
        /* Don't fail startup for this */
    }
}

indigo_error_t
indigo_fwd_expiration_enable_set(int is_enabled)
{
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_fwd_expiration_enable_get(int *is_enabled)
{
    *is_enabled = 0;
    return INDIGO_ERROR_NONE;
}

indigo_error_t
ind_ovs_init(const char *datapath_name)
{
    int ret;
    char *env_str;

    env_str = getenv("INDIGO_BENCHMARK");
    if (env_str != NULL && atoi(env_str) == 1) {
        LOG_WARN("Benchmark mode enabled.");
        ind_ovs_benchmark_mode = true;
    }

    env_str = getenv("IVS_DISABLE_KFLOWS");
    if (env_str != NULL && atoi(env_str) == 1) {
        LOG_WARN("Kernel flow installation disabled.");
        ind_ovs_disable_kflows = true;
    }

    ind_ovs_salt = get_entropy();

    ind_ovs_kflow_module_init();

    nlmsg_set_default_size(IND_OVS_DEFAULT_MSG_SIZE);

    ind_ovs_nlmsg_freelist_init();

    /* Init main netlink socket. */
    ind_ovs_socket = ind_ovs_create_nlsock();
    if (ind_ovs_socket == NULL) {
        return INDIGO_ERROR_UNKNOWN;
    }

    /* Resolve generic netlink families. */
    ovs_datapath_family = genl_ctrl_resolve(ind_ovs_socket, OVS_DATAPATH_FAMILY);
    ovs_packet_family = genl_ctrl_resolve(ind_ovs_socket, OVS_PACKET_FAMILY);
    ovs_vport_family = genl_ctrl_resolve(ind_ovs_socket, OVS_VPORT_FAMILY);
    ovs_flow_family = genl_ctrl_resolve(ind_ovs_socket, OVS_FLOW_FAMILY);
    if (ovs_datapath_family < 0 || ovs_packet_family < 0 ||
        ovs_vport_family < 0 || ovs_flow_family < 0) {
        LOG_ERROR("failed to resolve Open vSwitch generic netlink families; module not loaded?");
        return INDIGO_ERROR_NOT_FOUND;
    }

    ind_ovs_fwd_init();
    ind_ovs_pktin_init();
    ind_ovs_upcall_init();
    ind_ovs_bh_init();
    ind_ovs_multicast_init();
    ind_ovs_port_init();
    ind_ovs_vlan_stats_init();
    ind_ovs_barrier_init();

    if ((ret = ind_ovs_create_datapath(datapath_name)) != 0) {
        LOG_ERROR("failed to create OVS datapath");
        return ret;
    }

    /* Pretend we received a port created notification for the internal port */
    of_mac_addr_t local_mac = { { 0, 0, 0, 0, 0, 0 } };
    ind_ovs_port_added(OVSP_LOCAL, "local", local_mac);

    if ((ret = ind_soc_timer_event_register(
        (ind_soc_timer_callback_f)ind_ovs_kflow_expire, NULL, 2345)) != 0) {
        LOG_ERROR("failed to create timer");
        return ret;
    }

    ind_ovs_dpid_set(datapath_name);

    return 0;
}

void
ind_ovs_finish(void)
{
    ind_ovs_fwd_finish();
    ind_ovs_port_finish();
    ind_ovs_upcall_finish();
    (void) ind_ovs_destroy_datapath();
    ind_ovs_nlmsg_freelist_finish();
}

void
ind_ovs_enable(void)
{
    ind_ovs_upcall_enable();
}

/* Called by AIM's main() before the real main(). */
void
__ovsdriver_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}
