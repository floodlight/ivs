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
#include "ovsdriver_log.h"
#include "indigo/forwarding.h"
#include "indigo/port_manager.h"
#include "indigo/of_state_manager.h"
#include "SocketManager/socketmanager.h"
#include <errno.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>

#ifndef _LINUX_IF_H
/* Some versions of libnetlink include linux/if.h, which conflicts with net/if.h. */
#include <net/if.h>
#endif

struct ind_ovs_port *ind_ovs_ports[IND_OVS_MAX_PORTS];  /**< Table of all ports */

static struct nl_cache_mngr *route_cache_mngr;

static indigo_error_t port_status_notify(of_port_no_t of_port_num, unsigned reason);
static void port_desc_set(of_port_desc_t *of_port_desc, of_port_no_t of_port_num);
static void port_desc_set_local(of_port_desc_t *of_port_desc);

struct ind_ovs_port *
ind_ovs_port_lookup(of_port_no_t port_no)
{
    if (port_no >= IND_OVS_MAX_PORTS) {
        return NULL;
    }

    return ind_ovs_ports[port_no];
}

struct ind_ovs_port *
ind_ovs_port_lookup_by_name(const char *ifname)
{
    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port && !strcmp(port->ifname, ifname)) {
            return port;
        }
    }
    return NULL;
}

/* TODO populate more fields of the port desc */
indigo_error_t indigo_port_features_get(
    of_features_reply_t *features)
{
    indigo_error_t      result             = INDIGO_ERROR_NONE;
    of_list_port_desc_t *of_list_port_desc = 0;
    of_port_desc_t      *of_port_desc      = 0;

    if ((of_port_desc = of_port_desc_new(ind_ovs_version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((of_list_port_desc = of_list_port_desc_new(features->version)) == 0) {
        LOG_ERROR("of_list_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        if (ind_ovs_ports[i]) {
            port_desc_set(of_port_desc, i);
            /* TODO error handling */
            of_list_port_desc_append(of_list_port_desc, of_port_desc);
        }
    }

    port_desc_set_local(of_port_desc);
    /* TODO error handling */
    of_list_port_desc_append(of_list_port_desc, of_port_desc);

    if (LOXI_FAILURE(of_features_reply_ports_set(features,
                                                 of_list_port_desc
                                                 )
                     )
        ) {
        LOG_ERROR("of_features_reply_ports_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

 done:
    if (of_list_port_desc)  of_list_port_desc_delete(of_list_port_desc);
    if (of_port_desc)       of_port_desc_delete(of_port_desc);

    return (result);
}

/*
 * This function just asks the datapath to add the port. If that succeeds we'll
 * get a OVS_VPORT_CMD_NEW multicast message. At that point ind_ovs_port_added
 * will create our own representation of the port. This is to support using
 * ovs-dpctl to add and remove ports.
 */
indigo_error_t indigo_port_interface_add(
    indigo_port_name_t port_name,
    of_port_no_t of_port,
    indigo_port_config_t *config)
{
    assert(of_port < IND_OVS_MAX_PORTS);
    assert(strlen(port_name) < 256);

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_NEW);
    nla_put_u32(msg, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_NETDEV);
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, port_name);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, of_port);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID, 0);
    return ind_ovs_transact(msg);
}

indigo_error_t 
indigo_port_interface_list(indigo_port_info_t** list)
{
    int i;
    indigo_port_info_t* head = NULL; 

    if(list == NULL) { 
        return INDIGO_ERROR_PARAM; 
    }

    for (i = IND_OVS_MAX_PORTS-1; i >= 0; i--) { 
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if(port != NULL) { 
            indigo_port_info_t* pi = calloc(1, sizeof(*pi)); 
            strncpy(pi->port_name, port->ifname, sizeof(port->ifname)); 
            pi->of_port = i; 
            pi->next = head; 
            head = pi;
        }
    }
    *list = head; 
    return 0; 
}


void
indigo_port_interface_list_destroy(indigo_port_info_t* list)
{
    while(list) { 
        indigo_port_info_t* next = list->next; 
        free(list); 
        list = next; 
    }
}


void
ind_ovs_port_added(uint32_t port_no, const char *ifname, of_mac_addr_t mac_addr)
{
    indigo_error_t err;

    if (ind_ovs_ports[port_no]) {
        return;
    }

    struct ind_ovs_port *port = calloc(1, sizeof(*port));
    if (port == NULL) {
        LOG_ERROR("failed to allocate port");
        return;
    }

    strncpy(port->ifname, ifname, sizeof(port->ifname));
    port->dp_port_no = port_no;
    port->mac_addr = mac_addr;
    aim_ratelimiter_init(&port->upcall_log_limiter, 1000*1000, 5, NULL);
    aim_ratelimiter_init(&port->pktin_limiter, PORT_PKTIN_INTERVAL, PORT_PKTIN_BURST_SIZE, NULL);
    pthread_mutex_init(&port->quiesce_lock, NULL);
    pthread_cond_init(&port->quiesce_cvar, NULL);

    port->notify_socket = ind_ovs_create_nlsock();
    if (port->notify_socket == NULL) {
        goto cleanup_port;
    }

    if (nl_socket_set_nonblocking(port->notify_socket) < 0) {
        LOG_ERROR("failed to set netlink socket nonblocking");
        goto cleanup_port;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_SET);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port_no);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID,
                nl_socket_get_local_port(port->notify_socket));
    err = ind_ovs_transact(msg);
    if (err < 0) {
        LOG_ERROR("datapath failed to configure port %s", ifname);
        goto cleanup_port;
    }

    int if_flags;
    if (!ind_ovs_get_interface_flags(ifname, &if_flags)) {
        (void) ind_ovs_set_interface_flags(ifname, if_flags|IFF_UP);
    }

    /* Ensure port is fully populated before publishing it. */
    __sync_synchronize();

    ind_ovs_ports[port_no] = port;

    if ((err = port_status_notify(port_no, OF_PORT_CHANGE_REASON_ADD)) < 0) {
        LOG_WARN("failed to notify controller of port addition");
        /* Can't cleanup the port because it's already visible to other
         * threads. */
    }

    ind_ovs_upcall_register(port);
    LOG_INFO("Added port %s", port->ifname);
    ind_ovs_kflow_invalidate_flood();
    return;

cleanup_port:
    assert(ind_ovs_ports[port_no] == NULL);
    if (port->notify_socket) {
        nl_socket_free(port->notify_socket);
    }
    free(port);
}

/*
 * ind_ovs_port_deleted will free the port struct.
 */
indigo_error_t indigo_port_interface_remove(
    indigo_port_name_t port_name)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup_by_name(port_name);
    if (port == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_DEL);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port->dp_port_no);
    return ind_ovs_transact(msg);
}

void
ind_ovs_port_deleted(uint32_t port_no)
{
    assert(port_no < IND_OVS_MAX_PORTS);
    struct ind_ovs_port *port = ind_ovs_ports[port_no];
    if (port == NULL) {
        return;
    }

    ind_ovs_upcall_quiesce(port);
    ind_ovs_upcall_unregister(port);

    if (port_status_notify(port_no, OF_PORT_CHANGE_REASON_DELETE) < 0) {
        LOG_ERROR("failed to notify controller of port deletion");
    }

    LOG_INFO("Deleted port %s", port->ifname);

    ind_ovs_fwd_write_lock();
    nl_socket_free(port->notify_socket);
    pthread_mutex_destroy(&port->quiesce_lock);
    pthread_cond_destroy(&port->quiesce_cvar);
    free(port);
    ind_ovs_ports[port_no] = NULL;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_flood();
}

void indigo_port_modify(
    of_port_mod_t *port_mod,
    indigo_cookie_t callback_cookie)
{
    of_port_no_t port_no;
    of_port_mod_port_no_get(port_mod, &port_no);
    uint32_t config;
    of_port_mod_config_get(port_mod, &config);
    uint32_t mask;
    of_port_mod_mask_get(port_mod, &mask);

    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        indigo_core_port_modify_callback(INDIGO_ERROR_NOT_FOUND, callback_cookie);
        return;
    }

    port->config = (port->config & ~mask) | (config & mask);
    /* TODO change other configuration? */
    ind_ovs_kflow_invalidate_flood();

    indigo_core_port_modify_callback(INDIGO_ERROR_NONE, callback_cookie);
}

void indigo_port_stats_get(
    of_port_stats_request_t *port_stats_request,
    indigo_cookie_t callback_cookie)
{
    of_port_no_t               req_of_port_num;
    of_port_stats_reply_t      *port_stats_reply;
    of_version_t               version;

    version = port_stats_request->version;
    port_stats_reply = of_port_stats_reply_new(version);
    NYI(port_stats_reply == NULL);

    of_list_port_stats_entry_t list[1];
    of_port_stats_reply_entries_bind(port_stats_reply, list);

    of_port_stats_request_port_no_get(port_stats_request, &req_of_port_num);
    int dump_all = req_of_port_num == OF_PORT_DEST_NONE_BY_VERSION(version);

    /* TODO clang can't handle nested functions */
    int callback(struct nl_msg *msg, void *arg)
    {
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attrs[OVS_VPORT_ATTR_MAX+1];
        if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                        attrs, OVS_VPORT_ATTR_MAX,
                        NULL) < 0) {
            abort();
        }
        assert(attrs[OVS_VPORT_ATTR_PORT_NO]);
        assert(attrs[OVS_VPORT_ATTR_STATS]);

        uint32_t port_no = nla_get_u32(attrs[OVS_VPORT_ATTR_PORT_NO]);
        struct ovs_vport_stats *port_stats = nla_data(attrs[OVS_VPORT_ATTR_STATS]);

        if (!dump_all && port_no != req_of_port_num) {
            return NL_OK;
        }

        of_port_stats_entry_t entry[1];
        of_port_stats_entry_init(entry, version, -1, 1);
        if (of_list_port_stats_entry_append_bind(list, entry) < 0) {
            LOG_ERROR("too many port stats replies");
            return NL_STOP;
        }

        of_port_stats_entry_port_no_set(entry, port_no);
        of_port_stats_entry_rx_packets_set(entry, port_stats->rx_packets);
        of_port_stats_entry_tx_packets_set(entry, port_stats->tx_packets);
        of_port_stats_entry_rx_bytes_set(entry, port_stats->rx_bytes);
        of_port_stats_entry_tx_bytes_set(entry, port_stats->tx_bytes);
        of_port_stats_entry_rx_dropped_set(entry, port_stats->rx_dropped);
        of_port_stats_entry_tx_dropped_set(entry, port_stats->tx_dropped);
        of_port_stats_entry_rx_errors_set(entry, port_stats->rx_errors);
        of_port_stats_entry_tx_errors_set(entry, port_stats->tx_errors);
        /* TODO get these from physical interface? */
        of_port_stats_entry_rx_frame_err_set(entry, 0);
        of_port_stats_entry_rx_over_err_set(entry, 0);
        of_port_stats_entry_rx_crc_err_set(entry, 0);
        of_port_stats_entry_collisions_set(entry, 0);

        return NL_OK;
    }

    /* TODO factor this out */
    struct nl_msg *msg = nlmsg_alloc();
    if (msg == NULL) {
        NYI(0);
    }

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (cb == NULL) {
        NYI(0);
    }

    /* TODO send a GET cmd if we don't need all ports */
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_vport_family, sizeof(*hdr),
                                         NLM_F_DUMP, OVS_DP_CMD_GET, OVS_VPORT_VERSION);
    hdr->dp_ifindex = ind_ovs_dp_ifindex;

#ifndef NDEBUG
    int ret =
#endif
        nl_send_auto(ind_ovs_socket, msg);
    NYI(ret < 0);

    nlmsg_free(msg);

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback, NULL);

#ifndef NDEBUG
    ret =
#endif
        nl_recvmsgs(ind_ovs_socket, cb);
    NYI(ret < 0);

    nl_cb_put(cb);

    indigo_core_port_stats_get_callback(INDIGO_ERROR_NONE, port_stats_reply, callback_cookie);
}

/* Currently returns an empty reply */
void indigo_port_queue_config_get(
    of_queue_get_config_request_t *request,
    indigo_cookie_t callback_cookie)
{
    of_queue_get_config_reply_t *reply;
    indigo_error_t result = INDIGO_ERROR_NONE;

    reply = of_queue_get_config_reply_new(request->version);
    if (reply == NULL) {
        result = INDIGO_ERROR_RESOURCE;
        LOG_ERROR("Could not allocate queue config reply");
    }

    indigo_core_queue_config_get_callback(result, reply, callback_cookie);
}

/* Currently returns an empty reply */
void indigo_port_queue_stats_get(
    of_queue_stats_request_t *queue_stats_request,
    indigo_cookie_t callback_cookie)
{
    of_queue_stats_reply_t *queue_stats_reply = of_queue_stats_reply_new(ind_ovs_version);
    if (queue_stats_reply == NULL) {
        indigo_core_queue_stats_get_callback(INDIGO_ERROR_RESOURCE, NULL, callback_cookie);
        return;
    }

    uint32_t xid;
    of_queue_stats_request_xid_get(queue_stats_request, &xid);
    of_queue_stats_reply_xid_set(queue_stats_reply, xid);

    indigo_core_queue_stats_get_callback(INDIGO_ERROR_NONE, queue_stats_reply, callback_cookie);
}

static indigo_error_t
port_status_notify(of_port_no_t of_port_num, unsigned reason)
{
    indigo_error_t   result = INDIGO_ERROR_NONE;
    of_port_desc_t   *of_port_desc   = 0;
    of_port_status_t *of_port_status = 0;

    /* Don't know the cxn this is going to, so use configured version */
    if ((of_port_desc = of_port_desc_new(ind_ovs_version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    port_desc_set(of_port_desc, of_port_num);

    if ((of_port_status = of_port_status_new(ind_ovs_version)) == 0) {
        LOG_ERROR("of_port_status_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    of_port_status_reason_set(of_port_status, reason);
    of_port_status_desc_set(of_port_status, of_port_desc);
    of_port_desc_delete(of_port_desc);

    indigo_core_port_status_update(of_port_status);

    of_port_desc   = 0;     /* No longer owned */
    of_port_status = 0;     /* No longer owned */

 done:
    if (of_port_desc)    of_port_desc_delete(of_port_desc);
    if (of_port_status)  of_port_status_delete(of_port_status);

    return (result);
}

static void
port_desc_set(of_port_desc_t *of_port_desc, of_port_no_t of_port_num)
{
    struct ind_ovs_port *port = ind_ovs_ports[of_port_num];
    assert(port != NULL);

    of_port_desc_port_no_set(of_port_desc, of_port_num);
    of_port_desc_hw_addr_set(of_port_desc, port->mac_addr);
    of_port_desc_name_set(of_port_desc, port->ifname);
    of_port_desc_config_set(of_port_desc, port->config);
    of_port_desc_state_set(of_port_desc, 0);

    uint32_t curr, advertised, supported, peer;
    ind_ovs_get_interface_features(port->ifname, &curr, &advertised,
        &supported, &peer, of_port_desc->version);

    of_port_desc_curr_set(of_port_desc, curr);
    of_port_desc_advertised_set(of_port_desc, advertised);
    of_port_desc_supported_set(of_port_desc, supported);
    of_port_desc_peer_set(of_port_desc, peer);
}

static void
port_desc_set_local(of_port_desc_t *of_port_desc)
{
    of_port_desc_port_no_set(of_port_desc, OF_PORT_DEST_LOCAL);
    {
        of_mac_addr_t of_mac_addr;
        /** \todo Get proper MAC address */
        memset(&of_mac_addr, 0, sizeof(of_mac_addr));
        of_port_desc_hw_addr_set(of_port_desc, of_mac_addr);
    }
    of_port_name_t name = "local";
    of_port_desc_name_set(of_port_desc, name);
    of_port_desc_config_set(of_port_desc, 0);
    of_port_desc_state_set(of_port_desc, 0);

    of_port_desc_curr_set(of_port_desc, OF_PORT_FEATURE_FLAG_10GB_FD |
        OF_PORT_FEATURE_FLAG_COPPER_BY_VERSION(of_port_desc->version));
    of_port_desc_advertised_set(of_port_desc, 0);
    of_port_desc_supported_set(of_port_desc, 0);
    of_port_desc_peer_set(of_port_desc, 0);
}

/*
 * Called by nl_cache_mngr_data_ready if a link object changed.
 *
 * Sends a port status message to the controller.
 */
static void
link_change_cb(struct nl_cache *cache,
               struct nl_object *obj,
               int action,
               void *arg)
{
    struct rtnl_link *link = (struct rtnl_link *) obj;
    const char *ifname = rtnl_link_get_name(link);

    /*
     * Ignore additions/deletions, already handled by
     * ind_ovs_handle_vport_multicast.
     */
    if (action != NL_ACT_CHANGE) {
        return;
    }

    /* Ignore interfaces not connected to our datapath. */
    struct ind_ovs_port *port = ind_ovs_port_lookup_by_name(ifname);
    if (port == NULL) {
        return;
    }

    LOG_VERBOSE("Sending port status change notification for interface %s", ifname);

    port_status_notify(port->dp_port_no, OF_PORT_CHANGE_REASON_MODIFY);
}

static void
route_cache_mngr_socket_cb(void)
{
    nl_cache_mngr_data_ready(route_cache_mngr);
}

void
ind_ovs_port_init(void)
{
    struct nl_cache *cache;
    struct nl_sock *nlsock;
    int nlerr;

    nlsock = nl_socket_alloc();
    if (nlsock == NULL) {
        LOG_ERROR("nl_socket_alloc failed");
        abort();
    }

    if ((nlerr = nl_cache_mngr_alloc(nlsock, NETLINK_ROUTE, 0, &route_cache_mngr)) < 0) {
        LOG_ERROR("nl_cache_mngr_alloc failed: %s", nl_geterror(nlerr));
        abort();
    }

    if ((nlerr = nl_cache_mngr_add(route_cache_mngr, "route/link", link_change_cb, NULL, &cache)) < 0) {
        LOG_ERROR("nl_cache_mngr_add failed: %s", nl_geterror(nlerr));
        abort();
    }

    if (ind_soc_socket_register(nl_cache_mngr_get_fd(route_cache_mngr),
                                (ind_soc_socket_ready_callback_f)route_cache_mngr_socket_cb,
                                NULL) < 0) {
        LOG_ERROR("failed to register socket");
        abort();
    }
}
