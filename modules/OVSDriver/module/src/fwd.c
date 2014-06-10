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

/**
 * Stats for packet in
 */
uint64_t ind_fwd_packet_in_packets;
uint64_t ind_fwd_packet_in_bytes;
uint64_t ind_fwd_packet_out_packets;
uint64_t ind_fwd_packet_out_bytes;

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

    ++ind_fwd_packet_in_packets;
    ind_fwd_packet_in_bytes += len;

    return indigo_core_packet_in(of_packet_in);
}

/* Check for a single output to OFPP_TABLE */

static bool
check_for_table_action(of_list_action_t *actions)
{
    of_action_t action;

    if (of_list_action_first(actions, &action) < 0) {
        return false;
    }

    if (action.header.object_id != OF_ACTION_OUTPUT) {
        return false;
    }

    of_port_no_t port_no;
    of_action_output_port_get(&action.output, &port_no);
    if (port_no != OF_PORT_DEST_USE_TABLE) {
        return false;
    }

    if (of_list_action_next(actions, &action) == 0) {
        return false;
    }

    return true;
}

/** \brief Handle packet out request from Core */

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *of_packet_out)
{
    of_port_no_t     of_port_num;
    of_list_action_t of_list_action[1];
    of_octets_t      of_octets[1];

    of_packet_out_in_port_get(of_packet_out, &of_port_num);
    of_packet_out_data_get(of_packet_out, of_octets);
    of_packet_out_actions_bind(of_packet_out, of_list_action);

    bool use_table = check_for_table_action(of_list_action);

    int netlink_pid;
    if (use_table) {
        if (of_port_num == OF_PORT_DEST_CONTROLLER) {
            of_port_num = OF_PORT_DEST_LOCAL;
        }
        /* Send the packet to in_port's upcall thread */
        struct ind_ovs_port *in_port = ind_ovs_port_lookup(of_port_num);
        if (in_port == NULL) {
            LOG_ERROR("controller specified an invalid packet-out in_port: 0x%x", of_port_num);
            return INDIGO_ERROR_PARAM;
        }
        netlink_pid = nl_socket_get_local_port(in_port->notify_socket);
    } else {
        /* Send the packet back to ourselves with the full key */
        netlink_pid = nl_socket_get_local_port(ind_ovs_socket);
    }

    /* Create the OVS_PACKET_CMD_EXECUTE message which will be used twice: once
     * to ask the kernel to parse the packet, and then again with the real actions. */
    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_packet_family, OVS_PACKET_CMD_EXECUTE);

    /*
    * The key attribute sent to the kernel only needs to have the metadata:
    * in_port, priority, etc. The kernel parses the packet to get the rest.
    */
    struct nlattr *key = nla_nest_start(msg, OVS_PACKET_ATTR_KEY);
    if (of_port_num < IND_OVS_MAX_PORTS) {
        nla_put_u32(msg, OVS_KEY_ATTR_IN_PORT, of_port_num);
    } else if (of_port_num == OF_PORT_DEST_LOCAL) {
        nla_put_u32(msg, OVS_KEY_ATTR_IN_PORT, OVSP_LOCAL);
    } else {
        /* Can't have an empty key. */
        nla_put_u32(msg, OVS_KEY_ATTR_PRIORITY, 0);
    }
    nla_nest_end(msg, key);

    nla_put(msg, OVS_PACKET_ATTR_PACKET, of_octets->bytes, of_octets->data);

    struct nlattr *actions = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);
    struct nlattr *action_attr = nla_nest_start(msg, OVS_ACTION_ATTR_USERSPACE);
    nla_put_u32(msg, OVS_USERSPACE_ATTR_PID, netlink_pid);
    nla_nest_end(msg, action_attr);
    nla_nest_end(msg, actions);

    /* Send the first message */
    int err = nl_send_auto(ind_ovs_socket, msg);
    if (err < 0) {
        LOG_ERROR("nl_send failed: %s", nl_geterror(err));
        ind_ovs_nlmsg_freelist_free(msg);
        return INDIGO_ERROR_UNKNOWN;
    }

    if (use_table) {
        /* An upcall thread will forward the packet */
        ind_ovs_nlmsg_freelist_free(msg);
        return INDIGO_ERROR_NONE;
    }

    /* Receive the OVS_PACKET_CMD_ACTION we just caused */
    struct nl_msg *reply_msg = ind_ovs_recv_nlmsg(ind_ovs_socket);
    if (reply_msg == NULL) {
        LOG_ERROR("ind_ovs_recv_nlmsg failed: %s", strerror(errno));
        ind_ovs_nlmsg_freelist_free(msg);
        return INDIGO_ERROR_UNKNOWN;
    }

    struct nlmsghdr *nlh = nlmsg_hdr(reply_msg);
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        assert(nlh->nlmsg_seq == nlmsg_hdr(msg)->nlmsg_seq);
        LOG_ERROR("Kernel failed to parse packet-out data");
        ind_ovs_nlmsg_freelist_free(msg);
        ind_ovs_nlmsg_freelist_free(reply_msg);
        return INDIGO_ERROR_UNKNOWN;
    }

    /* Parse the reply to get the flow key */
    assert(nlh->nlmsg_type == ovs_packet_family);
#ifndef NDEBUG
    struct genlmsghdr *gnlh = (void *)(nlh + 1);
    assert(gnlh->cmd == OVS_PACKET_CMD_ACTION);
#endif
    key = nlmsg_find_attr(nlh,
                          sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
                          OVS_PACKET_ATTR_KEY);
    assert(key);

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key(key, &pkey);

    ind_ovs_nlmsg_freelist_free(reply_msg);

    /* Discard the actions list added earlier */
    nlmsg_hdr(msg)->nlmsg_len -= nla_total_size(nla_len(actions));

    /* Add the real actions generated from the kernel's flow key */
    struct xbuf xbuf;
    xbuf_init(&xbuf);
    ind_ovs_translate_openflow_actions(of_list_action, &xbuf, false);
    struct nlattr *actions_attr = nla_nest_start(msg, OVS_PACKET_ATTR_ACTIONS);
    ind_ovs_translate_actions(&pkey, &xbuf, msg);
    ind_ovs_nla_nest_end(msg, actions_attr);
    xbuf_cleanup(&xbuf);

    /* Send the second message */
    if (ind_ovs_transact(msg) < 0) {
        LOG_ERROR("OVS_PACKET_CMD_EXECUTE failed");
        return INDIGO_ERROR_UNKNOWN;
    }

    ++ind_fwd_packet_out_packets;
    ind_fwd_packet_out_packets += of_octets->bytes;

    return INDIGO_ERROR_NONE;
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
