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

static bool check_for_table_action(of_list_action_t *actions);

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

    return INDIGO_ERROR_NONE;
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
