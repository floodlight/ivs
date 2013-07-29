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

/*
 * IVS actions
 *
 * These actions are more efficient for the upcall processing code to parse
 * than the LOCI of_list_action_t. It also helps to abstract some of the
 * differences between OpenFlow 1.0 and 1.3.
 */

#ifndef OVSDRIVER_ACTIONS_H
#define OVSDRIVER_ACTIONS_H

enum {
    IND_OVS_ACTION_OUTPUT, /* of_port_no_t */
    IND_OVS_ACTION_CONTROLLER,
    IND_OVS_ACTION_FLOOD,
    IND_OVS_ACTION_ALL,
    IND_OVS_ACTION_TABLE,
    IND_OVS_ACTION_LOCAL,
    IND_OVS_ACTION_IN_PORT,
    IND_OVS_ACTION_NORMAL,
    IND_OVS_ACTION_SET_ETH_DST, /* of_mac_addr_t */
    IND_OVS_ACTION_SET_ETH_SRC, /* of_mac_addr_t */
    IND_OVS_ACTION_SET_IPV4_DST, /* uint32_t */
    IND_OVS_ACTION_SET_IPV4_SRC, /* uint32_t */
    IND_OVS_ACTION_SET_IPV4_DSCP, /* uint8_t */
    IND_OVS_ACTION_SET_TCP_DST, /* uint16_t */
    IND_OVS_ACTION_SET_TCP_SRC, /* uint16_t */
    IND_OVS_ACTION_SET_UDP_DST, /* uint16_t */
    IND_OVS_ACTION_SET_UDP_SRC, /* uint16_t */
    IND_OVS_ACTION_SET_TP_DST, /* uint16_t */
    IND_OVS_ACTION_SET_TP_SRC, /* uint16_t */
    IND_OVS_ACTION_SET_VLAN_VID, /* uint16_t */
    IND_OVS_ACTION_SET_VLAN_PCP, /* uint8_t */
    IND_OVS_ACTION_POP_VLAN,
    IND_OVS_ACTION_DEC_NW_TTL,
    IND_OVS_ACTION_SET_TUNNEL_DST, /* uint32_t */
};

#endif
