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

#include <ivs/ivs.h>
#include <indigo/forwarding.h>

static struct vlan_counters vcounters[4096];

void
indigo_fwd_vlan_stats_get(uint16_t vlan_vid, indigo_fi_vlan_stats_t *vlan_stats)
{
    if (vlan_vid < 1 || vlan_vid > 4095) return;

    AIM_ASSERT(vlan_stats != NULL);

    vlan_stats->rx_bytes = vcounters[vlan_vid].rx_stats.bytes;
    vlan_stats->rx_packets = vcounters[vlan_vid].rx_stats.packets;
    vlan_stats->tx_bytes = vcounters[vlan_vid].tx_stats.bytes;
    vlan_stats->tx_packets = vcounters[vlan_vid].tx_stats.packets;
}

indigo_error_t
ind_ovs_rx_vlan_stats_select(uint16_t vlan_vid, struct ind_ovs_flow_stats **vlan_stats)
{
    if (vlan_vid < 1 || vlan_vid > 4095) {
        return INDIGO_ERROR_PARAM;
    }

    *vlan_stats = &vcounters[vlan_vid].rx_stats;

    return INDIGO_ERROR_NONE;
}

indigo_error_t
ind_ovs_tx_vlan_stats_select(uint16_t vlan_vid, struct ind_ovs_flow_stats **vlan_stats)
{
    if (vlan_vid < 1 || vlan_vid > 4095) {
        return INDIGO_ERROR_PARAM;
    }

    *vlan_stats = &vcounters[vlan_vid].tx_stats;

    return INDIGO_ERROR_NONE;
}
