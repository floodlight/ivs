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

struct vlan_counters {
    struct stats_handle rx_stats_handle;
    struct stats_handle tx_stats_handle;
};

static struct vlan_counters vcounters[4096];

void
ind_ovs_vlan_stats_init(void)
{
    int i;
    for (i = 0; i < 4096; i++) {
        stats_alloc(&vcounters[i].rx_stats_handle);
        stats_alloc(&vcounters[i].tx_stats_handle);
    }
}

void
indigo_fwd_vlan_stats_get(uint16_t vlan_vid, indigo_fi_vlan_stats_t *vlan_stats)
{
    if (vlan_vid < 1 || vlan_vid > 4095) return;

    AIM_ASSERT(vlan_stats != NULL);

    struct stats rx_stats, tx_stats;
    stats_get(&vcounters[vlan_vid].rx_stats_handle, &rx_stats);
    stats_get(&vcounters[vlan_vid].tx_stats_handle, &tx_stats);

    vlan_stats->rx_bytes = rx_stats.bytes;
    vlan_stats->rx_packets = rx_stats.packets;
    vlan_stats->tx_bytes = tx_stats.bytes;
    vlan_stats->tx_packets = tx_stats.packets;
}

struct stats_handle *
ind_ovs_rx_vlan_stats_select(uint16_t vlan_vid)
{
    AIM_ASSERT(vlan_vid > 0 && vlan_vid < 4096);

    return &vcounters[vlan_vid].rx_stats_handle;
}

struct stats_handle *
ind_ovs_tx_vlan_stats_select(uint16_t vlan_vid)
{
    AIM_ASSERT(vlan_vid > 0 && vlan_vid < 4096);

    return &vcounters[vlan_vid].tx_stats_handle;
}
