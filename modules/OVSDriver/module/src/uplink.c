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
#include "ovsdriver_log.h"
#include <BigList/biglist.h>
#include <net/if.h>

/* List of string interface names */
static biglist_t *uplinks = NULL;

static of_port_no_t current_uplink = OF_PORT_DEST_NONE;

void
ind_ovs_uplink_add(const char *name)
{
    uplinks = biglist_append(uplinks, strdup(name));
}

bool
ind_ovs_uplink_check_by_name(const char *name)
{
    biglist_t *element;
    char *str;
    BIGLIST_FOREACH_DATA(element, uplinks, char *, str) {
        if (!strcmp(name, str)) {
            return true;
        }
    }
    return false;
}

bool
ind_ovs_uplink_check(of_port_no_t port_no)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return false;
    }
    return port->is_uplink;
}

of_port_no_t
ind_ovs_uplink_select(void)
{
    return current_uplink;
}

static bool
is_valid_uplink(uint32_t port_no)
{
    if (port_no > IND_OVS_MAX_PORTS) {
        return false;
    }
    struct ind_ovs_port *port = ind_ovs_ports[port_no];
    return port && port->is_uplink && port->ifflags & IFF_RUNNING;
}

/*
 * Called whenever an uplink is added, removed, or link status changed.
 * May select a new port to be returned by ind_ovs_uplink_select.
 */
void
ind_ovs_uplink_reselect(void)
{
    /* Sticky - keep current uplink if it's still good */
    if (is_valid_uplink(current_uplink)) {
        AIM_LOG_VERBOSE("Keeping same uplink");
        return;
    }

    /* Pick first valid uplink */
    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        if (is_valid_uplink(i)) {
            current_uplink = i;
            AIM_LOG_VERBOSE("Selected uplink %s", ind_ovs_ports[i]->ifname);
            return;
        }
    }

    current_uplink = OF_PORT_DEST_NONE;
    AIM_LOG_VERBOSE("No uplinks available");
}
