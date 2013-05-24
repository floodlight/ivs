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

/* Non-indigo forwarding/portmanager APIs required by IVS */
/* Remove these when IVS is removed */
#include <Forwarding/forwarding.h>
#include <PortManager/portmanager.h>

indigo_error_t
ind_fwd_init(ind_fwd_config_t *config)
{
    abort();
}

indigo_error_t
ind_fwd_enable_set(int enable)
{
    abort();
}

indigo_error_t
ind_fwd_enable_get(int *enable)
{
    abort();
}

indigo_error_t
ind_fwd_finish(void)
{
    abort();
}

/*
indigo_error_t
ind_port_base_mac_addr_set(of_mac_addr_t *base_mac)
{
    abort();
}
*/

indigo_error_t
ind_port_init(ind_port_config_t *config)
{
    abort();
}

indigo_error_t
ind_port_enable_set(int enable)
{
    abort();
}

indigo_error_t
ind_port_enable_get(int *enable)
{
    abort();
}

indigo_error_t
ind_port_finish(void)
{
    abort();
}

/*
unsigned
ind_port_packet_in_is_enabled(of_port_no_t of_port_num)
{
    abort();
}
*/
