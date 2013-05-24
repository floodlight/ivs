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

/******************************************************************************
 *
 *  /module/inc/portmanager.h
 *
 *  PortManager Public Interface
 *
 *****************************************************************************/


#ifndef __PORTMANAGER_H__
#define __PORTMANAGER_H__


#include <indigo/port_manager.h>
#include <indigo/forwarding.h>
#include <indigo/of_state_manager.h>


/**
 * Configuration structure for the configuration manager
 * @param periodic_event_ms Time out in ms for periodic event checking
 * @param flags Currently ignored
 */

typedef struct ind_port_config_s {
  unsigned of_version; /**< OF protocol version to use; see LOXI */
  unsigned max_ports; /**< Maximum number of OpenFlow ports */
} ind_port_config_t;

extern indigo_error_t ind_port_base_mac_addr_set(of_mac_addr_t *base_mac);

/**
 * Initialize the port manager
 * @param config The port manager specific config data
 * @returns An error code
 */

extern indigo_error_t ind_port_init(ind_port_config_t *config);

/**
 * Enable set/get for the port manager
 */

extern indigo_error_t ind_port_enable_set(int enable);
extern indigo_error_t ind_port_enable_get(int *enable);

/**
 * Disable/dealloc call for the port manager
 */

extern indigo_error_t ind_port_finish(void);

extern unsigned ind_port_packet_in_is_enabled(of_port_no_t of_port_num);

#endif /* __PORTMANAGER_H__ */
