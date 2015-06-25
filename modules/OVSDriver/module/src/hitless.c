/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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
#include <indigo/of_state_manager.h>

/*
 * Take over management of the kernel flowtable
 *
 * If ind_ovs_hitless is true then until this point we have not touched the
 * kernel flowtable. Flows that were active when the previous instance of
 * IVS died have continued using their kernel flows while this IVS booted
 * and was configured by the controller. New flows have been handled by the
 * upcall threads and likely dropped.
 *
 * The controller sends this message to tell us that it has finished pushing
 * OpenFlow table entries and we're ready to manage the existing flows.
 *
 * Currently this just flushes the kernel flowtable and relies on the upcall
 * threads to figure out what should go back into the kernel flowtable.
 * Future work is to read the flows from the kernel, validate them against the
 * new userspace forwarding state, and modify them if necessary.
 */
static void
handle_takeover(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    if (ind_ovs_hitless) {
        AIM_LOG_INFO("Received takeover message");
        ind_ovs_kflow_flush();
        ind_ovs_hitless = false;
    } else {
        AIM_LOG_VERBOSE("Not in hitless restart mode, ignoring takeover message");
    }
}

static indigo_core_listener_result_t
message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    switch (msg->object_id) {
    case OF_BSN_TAKEOVER:
        handle_takeover(cxn_id, msg);
        return INDIGO_CORE_LISTENER_RESULT_DROP;

    default:
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
}

void
ind_ovs_hitless_init(void)
{
    indigo_core_message_listener_register(message_listener);
}
