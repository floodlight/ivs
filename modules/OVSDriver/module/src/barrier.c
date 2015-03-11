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

/*
 * Deferred kernel flow revalidation
 *
 * This module provides the function 'ind_ovs_barrier_defer_revalidation' which
 * schedules a kflow revalidation to run the next time the given connection
 * receives a barrier request. This allows multiple flow-mods (for example) to
 * share the expensive revalidation processing.
 */

#include "ovs_driver_int.h"
#include <indigo/of_state_manager.h>
#include <indigo/of_connection_manager.h>
#include <SocketManager/socketmanager.h>
#include <unistd.h>

#define MAX_BLOCKED_CXNS 8

struct blocked_cxn {
    indigo_cxn_id_t cxn_id;
    indigo_cxn_barrier_blocker_t blocker;
};

static void revalidate(void);
static void barrier_timer(void *cookie);

/* Map from cxn_id to a barrier blocker */
static struct blocked_cxn blocked_cxns[MAX_BLOCKED_CXNS];
static bool barrier_timer_active = false;

DEBUG_COUNTER(blocked_cxns_full, "ovsdriver.barrier.blocked_cxns_full",
              "Early revalidation caused by full blocked_cxns table");
DEBUG_COUNTER(timer_expired, "ovsdriver.barrier.timer_expired",
              "Revalidation caused by barrier timer expiration");

void
ind_ovs_barrier_defer_revalidation(indigo_cxn_id_t cxn_id)
{
    struct blocked_cxn *blocked_cxn = NULL;
    AIM_LOG_TRACE("deferring revalidation for cxn %d", cxn_id);

    int i;
    for (i = 0; i < MAX_BLOCKED_CXNS; i++) {
        if (blocked_cxns[i].cxn_id == cxn_id) {
            AIM_LOG_TRACE("cxn %d already blocked", cxn_id);
            return;
        } else if (blocked_cxns[i].cxn_id == INDIGO_CXN_ID_UNSPECIFIED) {
            blocked_cxn = &blocked_cxns[i];
        }
    }

    if (!blocked_cxn) {
        debug_counter_inc(&blocked_cxns_full);
        AIM_LOG_WARN("blocked connection table full");
        revalidate();
        /* blocked_cxns table empty, retry */
        ind_ovs_barrier_defer_revalidation(cxn_id);
        return;
    }

    AIM_LOG_TRACE("blocking cxn %d", cxn_id);
    blocked_cxn->cxn_id = cxn_id;
    indigo_cxn_block_barrier(cxn_id, &blocked_cxn->blocker);

    if (!barrier_timer_active) {
        ind_soc_timer_event_register_with_priority(barrier_timer, NULL, 1000,
                                                   IND_SOC_LOWEST_PRIORITY);
        barrier_timer_active = true;
    }
}

/*
 * Schedule a revalidation not triggered by an OpenFlow connection
 *
 * Used for port status changes. For the next 100ms, any other port status
 * changes will be revalidated at the same time as this one. However the
 * controller will likely react to the event more quickly and force a
 * revalidation before this timer expires.
 */
void
ind_ovs_barrier_defer_revalidation_internal(void)
{
    if (!barrier_timer_active) {
        ind_soc_timer_event_register_with_priority(barrier_timer, NULL, 100,
                                                   IND_SOC_LOWEST_PRIORITY);
        barrier_timer_active = true;
    }
}

static void
revalidate(void)
{
    AIM_LOG_TRACE("revalidating all kernel flows");

    ind_ovs_kflow_invalidate_all();
    ind_ovs_upcall_respawn();

    int i;
    for (i = 0; i < MAX_BLOCKED_CXNS; i++) {
        if (blocked_cxns[i].cxn_id != INDIGO_CXN_ID_UNSPECIFIED) {
            AIM_LOG_TRACE("unblocking cxn %d", blocked_cxns[i].cxn_id);
            indigo_cxn_unblock_barrier(&blocked_cxns[i].blocker);
            blocked_cxns[i].cxn_id = INDIGO_CXN_ID_UNSPECIFIED;
        }
    }

    if (barrier_timer_active) {
        ind_soc_timer_event_unregister(barrier_timer, NULL);
        barrier_timer_active = false;
    }
}

/*
 * Some controllers, like the reference implementation, don't send barriers
 * after flow-mods. For IVS to be usable with these controllers we need
 * to eventually revalidate the kernel flow table and spawn new upcall
 * processes. This 1-second timeout isn't ideal for a reactive controller
 * but it's sufficient for ping. The timeout is relatively long to avoid
 * unnecessary kflow revalidation when using a proactive controller that
 * does send barriers.
 */
static void
barrier_timer(void *cookie)
{
    AIM_LOG_VERBOSE("Barrier timer fired");
    debug_counter_inc(&timer_expired);
    revalidate();
}

static void
barrier_received(indigo_cxn_id_t cxn_id, void *cookie)
{
    int i;
    for (i = 0; i < MAX_BLOCKED_CXNS; i++) {
        if (blocked_cxns[i].cxn_id == cxn_id) {
            revalidate();
            return;
        }
    }

    AIM_LOG_TRACE("cxn %d was not blocked", cxn_id);
}

void
ind_ovs_barrier_init(void)
{
    int i;
    for (i = 0; i < MAX_BLOCKED_CXNS; i++) {
        blocked_cxns[i].cxn_id = INDIGO_CXN_ID_UNSPECIFIED;
    }

    indigo_cxn_barrier_notify_register(barrier_received, NULL);
}
