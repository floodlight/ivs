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
#include <unistd.h>

#define MAX_BLOCKED_CXNS 8

struct blocked_cxn {
    indigo_cxn_id_t cxn_id;
    indigo_cxn_barrier_blocker_t blocker;
};

static void revalidate(void);

/* Map from cxn_id to a barrier blocker */
static struct blocked_cxn blocked_cxns[MAX_BLOCKED_CXNS];

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
        AIM_LOG_WARN("blocked connection table full");
        revalidate();
        /* blocked_cxns table empty, retry */
        ind_ovs_barrier_defer_revalidation(cxn_id);
        return;
    }

    AIM_LOG_TRACE("blocking cxn %d", cxn_id);
    blocked_cxn->cxn_id = cxn_id;
    indigo_cxn_block_barrier(cxn_id, &blocked_cxn->blocker);
}

static void
revalidate(void)
{
    AIM_LOG_TRACE("revalidating all kernel flows");

    ind_ovs_kflow_invalidate_all();

    int i;
    for (i = 0; i < MAX_BLOCKED_CXNS; i++) {
        if (blocked_cxns[i].cxn_id != INDIGO_CXN_ID_UNSPECIFIED) {
            AIM_LOG_TRACE("unblocking cxn %d", blocked_cxns[i].cxn_id);
            indigo_cxn_unblock_barrier(&blocked_cxns[i].blocker);
            blocked_cxns[i].cxn_id = INDIGO_CXN_ID_UNSPECIFIED;
        }
    }
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
