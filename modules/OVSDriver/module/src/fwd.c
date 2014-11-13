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

#include "ovs_driver_int.h"
#include <pthread.h>

static pthread_rwlock_t ind_ovs_fwd_rwlock;

indigo_error_t
indigo_fwd_forwarding_features_get(of_features_reply_t *features)
{
    uint32_t capabilities = 0, actions = 0;

    of_features_reply_n_tables_set(features, 1);

    OF_CAPABILITIES_FLAG_FLOW_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_TABLE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_PORT_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_QUEUE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_ARP_MATCH_IP_SET(capabilities, features->version);
    of_features_reply_capabilities_set(features, capabilities);

    if (features->version == OF_VERSION_1_0) {
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_OUTPUT_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_VLAN_VID_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_VLAN_PCP_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_STRIP_VLAN_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_DL_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_DL_DST_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_DST_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_NW_TOS_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_TP_SRC_BY_VERSION(features->version));
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_SET_TP_DST_BY_VERSION(features->version));
#if 0
        OF_FLAG_ENUM_SET(actions,
            OF_ACTION_TYPE_ENQUEUE_BY_VERSION(features->version));
#endif
        of_features_reply_actions_set(features, actions);
    }

    return (INDIGO_ERROR_NONE);
}

void
ind_ovs_fwd_read_lock(void)
{
    pthread_rwlock_rdlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_read_unlock(void)
{
    pthread_rwlock_unlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_write_lock(void)
{
    pthread_rwlock_wrlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_write_unlock(void)
{
    pthread_rwlock_unlock(&ind_ovs_fwd_rwlock);
}

void
ind_ovs_fwd_init(void)
{
    pthread_rwlock_init(&ind_ovs_fwd_rwlock, NULL);
}

void
ind_ovs_fwd_finish(void)
{
    /* Hold this forever. */
    ind_ovs_fwd_write_lock();
}
