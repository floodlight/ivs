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
 * Bottom halves are the mechanism for upcall handlers to defer work, like
 * installing flows, to the main event loop. This is done to avoid concurrency
 * issues between the main event loop and upcalls and to reduce upcall latency.
 */
#include "ovs_driver_int.h"
#include <unistd.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include "SocketManager/socketmanager.h"

#define IND_OVS_BH_MAX_QUEUE_LEN 100

enum ind_ovs_bh_request_type {
    IND_OVS_BH_REQUEST_KFLOW,
    IND_OVS_BH_REQUEST_PKTIN,
};

struct ind_ovs_bh_request {
    struct list_links links;
    enum ind_ovs_bh_request_type type;
    int len; /* Total length of netlink attrs */

    /* Only for packet-in */
    uint32_t in_port;
    int reason;

    /* Netlink attrs follow */
    struct nlattr attr_head[0];
};

static void ind_ovs_bh_enqueue(struct ind_ovs_bh_request *req);

/* Bottom-half requests to be handled in the main event loop. */
static struct list_head ind_ovs_bh_requests;

/* Length of the ind_ovs_bh_requests list */
static int ind_ovs_bh_queue_len;

/* Eventfd to upcalls to wake up main event loop to run bottom halves. */
static int ind_ovs_bh_eventfd;

/* Lock to protect eventfd and request queue */
static pthread_mutex_t ind_ovs_bh_lock = PTHREAD_MUTEX_INITIALIZER;

/* TODO figure out interaction with flow-mods, need a generation counter? */
void
ind_ovs_bh_request_kflow(struct nlattr *key, struct nlattr *actions)
{
    int key_size = nla_total_size(nla_len(key));
    int actions_size = nla_total_size(nla_len(actions));
    struct ind_ovs_bh_request *req = malloc(sizeof(*req) + key_size + actions_size);
    if (req == NULL) {
        LOG_ERROR("failed to allocate bottom-half request");
        return;
    }

    req->type = IND_OVS_BH_REQUEST_KFLOW;
    req->len = key_size + actions_size;
    memcpy(req->attr_head, key, key_size);
    memcpy(((void *)(req->attr_head)) + key_size, actions, actions_size);

    ind_ovs_bh_enqueue(req);
}

void
ind_ovs_bh_request_pktin(uint32_t in_port, struct nlattr *packet, struct nlattr *key, int reason)
{
    int packet_size = nla_total_size(nla_len(packet));
    int key_size = nla_total_size(nla_len(key));
    struct ind_ovs_bh_request *req = malloc(sizeof(*req) + packet_size + key_size);
    if (req == NULL) {
        LOG_ERROR("failed to allocate bottom-half request");
        return;
    }

    req->type = IND_OVS_BH_REQUEST_PKTIN;
    req->len = packet_size + key_size;
    req->in_port = in_port;
    req->reason = reason;
    memcpy(req->attr_head, packet, packet_size);
    memcpy(((void *)(req->attr_head)) + packet_size, key, key_size);

    ind_ovs_bh_enqueue(req);
}

static void
ind_ovs_bh_enqueue(struct ind_ovs_bh_request *req)
{
    pthread_mutex_lock(&ind_ovs_bh_lock);
    if (ind_ovs_bh_queue_len > IND_OVS_BH_MAX_QUEUE_LEN) {
        pthread_mutex_unlock(&ind_ovs_bh_lock);
        LOG_VERBOSE("dropping bottom-half request: queue too long");
        free(req);
        return;
    }
    list_push(&ind_ovs_bh_requests, &req->links);
    ind_ovs_bh_queue_len++;
    uint64_t v = 1;
    if (write(ind_ovs_bh_eventfd, &v, sizeof(v)) < 0) {
        LOG_ERROR("failed to write to bh eventfd: %s", strerror(errno));
    }
    pthread_mutex_unlock(&ind_ovs_bh_lock);
}

static void
ind_ovs_bh_run()
{
    pthread_mutex_lock(&ind_ovs_bh_lock);

    uint64_t v;
    if (read(ind_ovs_bh_eventfd, &v, sizeof(v)) < 0) {
        LOG_ERROR("read bh eventfd: %s", strerror(errno));
        return;
    }

    struct list_head reqs;
    list_move(&ind_ovs_bh_requests, &reqs);
    ind_ovs_bh_queue_len = 0;

    pthread_mutex_unlock(&ind_ovs_bh_lock);

    LOG_VERBOSE("processing %d bh requests", (int)v);

    struct list_links *cur, *next;
    LIST_FOREACH_SAFE(&reqs, cur, next) {
        struct ind_ovs_bh_request *req = container_of(cur, links, struct ind_ovs_bh_request);
        struct nlattr *attrs[OVS_PACKET_ATTR_MAX+1];
#ifndef NDEBUG
        int ret =
#endif
            nla_parse(attrs, OVS_PACKET_ATTR_MAX, (void*)(req+1), req->len, NULL);
        assert(ret == 0);
        if (req->type == IND_OVS_BH_REQUEST_KFLOW) {
            struct nlattr *key = attrs[OVS_PACKET_ATTR_KEY];
            struct nlattr *actions = attrs[OVS_PACKET_ATTR_ACTIONS];

            struct ind_ovs_parsed_key pkey;
            ind_ovs_parse_key(key, &pkey);

            /* Lookup the flow in the userspace flowtable. */
            /* XXX need to retranslate actions */
            struct ind_ovs_flow *flow;
            if (ind_ovs_lookup_flow(&pkey, &flow) == 0) {
                if (ind_ovs_kflow_add(flow, key, actions) < 0) {
                    LOG_ERROR("Failed to insert kernel flow");
                }
            } else {
                LOG_ERROR("Failed to find flow");
            }
        } else if (req->type == IND_OVS_BH_REQUEST_PKTIN) {
            struct nlattr *packet = attrs[OVS_PACKET_ATTR_PACKET];
            assert(packet);
            struct nlattr *key = attrs[OVS_PACKET_ATTR_KEY];
            assert(key);

            struct ind_ovs_parsed_key pkey;
            ind_ovs_parse_key(key, &pkey);

            of_match_t match;
            ind_ovs_key_to_match(&pkey, &match);

            ind_fwd_pkt_in(req->in_port, nla_data(packet), nla_len(packet), req->reason, &match);
        } else {
            abort();
        }
        free(req);
    }
}

void
ind_ovs_bh_init()
{
    list_init(&ind_ovs_bh_requests);

    ind_ovs_bh_eventfd = eventfd(0, 0);
    if (ind_ovs_bh_eventfd < 0) {
        LOG_ERROR("failed to create eventfd: %s", strerror(errno));
        abort();
    }

    if (ind_soc_socket_register(ind_ovs_bh_eventfd,
                                (ind_soc_socket_ready_callback_f)ind_ovs_bh_run,
                                NULL) < 0) {
        LOG_ERROR("failed to register socket");
        abort();
    }
}
