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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <AIM/aim.h>
#include <l2table/l2table.h>

#ifdef USE_CALLGRIND
#include <valgrind/callgrind.h>
#else
#define CALLGRIND_START_INSTRUMENTATION
#define CALLGRIND_STOP_INSTRUMENTATION
#endif

const int num_iters = 10;
const int num_flows = 100*1000;
const int num_lookups_per_flow = 5;

uint64_t total_elapsed = 0;

struct sample_key {
    uint8_t mac[L2TABLE_MAC_LEN];
    uint16_t vlan_id;
};

static uint64_t
monotonic_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return ((uint64_t)tp.tv_sec * 1000*1000*1000) + tp.tv_nsec;
}

static void
make_random_key(struct sample_key *key)
{
    int i;
    for (i = 0; i < sizeof(key->mac); i++) {
        key->mac[i] = random();
    }

    key->vlan_id = random() & 0xffff;
}

static void
benchmark_iteration(void)
{
    int i, j;

    struct sample_key *sample_keys = calloc(num_flows, sizeof(*sample_keys));
    struct l2table *t = l2table_create(random());

    for (i = 0; i < num_flows; i++) {
        make_random_key(&sample_keys[i]);
        sample_keys[i].vlan_id &= 0xfff;
        if (l2table_insert(t, sample_keys[i].mac, sample_keys[i].vlan_id, i, i) < 0) {
            abort();
        }
    }

    uint64_t start_time = monotonic_ns();

    CALLGRIND_START_INSTRUMENTATION;

    for (i = 0; i < num_lookups_per_flow; i++) {
        for (j = 0; j < num_flows; j++) {
            uint32_t out_port;
            uint32_t metadata;
            if (l2table_lookup(t, sample_keys[j].mac, sample_keys[j].vlan_id, &out_port, &metadata) < 0) {
                abort();
            }
        }
    }

    uint64_t end_time = monotonic_ns();

    CALLGRIND_STOP_INSTRUMENTATION;

    for (i = 0; i < num_flows; i++) {
        if (l2table_remove(t, sample_keys[i].mac, sample_keys[i].vlan_id) < 0) {
            abort();
        }
    }

    free(sample_keys);
    l2table_destroy(t);

    uint64_t elapsed = end_time - start_time;
    total_elapsed += elapsed;
}

int main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    CALLGRIND_STOP_INSTRUMENTATION;

    int i;
    for (i = 0; i < num_iters; i++) {
        benchmark_iteration();
    }

    double avg_time = (total_elapsed*1.0)/(num_flows*num_lookups_per_flow*num_iters);
    fprintf(stderr, "average lookup time: %.3f ns\n", avg_time);

    return 0;
}
