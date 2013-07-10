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
#include <flowtable/flowtable.h>

#ifdef USE_CALLGRIND
#include <valgrind/callgrind.h>
#else
#define CALLGRIND_START_INSTRUMENTATION
#define CALLGRIND_STOP_INSTRUMENTATION
#endif

const int num_iters = 100;
const int num_flows = 20000;
const int num_lookups_per_flow = 5;
const int max_unique_masks = 8;

uint32_t ind_ovs_salt = 42;

uint64_t total_elapsed = 0;

static uint64_t
monotonic_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return ((uint64_t)tp.tv_sec * 1000*1000*1000) + tp.tv_nsec;
}

static void
make_random_mask(struct flowtable_key *mask)
{
    memset(mask, 0, sizeof(*mask));
    mask->data[0] = 0xffffffffffffffff;
    mask->data[1] = 0x00000000ffffffff;
    mask->data[FLOWTABLE_KEY_SIZE/8-1] = random()%max_unique_masks;
}

static void
make_random_key(struct flowtable_key *key, const struct flowtable_key *mask)
{
    int i;
    for (i = 0; i < FLOWTABLE_KEY_SIZE/8; i++) {
        key->data[i] = 0;
        int j;
        for (j = 0; j < 8; j++) {
            key->data[i] <<= 8;
            key->data[i] ^= random();
        }
        key->data[i] &= mask->data[i];
    }
}

static void
benchmark_iteration(void)
{
    int i, j;

    struct flowtable_entry *ftes = calloc(num_flows, sizeof(*ftes));
    struct flowtable *ft = flowtable_create();

    for (i = 0; i < num_flows; i++) {
        struct flowtable_key key, mask;
        make_random_mask(&mask);
        make_random_key(&key, &mask);
        flowtable_entry_init(&ftes[i], &key, &mask, i % 4);
        flowtable_insert(ft, &ftes[i]);
    }

    uint64_t start_time = monotonic_ns();

    CALLGRIND_START_INSTRUMENTATION;

    for (i = 0; i < num_lookups_per_flow; i++) {
        for (j = 0; j < num_flows; j++) {
            (void) flowtable_match(ft, &ftes[j].key);
        }
    }

    uint64_t end_time = monotonic_ns();

    CALLGRIND_STOP_INSTRUMENTATION;

    for (i = 0; i < num_flows; i++) {
        flowtable_remove(ft, &ftes[i]);
    }

    free(ftes);
    flowtable_destroy(ft);

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
