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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>
#include <tcam/tcam.h>
#include <assert.h>

#define TCAM_KEY_SIZE 112

struct tcam_key {
    uint64_t data[TCAM_KEY_SIZE/8];
};

static struct tcam_key
make_key(uint64_t pattern)
{
    struct tcam_key key;
    int i;

    for (i = 0; i < TCAM_KEY_SIZE/8; i++) {
        key.data[i] = pattern;
    }

    return key;
}

static void
test_basic(void)
{
    struct tcam *tcam = tcam_create(sizeof(struct tcam_key), 42);

    struct tcam_key key, mask;
    struct tcam_entry A, B, C, *match;

    /* Exact match, normal priority */
    key = make_key(0x12345678);
    mask = make_key(~0);
    tcam_insert(tcam, &A, &key, &mask, 1000);

    /* Exact match, low priority */
    key = make_key(0x12345678);
    mask = make_key(~0);
    tcam_insert(tcam, &B, &key, &mask, 0);

    /* Wildcarded, low priority */
    key = make_key(0x00005678);
    mask = make_key(0x0000ffff);
    tcam_insert(tcam, &C, &key, &mask, 0);

    /* Should match A */
    key = make_key(0x12345678);
    match = tcam_match(tcam, &key);
    assert(match == &A);

    /* Should match C */
    key = make_key(0x22345678);
    match = tcam_match(tcam, &key);
    assert(match == &C);

    /* Should not match anything */
    key = make_key(0x12345679);
    match = tcam_match(tcam, &key);
    assert(match == NULL);

    /* Remove A */
    tcam_remove(tcam, &A);

    /* Should match C */
    key = make_key(0x12345678);
    match = tcam_match(tcam, &key);
    assert(match == &C);

    /* Remove C */
    tcam_remove(tcam, &C);

    /* Should match B */
    key = make_key(0x12345678);
    match = tcam_match(tcam, &key);
    assert(match == &B);

    /* Remove B */
    tcam_remove(tcam, &B);

    /* Should not match anything */
    key = make_key(0x12345678);
    match = tcam_match(tcam, &key);
    assert(match == NULL);

    tcam_destroy(tcam);
}

/*
 * Overfill the table and ensure everything can still be matched.
 *
 * The lower bits of the key are unique for every entry, and the mask is exact
 * on these bits. The upper bits of the key are zero, and the mask of these
 * bits is chosen from 100 different masks.
 */
static void
test_collisions(void)
{
    const int n = 16384 * 3;
    const int num_masks = 100;
    struct tcam *tcam = tcam_create(sizeof(struct tcam_key), 42);

    struct tcam_entry *es = calloc(n, sizeof(*es));
    assert(es);

    int i;
    struct tcam_key key, mask;

    /* Add entries */
    for (i = 0; i < n; i++) {
        key = make_key(i);
        mask = make_key(((uint64_t)(i % num_masks) << 32) | 0xffffffff);
        assert(tcam_match(tcam, &key) == NULL);
        tcam_insert(tcam, &es[i], &key, &mask, 0);
        assert(tcam_match(tcam, &key) == &es[i]);
    }

    /* Match on overfull table */
    for (i = 0; i < n; i++) {
        key = make_key(i);
        assert(tcam_match(tcam, &key) == &es[i]);
    }

    /* Remove entries */
    for (i = 0; i < n; i++) {
        key = make_key(i);
        assert(tcam_match(tcam, &key) == &es[i]);
        tcam_remove(tcam, &es[i]);
        assert(tcam_match(tcam, &key) == NULL);
    }

    tcam_destroy(tcam);

    free(es);
}

/*
 * Using random tcam entries and lookup keys (but unique priorities), compare
 * the tcam to a reference implementation.
 */
static void
test_random(void)
{
    const int num_entries = 10000;
    const int num_lookups = 10000;
    const int num_masks = 128;
    struct tcam *tcam = tcam_create(sizeof(struct tcam_key), 42);

    struct tcam_entry *es = calloc(num_entries, sizeof(*es));
    assert(es);

    int i;
    struct tcam_key key, mask;

    /* Add entries */
    for (i = 0; i < num_entries; i++) {
        uint64_t mask_pattern = rand() % num_masks;
        key = make_key(rand() & mask_pattern);
        mask = make_key(mask_pattern);
        tcam_insert(tcam, &es[i], &key, &mask, i);
        assert(tcam_match(tcam, &key) == &es[i]);
    }

    /* Random lookups */
    for (i = 0; i < num_lookups; i++) {
        key = make_key(rand());
        struct tcam_entry *tcam_result = tcam_match(tcam, &key);

        /* Linear search to find highest priority match */
        int j;
        struct tcam_entry *ref_result = NULL;
        for (j = num_entries-1; j >= 0; j--) {
            uint64_t key_pattern = ((struct tcam_key *)es[j].key)->data[0];
            uint64_t mask_pattern = ((struct tcam_key *)es[j].mask)->data[0];
            if ((key.data[0] & mask_pattern) == key_pattern) {
                ref_result = &es[j];
                break;
            }
        }

        AIM_ASSERT(tcam_result == ref_result, "mismatch with reference");
    }

    /* Remove entries */
    for (i = 0; i < num_entries; i++) {
        tcam_remove(tcam, &es[i]);
    }

    tcam_destroy(tcam);

    free(es);
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    test_basic();
    test_collisions();
    test_random();

    return 0;
}
