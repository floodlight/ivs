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
#include <AIM/aim.h>
#include <l2table/l2table.h>
#include <assert.h>

static uint8_t a[] = "\x01\x02\x03\x04\x05\x06";
static uint8_t b[] = "\x0a\x0b\x0c\x0d\x0e\x0f";
static uint8_t c[] = "\x11\x12\x13\x14\x15\x16";

enum {
    VLAN1 = 1,
    VLAN2,
};

enum {
    PORT1 = 1,
    PORT2,
    PORT3,
};

enum {
    META1 = 1,
    META2,
    META3,
};

static void
test_basic(void)
{
    struct l2table *t = l2table_create(42);
    uint32_t out_port;
    uint32_t metadata;

    /* Nonexistent entry should not be found */
    assert(l2table_lookup(t, a, VLAN1, &out_port, &metadata) == AIM_ERROR_NOT_FOUND);

    /* Add MACs A and B on VLAN1 */
    assert(l2table_insert(t, a, VLAN1, META1, PORT1) == AIM_ERROR_NONE);
    assert(l2table_insert(t, b, VLAN1, META2, PORT2) == AIM_ERROR_NONE);

    /* Find MAC A on VLAN1 */
    assert(l2table_lookup(t, a, VLAN1, &out_port, &metadata) == AIM_ERROR_NONE);
    assert(out_port == PORT1);
    assert(metadata == META1);

    /* Find MAC B on VLAN1 */
    assert(l2table_lookup(t, b, VLAN1, &out_port, &metadata) == AIM_ERROR_NONE);
    assert(out_port == PORT2);
    assert(metadata == META2);

    /* MACs A and B are not on VLAN2 */
    assert(l2table_lookup(t, a, VLAN2, &out_port, &metadata) == AIM_ERROR_NOT_FOUND);
    assert(l2table_lookup(t, b, VLAN2, &out_port, &metadata) == AIM_ERROR_NOT_FOUND);

    /* Add MAC C on VLAN2 */
    assert(l2table_insert(t, c, VLAN2, META3, PORT3) == AIM_ERROR_NONE);

    /* Find C on VLAN2 */
    assert(l2table_lookup(t, c, VLAN2, &out_port, &metadata) == AIM_ERROR_NONE);
    assert(out_port == PORT3);
    assert(metadata == META3);

    /* MAC C already exists on VLAN 2 */
    assert(l2table_insert(t, c, VLAN2, META3, PORT3) == AIM_ERROR_PARAM);

    /* Remove MAC C from VLAN 2 */
    assert(l2table_remove(t, c, VLAN2) == AIM_ERROR_NONE);

    /* MAC C does not exist on VLAN 2 */
    assert(l2table_remove(t, c, VLAN2) == AIM_ERROR_NOT_FOUND);
    assert(l2table_lookup(t, c, VLAN2, &out_port, &metadata) == AIM_ERROR_NOT_FOUND);

    l2table_destroy(t);
}

static void
make_entry(int i, uint8_t mac[6], uint16_t *vlan_id,
           uint32_t *metadata, uint32_t *out_port)
{
    *vlan_id = i & 0xFFF;
    memset(mac, 0, 6);
    *((uint32_t *)mac) = i;
    *metadata = (uint32_t)i;
    *out_port = (uint32_t)i;
}

static void
test_scale(void)
{
    struct l2table *t = l2table_create(42);
    int i;
    const int n = 1000*1000;

    uint8_t mac[6];
    uint16_t vlan_id;
    uint32_t metadata;
    uint32_t out_port;

    uint32_t found_out_port;
    uint32_t found_metadata;

    /* Add many entries */
    for (i = 0; i < n; i++) {
        make_entry(i, mac, &vlan_id, &metadata, &out_port);

        assert(l2table_lookup(t, mac, vlan_id, &found_out_port, &found_metadata) == AIM_ERROR_NOT_FOUND);

        assert(l2table_insert(t, mac, vlan_id, out_port, metadata) == AIM_ERROR_NONE);

        assert(l2table_lookup(t, mac, vlan_id, &found_out_port, &found_metadata) == AIM_ERROR_NONE);
        assert(found_out_port == out_port);
        assert(found_metadata == metadata);
    }

    /* Remove odd-numbered entries */
    for (i = 0; i < n; i++) {
        if (i % 2 == 1) {
            make_entry(i, mac, &vlan_id, &metadata, &out_port);
            assert(l2table_remove(t, mac, vlan_id) == AIM_ERROR_NONE);
        }
    }

    /* Verify even-numbered entries exist while odd-numbered do not */
    for (i = 0; i < n; i++) {
        make_entry(i, mac, &vlan_id, &metadata, &out_port);
        if (i % 2 == 1) {
            assert(l2table_lookup(t, mac, vlan_id, &found_out_port, &found_metadata) == AIM_ERROR_NOT_FOUND);
        } else {
            assert(l2table_lookup(t, mac, vlan_id, &found_out_port, &found_metadata) == AIM_ERROR_NONE);
            assert(found_out_port == out_port);
            assert(found_metadata == metadata);
        }
    }

    /* Reinsert odd-numbered entries */
    for (i = 0; i < n; i++) {
        if (i % 2 == 1) {
            make_entry(i, mac, &vlan_id, &metadata, &out_port);
            assert(l2table_insert(t, mac, vlan_id, out_port, metadata) == AIM_ERROR_NONE);
        }
    }

    /* Remove all entries */
    for (i = 0; i < n; i++) {
        make_entry(i, mac, &vlan_id, &metadata, &out_port);

        assert(l2table_lookup(t, mac, vlan_id, &found_out_port, &found_metadata) == AIM_ERROR_NONE);
        assert(found_out_port == out_port);
        assert(found_metadata == metadata);

        assert(l2table_remove(t, mac, vlan_id) == AIM_ERROR_NONE);

        assert(l2table_lookup(t, mac, vlan_id, &found_out_port, &found_metadata) == AIM_ERROR_NOT_FOUND);
    }


    l2table_destroy(t);
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    test_basic();
    test_scale();

    return 0;
}
