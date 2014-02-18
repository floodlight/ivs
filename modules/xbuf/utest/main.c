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
#include <xbuf/xbuf.h>
#include <assert.h>
#include <arpa/inet.h>

static void
test_basic(void)
{
    struct xbuf a;
    xbuf_init(&a);

    /* Should be initialized to be empty, but with some backing memory */
    assert(xbuf_length(&a) == 0);
    assert(xbuf_data(&a) != NULL);
    assert(a.allocated == 64);

    /* xbuf_append_zeroes should work */
    xbuf_append_zeroes(&a, 6);
    assert(xbuf_length(&a) == 6);
    assert(memcmp(xbuf_data(&a), "\0\0\0\0\0\0", 6) == 0);
    assert(a.allocated == 64);

    /* xbuf_append should work */
    uint32_t tmp = htonl(0x12345678);
    xbuf_append(&a, &tmp, sizeof(tmp));
    assert(xbuf_length(&a) == 10);
    assert(memcmp(xbuf_data(&a), "\0\0\0\0\0\0\x12\x34\x56\x78", 10) == 0);
    assert(a.allocated == 64);

    /* Should be able to fill the allocated space */
    xbuf_append_zeroes(&a, 54);
    assert(xbuf_length(&a) == 64);
    assert(a.allocated == 64);

    /* Should resize itself when exceeding the allocated space */
    xbuf_append_zeroes(&a, 1);
    assert(xbuf_length(&a) == 65);
    assert(a.allocated == 128);

    /* Should be able to reset to an empty buffer */
    xbuf_reset(&a);
    assert(xbuf_length(&a) == 0);
    assert(a.allocated == 128);

    /* Should be able to compact */
    xbuf_reset(&a);
    xbuf_append_zeroes(&a, 6);
    xbuf_compact(&a);
    assert(xbuf_length(&a) == 6);
    assert(a.allocated == 6);

    /* Should be able to allocate uninitialized space */
    xbuf_reset(&a);
    {
        char *data = xbuf_reserve(&a, 8);
        assert(data == xbuf_data(&a));
        assert(xbuf_length(&a) == 8);
    }
    {
        char *data = xbuf_reserve(&a, 4);
        assert(data == (char *)xbuf_data(&a) + 8);
        assert(xbuf_length(&a) == 12);
    }

    /* Should be able to safely steal the backing memory */
    xbuf_reset(&a);
    xbuf_append(&a, &tmp, sizeof(tmp));
    assert(xbuf_length(&a) == 4);
    assert(memcmp(xbuf_data(&a), "\x12\x34\x56\x78", 4) == 0);
    void *data = xbuf_steal(&a);
    assert(memcmp(data, "\x12\x34\x56\x78", 4) == 0);
    aim_free(data);
    assert(xbuf_length(&a) == 0);

    /* Should be able to append after stealing */
    xbuf_append(&a, &tmp, sizeof(tmp));
    assert(xbuf_length(&a) == 4);
    assert(memcmp(xbuf_data(&a), "\x12\x34\x56\x78", 4) == 0);

    xbuf_cleanup(&a);
}

static void
test_attrs(void)
{
    struct xbuf a;
    xbuf_init(&a);

    /* Empty attribute */
    xbuf_reset(&a);
    xbuf_append_attr(&a, htons(0x1234), NULL, 0);
    assert(xbuf_length(&a) == 4);
    assert(memcmp(xbuf_data(&a), "\x04\x00\x12\x34", 4) == 0);

    /* 1-byte attribute (3 bytes padding) */
    xbuf_reset(&a);
    xbuf_append_attr(&a, htons(0x1234), "\xab", 1);
    assert(xbuf_length(&a) == 8);
    assert(memcmp(xbuf_data(&a), "\x05\x00\x12\x34\xab\x00\x00\x00", 8) == 0);
    assert(*XBUF_PAYLOAD((struct nlattr *)xbuf_data(&a), uint8_t) == 0xab);

    /* 4-byte attribute (no padding) */
    xbuf_reset(&a);
    xbuf_append_attr(&a, htons(0x1234), "\xab\xcd\xef\xff", 4);
    assert(xbuf_length(&a) == 8);
    assert(memcmp(xbuf_data(&a), "\x08\x00\x12\x34\xab\xcd\xef\xff", 8) == 0);
    assert(*XBUF_PAYLOAD((struct nlattr *)xbuf_data(&a), uint32_t) == htonl(0xabcdefff));

    /* 7-byte attribute (1 byte padding) */
    xbuf_reset(&a);
    xbuf_append_attr(&a, htons(0x1234), "\x99\xaa\xbb\xcc\xdd\xee\xff", 7);
    assert(xbuf_length(&a) == 12);
    assert(memcmp(xbuf_data(&a), "\x0b\x00\x12\x34\x99\xaa\xbb\xcc\xdd\xee\xff\x00", 12) == 0);

    xbuf_cleanup(&a);
}

static void
test_nesting(void)
{
    uint32_t offset1, offset2, offset3;

    struct xbuf a;
    xbuf_init(&a);

    /* Empty nesting */
    xbuf_reset(&a);
    offset1 = xbuf_start_nest(&a, htons(0x1234));
    xbuf_end_nest(&a, offset1);
    assert(xbuf_length(&a) == 4);
    assert(memcmp(xbuf_data(&a), "\x04\x00\x12\x34", 4) == 0);

    /* Non-empty nesting */
    xbuf_reset(&a);
    offset1 = xbuf_start_nest(&a, htons(0x1234));
    xbuf_append_attr(&a, htons(0x5678), "\x11\x22\x33\x44", 4);
    xbuf_end_nest(&a, offset1);
    assert(xbuf_length(&a) == 12);
    assert(memcmp(xbuf_data(&a), "\x0c\x00\x12\x34\x08\x00\x56\x78\x11\x22\x33\x44", 12) == 0);

    /* Multiple levels of nesting */
    xbuf_reset(&a);
    offset1 = xbuf_start_nest(&a, htons(0x1234));
    offset2 = xbuf_start_nest(&a, htons(0x5678));
    offset3 = xbuf_start_nest(&a, htons(0x9abc));
    xbuf_end_nest(&a, offset3);
    xbuf_end_nest(&a, offset2);
    xbuf_end_nest(&a, offset1);
    assert(xbuf_length(&a) == 12);
    assert(memcmp(xbuf_data(&a), "\x0c\x00\x12\x34\x08\x00\x56\x78\x04\x00\x9a\xbc", 12) == 0);

    /* Nest across resize */
    xbuf_reset(&a);
    xbuf_resize(&a, 8);
    assert(a.allocated == 8);
    offset1 = xbuf_start_nest(&a, htons(0x1234));
    xbuf_append_attr(&a, htons(0x5678), "\x11\x22\x33\x44", 4);
    xbuf_end_nest(&a, offset1);
    assert(xbuf_length(&a) == 12);
    assert(memcmp(xbuf_data(&a), "\x0c\x00\x12\x34\x08\x00\x56\x78\x11\x22\x33\x44", 12) == 0);
    assert(a.allocated == 16);

    xbuf_cleanup(&a);
}

static void
test_iteration(void)
{
    uint32_t offset;
    int count;
    struct nlattr *attr;

    struct xbuf a;
    xbuf_init(&a);

    /* Iterate over an empty xbuf */
    xbuf_reset(&a);
    count = 0;
    XBUF_FOREACH(xbuf_data(&a), xbuf_length(&a), attr) {
        count++;
    }
    assert(count == 0);

    /* Iterate over a compact empty xbuf */
    xbuf_reset(&a);
    xbuf_compact(&a);
    count = 0;
    XBUF_FOREACH(xbuf_data(&a), xbuf_length(&a), attr) {
        count++;
    }
    assert(count == 0);

    /* Iterate over an xbuf with one attr */
    xbuf_reset(&a);
    xbuf_append_attr(&a, htons(0x1234), NULL, 0);
    count = 0;
    XBUF_FOREACH(xbuf_data(&a), xbuf_length(&a), attr) {
        assert(attr->nla_type == htons(0x1234));
        count++;
    }
    assert(count == 1);

    /* Iterate over an xbuf with multiple attrs */
    xbuf_reset(&a);
    xbuf_append_attr(&a, htons(0xFFF0), NULL, 0);
    xbuf_append_attr(&a, htons(0xFFF1), "\x00", 1);
    xbuf_append_attr(&a, htons(0xFFF2), "\x00\x00", 2);
    count = 0;
    XBUF_FOREACH(xbuf_data(&a), xbuf_length(&a), attr) {
        assert(attr->nla_type == htons(0xFFF0 | count));
        assert(attr->nla_len == count + NLA_HDRLEN);
        count++;
    }
    assert(count == 3);

    /* Iterate over children of an attribute */
    xbuf_reset(&a);
    offset = xbuf_start_nest(&a, 0);
    xbuf_append_attr(&a, htons(0xFFF0), NULL, 0);
    xbuf_append_attr(&a, htons(0xFFF1), "\x00", 1);
    xbuf_append_attr(&a, htons(0xFFF2), "\x00\x00", 2);
    xbuf_end_nest(&a, offset);
    count = 0;
    struct nlattr *parent = xbuf_data(&a);
    XBUF_FOREACH_CHILD(parent, attr) {
        assert(attr->nla_type == htons(0xFFF0 | count));
        assert(attr->nla_len == count + NLA_HDRLEN);
        count++;
    }
    assert(count == 3);

    xbuf_cleanup(&a);
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    test_basic();
    test_attrs();
    test_nesting();
    test_iteration();

    return 0;
}
