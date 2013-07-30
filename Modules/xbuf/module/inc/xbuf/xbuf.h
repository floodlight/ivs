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
 * xbuf - Expandable contiguous buffer
 *
 * Includes Netlink-compatible attributes.
 */

#ifndef XBUF_H
#define XBUF_H

#include <assert.h>
#include <AIM/aim.h>
#include <sys/socket.h>
#include <linux/netlink.h>

struct xbuf {
    void *data;
    uint32_t length;
    uint32_t allocated;
};

/**
 * Initialize an xbuf
 *
 * Allocates the backing memory.
 */
void xbuf_init(struct xbuf *xbuf);

/**
 * Clean up an xbuf
 *
 * Frees the backing memory.
 */
void xbuf_cleanup(struct xbuf *xbuf);

/**
 * Return a pointer to the backing memory
 *
 * This pointer is valid until the buffer is modified (e.g. xbuf_append).
 */
static inline void *
xbuf_data(struct xbuf *xbuf)
{
    return xbuf->data;
}

/**
 * Return the current length
 */
static inline uint32_t
xbuf_length(struct xbuf *xbuf)
{
    return xbuf->length;
}

/**
 * Resize an xbuf to have at least new_len bytes of backing memory
 *
 * Most users should use xbuf_resize_check. This function does not
 * check whether the requested size is less than the current size,
 * and so may shrink the buffer.
 */
void xbuf_resize(struct xbuf *xbuf, uint32_t new_len);

/**
 * Resize an xbuf to have at least new_len bytes of backing memory (without
 * shrinking)
 */
static inline void
xbuf_resize_check(struct xbuf *xbuf, uint32_t new_len)
{
    if (new_len > xbuf->allocated) {
        xbuf_resize(xbuf, new_len);
    }
}

/**
 * Shrink an xbuf's backing memory to just fit the contents
 */
void xbuf_compact(struct xbuf *xbuf);

/**
 * Set the current length to zero
 */
static inline void
xbuf_reset(struct xbuf *xbuf)
{
    xbuf->length = 0;
}

/* Internal */
static inline void
xbuf_append__(struct xbuf *xbuf, void *data, uint32_t len)
{
    memcpy((char *)xbuf->data + xbuf->length, data, len);
    xbuf->length += len;
}

/**
 * Append data into an xbuf
 */
static inline void
xbuf_append(struct xbuf *xbuf, void *data, uint32_t len)
{
    xbuf_resize_check(xbuf, xbuf->length + len);
    xbuf_append__(xbuf, data, len);
}

/* Internal */
static inline void
xbuf_append_zeroes__(struct xbuf *xbuf, uint32_t len)
{
    memset((char *)xbuf->data + xbuf->length, 0, len);
    xbuf->length += len;
}

/**
 * Append zeroes into an xbuf
 */
static inline void
xbuf_append_zeroes(struct xbuf *xbuf, uint32_t len)
{
    xbuf_resize_check(xbuf, xbuf->length + len);
    xbuf_append_zeroes__(xbuf, len);
}

/**
 * Append a Netlink-compatible attribute into an xbuf
 */
static inline void
xbuf_append_attr(struct xbuf *xbuf, uint16_t type, void *data, uint16_t len)
{
    xbuf_resize_check(xbuf, xbuf->length + NLA_HDRLEN + NLA_ALIGN(len));

    struct nlattr hdr = {
        .nla_len = NLA_HDRLEN + len,
        .nla_type = type,
    };

    xbuf_append__(xbuf, &hdr, sizeof(hdr));
    if (len > 0) {
        xbuf_append__(xbuf, data, len);
        xbuf_append_zeroes__(xbuf, NLA_ALIGN(len) - len);
    }
}

AIM_STATIC_ASSERT(NLA_HDRLEN, NLA_HDRLEN == sizeof(struct nlattr));

/*
 * Return a pointer to the attribute payload
 */
static inline void *
xbuf_payload(struct nlattr *attr)
{
    return attr + 1;
}

/*
 * Return a pointer to the attribute payload, after asserting length
 */
static inline void *
xbuf_payload_check(struct nlattr *attr, size_t len)
{
    assert((size_t)attr->nla_len - NLA_HDRLEN == len);
    return xbuf_payload(attr);
}

/**
 * Begin a nested attribute
 *
 * The result must be passed to xbuf_end_nest().
 */
static inline uint32_t
xbuf_start_nest(struct xbuf *xbuf, uint16_t type)
{
    xbuf_resize_check(xbuf, xbuf->length + NLA_HDRLEN);

    struct nlattr hdr = {
        .nla_len = 0 /* filled out by xbuf_end_nest() */,
        .nla_type = type,
    };

    xbuf_append__(xbuf, &hdr, sizeof(hdr));

    return xbuf->length - NLA_HDRLEN;
}

/**
 * End a nested attribute
 *
 * 'offset' must have been returned by xbuf_start_nest().
 */
static inline void
xbuf_end_nest(struct xbuf *xbuf, uint32_t offset)
{
    struct nlattr *hdr = (void *)((char *)xbuf->data + offset);
    hdr->nla_len = xbuf->length - offset;
}

/**
 * Iterate over attributes
 *
 * '_buf' and '_len' are evaluated multiple times so they should be free of side
 * effects. '_attr' should be a 'struct nlattr *' lvalue.
 */
#define XBUF_FOREACH(_buf, _len, _attr) \
    for ((_attr) = (struct nlattr *)(_buf); \
         (char *)(_attr) < (char *)(_buf) + (_len); \
         (_attr) = (struct nlattr *)((char *)(_attr) + NLA_ALIGN((_attr)->nla_len)))

/**
 * Iterate over child attributes
 *
 * '_parent' should be a 'struct nlattr *'. '_attr' is as in XBUF_FOREACH.
 */
#define XBUF_FOREACH_CHILD(_parent, _attr) XBUF_FOREACH((_parent) + 1, (_parent)->nla_len - NLA_HDRLEN, (_attr))

/**
 * Return a pointer to the attribute payload, after asserting length
 *
 * Uses the given type to check size and cast the result for convenience.
 */
#define XBUF_PAYLOAD(_attr, _type) (_type *)xbuf_payload_check((_attr), sizeof(_type))

#endif
