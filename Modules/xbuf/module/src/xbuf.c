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

#include <xbuf/xbuf.h>

#define XBUF_INITIAL_LEN 64

void
xbuf_init(struct xbuf *xbuf)
{
    xbuf->data = NULL;
    xbuf->length = 0;
    xbuf->allocated = 0;
    xbuf_resize(xbuf, XBUF_INITIAL_LEN);
}

void
xbuf_cleanup(struct xbuf *xbuf)
{
    free(xbuf->data);
}

/* From http://locklessinc.com/articles/next_pow2/ */
static inline int
next_pow2(uint32_t x)
{
    x -= 1;
    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    return x + 1;
}

void
xbuf_resize(struct xbuf *xbuf, uint32_t new_len)
{
    xbuf->allocated = next_pow2(new_len);
    xbuf->data = realloc(xbuf->data, xbuf->allocated);
    AIM_TRUE_OR_DIE(xbuf->data != NULL, "failed to allocate xbuf");
}
