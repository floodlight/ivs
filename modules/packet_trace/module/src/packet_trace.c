/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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

#include <packet_trace/packet_trace.h>
#include <AIM/aim.h>
#include <AIM/aim_list.h>
#include <unistd.h>

#define AIM_LOG_MODULE_NAME packet_trace
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

#define MAX_PORTS 1024

struct client {
    struct list_links links;
    int fd;
    aim_bitmap_t ports;
};

struct packet {
    uint32_t in_port;
};

static bool check_subscribed(struct client *client);

bool packet_trace_enabled;
static LIST_DEFINE(clients);
static aim_pvs_t *pvs;
static struct packet packet;

void
packet_trace_init(const char *name)
{
    pvs = aim_pvs_buffer_create();

    struct client *client = aim_zmalloc(sizeof(*client));
    client->fd = STDERR_FILENO;
    aim_bitmap_alloc(&client->ports, MAX_PORTS);
    list_push(&clients, &client->links);

    /* TODO allow user to select subset of ports */
    AIM_BITMAP_SET_ALL(&client->ports);

    /* TODO create and register listening socket */
}

void
packet_trace_finish(void)
{
    /* TODO cleanup socket */
}

void
packet_trace_begin(uint32_t in_port)
{
    packet.in_port = in_port;

    packet_trace_enabled = false;

    list_links_t *cur;
    LIST_FOREACH(&clients, cur) {
        struct client *client = container_of(cur, links, struct client);
        if (check_subscribed(client)) {
            packet_trace_enabled = true;
            break;
        }
    }

    packet_trace("--------------------------------------------------------------");
}

void
packet_trace_end(void)
{
    if (!packet_trace_enabled) {
        return;
    }

    char *buf = aim_pvs_buffer_get(pvs);
    int len = aim_pvs_buffer_size(pvs);
    aim_pvs_buffer_reset(pvs);

    list_links_t *cur;
    LIST_FOREACH(&clients, cur) {
        struct client *client = container_of(cur, links, struct client);
        if (!check_subscribed(client)) {
            continue;
        }
        AIM_LOG_TRACE("writing to client %d (%d bytes)", client->fd, len);
        int written = 0;
        while (written < len) {
            int c = write(client->fd, buf+written, len-written);
            if (c < 0) {
                break;
            } else if (c == 0) {
                break;
            } else {
                written += c;
            }
        }
    }

    aim_free(buf);
}

void
packet_trace_internal(const char *fmt, va_list vargs)
{
    aim_vprintf(pvs, fmt, vargs);
    aim_printf(pvs, "\n");
}

static bool
check_subscribed(struct client *client)
{
    return AIM_BITMAP_GET(&client->ports, packet.in_port);
}
