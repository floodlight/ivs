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

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <uCli/ucli.h>
#include <SocketManager/socketmanager.h>

#define AIM_LOG_MODULE_NAME ivs
#include <AIM/aim_log.h>

#define READ_BUFFER_SIZE 1024
#define LISTEN_BACKLOG 5

struct client {
    int fd;
    char read_buffer[READ_BUFFER_SIZE];
    int read_buffer_offset;
    bool read_finished;
    aim_pvs_t *write_pvs;
    char *write_buffer;
    int write_buffer_offset;
    int write_buffer_len;
    ucli_t *ucli;
};

static void listen_callback(int socket_id, void *cookie, int read_ready, int write_ready, int error_seen);
static void client_callback(int socket_id, void *cookie, int read_ready, int write_ready, int error_seen);
static void destroy_client(struct client *client);

static int listen_socket;

void
ivs_cli_init(const char *path)
{
    ucli_init();

    unlink(path);

    listen_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_socket < 0) {
        perror("socket (CLI)");
        abort();
    }

    struct sockaddr_un saddr;
    memset(&saddr, 0, sizeof(&saddr));
    saddr.sun_family = AF_UNIX;
    strcpy(saddr.sun_path, path);

    if (bind(listen_socket, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind (CLI)");
        abort();
    }

    if (listen(listen_socket, LISTEN_BACKLOG) < 0) {
        perror("listen (CLI)");
        abort();
    }

    indigo_error_t rv = ind_soc_socket_register(listen_socket, listen_callback, NULL);
    if (rv < 0) {
        AIM_DIE("Failed to register CLI socket: %s", indigo_strerror(rv));
    }
}

static void
listen_callback(
    int socket_id,
    void *cookie,
    int read_ready,
    int write_ready,
    int error_seen)
{
    AIM_LOG_TRACE("Accepting CLI client");

    int fd;
    if ((fd = accept(listen_socket, NULL, NULL)) < 0) {
        AIM_LOG_ERROR("Failed to accept on CLI socket: %s", strerror(errno));
        return;
    }

    struct client *client = aim_zmalloc(sizeof(*client));
    client->fd = fd;
    client->write_pvs = aim_pvs_buffer_create();
    client->ucli = ucli_create("ivs", NULL, NULL);

    indigo_error_t rv = ind_soc_socket_register(fd, client_callback, client);
    if (rv < 0) {
        AIM_LOG_ERROR("Failed to register CLI client socket: %s", indigo_strerror(rv));
        return;
    }
}

static void
client_callback(
    int socket_id,
    void *cookie,
    int read_ready,
    int write_ready,
    int error_seen)
{
    struct client *client = cookie;
    AIM_ASSERT(socket_id == client->fd);

    if (error_seen) {
        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        getsockopt(socket_id, SOL_SOCKET, SO_ERROR, &socket_error, &len);
        AIM_LOG_INFO("Error seen on CLI socket: %s", strerror(socket_error));
        destroy_client(client);
        return;
    }

    if (read_ready) {
        int c;
        if ((c = read(client->fd, client->read_buffer+client->read_buffer_offset,
                      READ_BUFFER_SIZE - client->read_buffer_offset)) < 0) {
            AIM_LOG_ERROR("read failed: %s", strerror(errno));
            return;
        }

        client->read_buffer_offset += c;

        if (c == 0) {
            /* Peer has shutdown their write side */
            if (client->write_buffer_len == 0 &&
                    aim_pvs_buffer_size(client->write_pvs) == 0) {
                destroy_client(client);
            } else {
                /* We'll destroy the client once we've finished writing to it */
                ind_soc_data_in_pause(client->fd);
                client->read_finished = true;
            }
            return;
        }

        /* Process each complete line */
        char *newline;
        char *start = client->read_buffer;
        int remaining = client->read_buffer_offset;
        while ((newline = memchr(start, '\n', remaining))) {
            *newline = '\0';
            ucli_dispatch_string(client->ucli, client->write_pvs, start);
            remaining -= newline - start + 1;
            start = newline + 1;
        }

        /* Move incomplete line (which may be empty) to the beginning of the read buffer */
        if (client->read_buffer != start) {
            memmove(client->read_buffer, start, remaining);
            client->read_buffer_offset = remaining;
        } else if (client->read_buffer_offset == READ_BUFFER_SIZE) {
            AIM_LOG_WARN("Disconnecting CLI client due to too-long line");
            destroy_client(client);
            return;
        }

        if (aim_pvs_buffer_size(client->write_pvs) > 0) {
            ind_soc_data_out_ready(socket_id);
        }
    }

    if (write_ready) {
        /* Copy PVS data into our write buffer and reset PVS */
        if (client->write_buffer == NULL) {
            client->write_buffer = aim_pvs_buffer_get(client->write_pvs);
            client->write_buffer_len = aim_pvs_buffer_size(client->write_pvs);
            client->write_buffer_offset = 0;
            /* aim_pvs_buffer_reset has a bug, workaround it */
            aim_pvs_destroy(client->write_pvs);
            client->write_pvs = aim_pvs_buffer_create();
        }

        int c = send(client->fd,
                     client->write_buffer+client->write_buffer_offset,
                     client->write_buffer_len-client->write_buffer_offset,
                     MSG_NOSIGNAL);
        if (c <= 0) {
            AIM_LOG_ERROR("write failed: %s", strerror(errno));
            destroy_client(client);
            return;
        }

        client->write_buffer_offset += c;

        /* Free our write buffer if we're finished with it */
        if (client->write_buffer_len == client->write_buffer_offset) {
            aim_free(client->write_buffer);
            client->write_buffer_len = client->write_buffer_offset = 0;
            client->write_buffer = NULL;
            if (aim_pvs_buffer_size(client->write_pvs) == 0) {
                ind_soc_data_out_clear(client->fd);
                if (client->read_finished) {
                    destroy_client(client);
                }
            }
        }
    }
}

static void
destroy_client(struct client *client)
{
    ind_soc_socket_unregister(client->fd);
    close(client->fd);
    aim_pvs_destroy(client->write_pvs);
    ucli_destroy(client->ucli);
    aim_free(client->write_buffer);
    aim_free(client);
}
