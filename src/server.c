#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <zlib.h>

#include "cacharle/ws/server.h"

#include "cacharle/ws/utils.h"
#include "cacharle/ws/xlibc.h"

// Return values for client_ingest / client_handle_frame:
//   0  -> nothing to report, keep polling
//   1  -> user-visible message written to *msg, caller should return it
//  -1  -> error, caller should remove this client
int  client_ingest(ws_server_t *server,
                   client_t *client,
                   uint8_t *buffer,
                   size_t size,
                   ws_message_t *msg);
int  client_handle_frame(ws_server_t *server,
                         client_t *client,
                         frame_t *frame,
                         ws_message_t *msg);
void client_close(client_t *client, int close_code);
void client_send(client_t *client, void *buffer, size_t size);
void client_send_frame(client_t *client, frame_t *frame);

ws_server_t *ws_server_new(const ws_server_config_t *config)
{
    ws_server_t *server = xmalloc(sizeof(ws_server_t));
    server->clients = xcalloc(SERVER_MAX_CLIENTS, sizeof(client_t));
    if (config->cert_path != NULL)
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        server->ssl_context = SSL_CTX_new(TLS_server_method());
        if (server->ssl_context == NULL)
        {
            ERR_print_errors_fp(stderr);
            xdie("Unable to create SSL context");
        }
        SSL_CTX_use_certificate_file(
            server->ssl_context, config->cert_path, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(server->ssl_context, config->key_path, SSL_FILETYPE_PEM);
        if (!SSL_CTX_check_private_key(server->ssl_context))
            xdie("Private key does not match certificate\n");
    }
    else
        server->ssl_context = NULL;
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    server->clients_count = 0;
    if (server->fd < 0)
        xdie("Couldn't create socket");
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(config->port),
        .sin_addr = {.s_addr = INADDR_ANY},
    };
    // Allow the port to be reused after program end
    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(server->fd, (struct sockaddr *)&addr, sizeof addr) < 0)
        xdie("Couldn't bind socket");
    if (listen(server->fd, 8) < 0)
        xdie("Couldn't listen on socket");
    return server;
}

void ws_server_destroy(ws_server_t *server)
{
    for (size_t i = 0; i < server->clients_count; i++)
    {
        client_close(&server->clients[i], 1001);
        free(server->clients[i].recv_overflow);
        free(server->clients[i].defragmentation_state.payload);
    }
    free(server->clients);
    close(server->fd);
    if (server->ssl_context != NULL)
    {
        SSL_CTX_free(server->ssl_context);
        EVP_cleanup();
    }
    free(server->last_msg_data);
    free(server);
}

int ws_server_recv(ws_server_t *server, ws_message_t *msg, int timeout)
{
    // Invalidate data returned on the previous call.
    free(server->last_msg_data);
    server->last_msg_data = NULL;

    // Drain any per-client overflow left over from a previous call before
    // polling — those bytes are already in our own buffer and poll() won't
    // wake up for them.
    for (size_t i = 0; i < server->clients_count; i++)
    {
        client_t *client = &server->clients[i];
        if (client->recv_overflow_len == 0)
            continue;
        uint8_t *buf = client->recv_overflow;
        size_t len = client->recv_overflow_len;
        client->recv_overflow = NULL;
        client->recv_overflow_len = 0;
        int outcome = client_ingest(server, client, buf, len, msg);
        free(buf);
        if (outcome == 1)
            return 0;
        if (outcome == -1)
        {
            // client_ingest already called client_close(). Remove the
            // zombie from the list so poll() won't see a closed fd.
            free(client->recv_overflow);
            free(client->defragmentation_state.payload);
            if (server->clients_count > 1)
                memmove(server->clients + i,
                        server->clients + i + 1,
                        (server->clients_count - i - 1) * sizeof(client_t));
            server->clients_count--;
            i--;
        }
    }

    while (true)
    {
        struct pollfd pollfds[SERVER_MAX_CLIENTS + 1];
        // Poll the server fd for accept and the clients for recv
        pollfds[0].fd = server->fd;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
        for (size_t i = 0; i < server->clients_count; i++)
        {
            pollfds[i + 1].fd = server->clients[i].fd;
            pollfds[i + 1].events = POLLIN;
            pollfds[i + 1].revents = 0;
        }
        int ret = poll(pollfds, server->clients_count + 1, timeout);
        if (ret < 0)
            xdie("ppoll");
        if (ret == 0)  // Timeout
            return 1;

        // Accept a new client and add it to the client list
        if (pollfds[0].revents & POLLIN)
        {
            if (server->clients_count == SERVER_MAX_CLIENTS)
                xdie("Too many clients");
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof client_addr;
            client_t *client = &server->clients[server->clients_count];
            client->fd = accept(
                server->fd, (struct sockaddr *)&client_addr, &client_addr_len);
            if (client->fd == -1)
                xdie("Unable to accept client");  // TODO: not die
            if (server->ssl_context != NULL)
            {
                client->ssl = SSL_new(server->ssl_context);
                SSL_set_fd(client->ssl, client->fd);
                if (SSL_accept(client->ssl) != 1)
                {
                    ERR_print_errors_fp(stderr);
                    xdie("Unable to accept SSL client");  // TODO: not die
                }
            }
            else
                client->ssl = NULL;
            client->closed = false;
            client->handshake_completed = false;
            client->defragmentation_state.active = false;
            client->defragmentation_state.payload = NULL;
            client->defragmentation_state.payload_length = 0;
            frame_parser_init(&client->parser, client->permessage_deflate.enabled);
            server->clients_count++;

            // Set message to open
            msg->type = WS_MESSAGE_OPEN;
            msg->client_id = client->fd;
            msg->data = NULL;
            msg->len = 0;
            msg->close_code = 0;
            return 0;
        }

        // Check if there is any data to receive from active clients
        bool to_remove[SERVER_MAX_CLIENTS];
        memset(to_remove, 0, SERVER_MAX_CLIENTS);
        int pending_message_index = -1;
        for (size_t i = 0; i < server->clients_count; i++)
        {
            if (pollfds[i + 1].revents & POLLIN)
            {
                uint8_t recv_buffer[RECV_BUFFER_SIZE + 1];
                size_t recv_size;
                client_t *client = &server->clients[i];
                if (client->ssl == NULL)
                {
                    int result = recv(client->fd, recv_buffer, RECV_BUFFER_SIZE, 0);
                    if (result <= 0)
                    {
                        // 0 = orderly shutdown, <0 = error (e.g. ECONNRESET
                        // after we sent a close frame). Either way, drop the
                        // client rather than killing the whole server.
                        to_remove[i] = true;
                        continue;
                    }
                    recv_size = result;
                }
                else
                {
                    int result = SSL_read_ex(
                        client->ssl, recv_buffer, RECV_BUFFER_SIZE, &recv_size);
                    if (result != 1)
                    {
                        int ssl_error = SSL_get_error(client->ssl, result);
                        if (ssl_error == SSL_ERROR_ZERO_RETURN)
                        {
                            to_remove[i] = true;
                            continue;
                        }
                        ERR_print_errors_fp(stderr);
                        xdie("Invalid SSL_read");
                    }
                }
                int outcome =
                    client_ingest(server, client, recv_buffer, recv_size, msg);
                if (outcome == -1)
                    to_remove[i] = true;
                else if (outcome == 1)
                {
                    // A message is ready; stop processing further clients
                    // so we can return it. Any remaining clients will be
                    // handled on the next ws_server_recv call.
                    pending_message_index = (int)i;
                    break;
                }
            }
        }

        // Remove clients who are closed
        for (size_t i = 0; i < server->clients_count; i++)
        {
            if (to_remove[i])
            {
                client_close(&server->clients[i], 1000);
                free(server->clients[i].recv_overflow);
                free(server->clients[i].defragmentation_state.payload);
                if (server->clients_count > 1)
                    memmove(server->clients + i,
                            server->clients + i + 1,
                            server->clients_count - i - 1);
                server->clients_count--;
                i--;
            }
        }

        if (pending_message_index >= 0)
            return 0;
    }

    printf("Clean exit\n");
}

int client_ingest(ws_server_t *server,
                  client_t *client,
                  uint8_t *buffer,
                  size_t size,
                  ws_message_t *msg)
{
    if (!client->handshake_completed)
    {
        buffer[size] = '\0';
        handshake_t handshake;
        handshake_init(&handshake);
        if (!handshake_parse_request(&handshake, (char *)buffer, size))
        {
            handshake_destroy(&handshake);
            client_close(client, 1002);
            return -1;
        }
        handshake.permessage_deflate.server_no_context_takeover = true;
        handshake.permessage_deflate.client_no_context_takeover = true;
        handshake.permessage_deflate.server_max_window_bits = 15;
        handshake.permessage_deflate.client_max_window_bits = 15;
        client->permessage_deflate = handshake.permessage_deflate;
        frame_parser_init(&client->parser, client->permessage_deflate.enabled);
        char response[1024];
        handshake_write_response(&handshake, response, sizeof response);
        client_send(client, response, strlen(response));
        client->handshake_completed = true;
        handshake_destroy(&handshake);
        return 0;
    }

    size_t remaining_size = size;
    while (remaining_size != 0)
    {
        frame_parser_ingest_result_t ingest_result =
            frame_parser_ingest(&client->parser, buffer, size, &remaining_size);
        buffer += size - remaining_size;
        size = remaining_size;
        if (FRAME_PARSER_INGEST_RESULT_IS_ERROR(ingest_result))
        {
            frame_destroy(&client->parser.frame);
            int close_code = 1000;
            switch (ingest_result)
            {
            case FRAME_PARSER_INGEST_RESULT_ERROR:
                close_code = 1000;
                break;
            case FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL:
                close_code = 1002;
                break;
            case FRAME_PARSER_INGEST_RESULT_ERROR_UNSUPPORTED_DATA:
                close_code = 1003;
                break;
            case FRAME_PARSER_INGEST_RESULT_ERROR_INVALID_PAYLOAD:
                close_code = 1007;
                break;
            case FRAME_PARSER_INGEST_RESULT_ERROR_POLICY_VIOLATION:
                close_code = 1008;
                break;
            case FRAME_PARSER_INGEST_RESULT_ERROR_TOO_BIG:
                close_code = 1009;
                break;
            case FRAME_PARSER_INGEST_RESULT_ERROR_EXTENSION_NEEDED:
                close_code = 1010;
                break;
            case FRAME_PARSER_INGEST_RESULT_ERROR_INTERNAL:
                close_code = 1011;
                break;
            default:
                abort();
            }
            client_close(client, close_code);
            return -1;
        }
        else if (ingest_result == FRAME_PARSER_INGEST_RESULT_PENDING)
        {
            return 0;
        }
        else if (ingest_result == FRAME_PARSER_INGEST_RESULT_DONE)
        {
            int handled =
                client_handle_frame(server, client, &client->parser.frame, msg);
            frame_destroy(&client->parser.frame);
            frame_parser_init(&client->parser, client->permessage_deflate.enabled);
            if (handled == -1)
            {
                free(client->defragmentation_state.payload);
                client->defragmentation_state.payload = NULL;
                return -1;
            }
            if (handled == 1)
            {
                // Save any remaining unparsed bytes so the next call can
                // consume them before polling again.
                if (size > 0)
                {
                    client->recv_overflow = xmalloc(size);
                    memcpy(client->recv_overflow, buffer, size);
                    client->recv_overflow_len = size;
                }
                return 1;
            }
        }
    }
    return 0;
}

char *close_status_reason[] = {
    [1000] = "Normal closure",
    [1001] = "Going away",
    [1002] = "Protocol error",
    [1003] = "Unsupported data",
    // 1004 is reserved and should not be used
    // 1005 is reserved and should not be used
    // 1006 is reserved and should not be used
    [1007] = "Invalid payload",
    [1008] = "Policy violation",
    [1009] = "Too big",
    [1010] = "Extension needed",
    [1011] = "Internal error",
    // 1015 is reserved and should not be used
};

void client_close(client_t *client, int close_code)
{
    if (client->closed)
        return;
    client->closed = true;
    char *close_reason = close_status_reason[close_code];
    size_t payload_length = 2 + strlen(close_reason);
    frame_t close_frame = {
        .final = true,
        .opcode = FRAME_OPCODE_CLOSE,
        .payload_length = payload_length,
        .payload.close.status_code = close_code,
        .payload.close.reason = close_reason,
    };
    client_send_frame(client, &close_frame);
    if (client->ssl != NULL)
    {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    close(client->fd);
}

int client_handle_frame(ws_server_t *server,
                        client_t *client,
                        frame_t *frame,
                        ws_message_t *msg)
{
    switch (frame->opcode)
    {
    case FRAME_OPCODE_CLOSE:
        msg->type = WS_MESSAGE_CLOSE;
        msg->client_id = client->fd;
        msg->data = NULL;
        msg->len = 0;
        msg->close_code = frame->payload.close.status_code;
        return 1;
    case FRAME_OPCODE_PING:
    {
        frame_t pong = *frame;
        pong.opcode = FRAME_OPCODE_PONG;
        pong.permessage_deflate = false;
        client_send_frame(client, &pong);
        return 0;
    }
    case FRAME_OPCODE_PONG:
        return 0;
    case FRAME_OPCODE_TEXT:
    case FRAME_OPCODE_BINARY:
    {
        if (client->defragmentation_state.active)
        {
            client_close(client, 1002);
            return -1;
        }
        if (!frame->final)
        {
            client->defragmentation_state.active = true;
            client->defragmentation_state.permessage_deflate =
                frame->permessage_deflate;
            client->defragmentation_state.opcode = frame->opcode;
            client->defragmentation_state.payload_length = frame->payload_length;
            client->defragmentation_state.payload = xmalloc(frame->payload_length);
            memcpy(client->defragmentation_state.payload,
                   frame->payload.binary,
                   frame->payload_length);
            return 0;
        }
        // Single-frame message: take ownership of the parser payload.
        frame_uncompress(frame);
        if (frame->opcode == FRAME_OPCODE_TEXT &&
            !is_valid_utf8(frame->payload.text, frame->payload_length))
        {
            client_close(client, 1007);
            return -1;
        }
        msg->type = (frame->opcode == FRAME_OPCODE_TEXT) ? WS_MESSAGE_TEXT
                                                         : WS_MESSAGE_BINARY;
        msg->client_id = client->fd;
        msg->len = frame->payload_length;
        msg->close_code = 0;
        server->last_msg_data = (uint8_t *)frame->payload.binary;
        msg->data = server->last_msg_data;
        frame->payload.binary = NULL;  // ownership transferred to server
        return 1;
    }
    case FRAME_OPCODE_CONTINUATION:
    {
        if (!client->defragmentation_state.active)
        {
            client_close(client, 1002);
            return -1;
        }
        size_t old_len = client->defragmentation_state.payload_length;
        size_t new_len = old_len + frame->payload_length;
        client->defragmentation_state.payload =
            xrealloc(client->defragmentation_state.payload, new_len);
        memcpy((uint8_t *)client->defragmentation_state.payload + old_len,
               frame->payload.binary,
               frame->payload_length);
        client->defragmentation_state.payload_length = new_len;
        if (!frame->final)
            return 0;
        frame_t merged = {
            .final = true,
            .permessage_deflate =
                client->defragmentation_state.permessage_deflate,
            .opcode = client->defragmentation_state.opcode,
            .payload_length = client->defragmentation_state.payload_length,
            .payload.binary = client->defragmentation_state.payload,
        };
        client->defragmentation_state.payload = NULL;
        client->defragmentation_state.payload_length = 0;
        client->defragmentation_state.active = false;
        frame_uncompress(&merged);
        if (merged.opcode == FRAME_OPCODE_TEXT &&
            !is_valid_utf8(merged.payload.text, merged.payload_length))
        {
            free(merged.payload.binary);
            client_close(client, 1007);
            return -1;
        }
        msg->type = (merged.opcode == FRAME_OPCODE_TEXT) ? WS_MESSAGE_TEXT
                                                         : WS_MESSAGE_BINARY;
        msg->client_id = client->fd;
        msg->len = merged.payload_length;
        msg->close_code = 0;
        server->last_msg_data = (uint8_t *)merged.payload.binary;
        msg->data = server->last_msg_data;
        return 1;
    }
    }
    client_close(client, 1002);
    return -1;
}

void client_send(client_t *client, void *buffer, size_t size)
{
    if (client->closed || client->fd < 0)
        return;
    while (size > 0)
    {
        size_t send_bytes;
        if (client->ssl == NULL)
        {
            // MSG_NOSIGNAL so a write to a closed peer returns EPIPE instead
            // of raising SIGPIPE and killing the process.
            int result = send(client->fd, buffer, size, MSG_NOSIGNAL);
            if (result < 0)
            {
                // Peer is gone (EBADF, EPIPE, ECONNRESET, ...). Give up on
                // this client; the poll loop will remove it.
                client->closed = true;
                return;
            }
            send_bytes = result;
        }
        else
        {
            int result = SSL_write_ex(client->ssl, buffer, size, &send_bytes);
            if (result != 1)
            {
                ERR_print_errors_fp(stderr);
                xdie("Invalid SSL_write");
            }
        }
        buffer += send_bytes;
        size -= send_bytes;
    }
}

void client_send_frame(client_t *client, frame_t *frame)
{
    frame_compress(frame);
    void *send_buffer = xmalloc(frame->payload_length + 16);
    size_t send_buffer_size;
    frame_dump(frame, send_buffer, &send_buffer_size);
    client_send(client, send_buffer, send_buffer_size);
    free(send_buffer);
}

static client_t *find_client_by_id(ws_server_t *server, int client_id)
{
    for (size_t i = 0; i < server->clients_count; i++)
        if (server->clients[i].fd == client_id && !server->clients[i].closed)
            return &server->clients[i];
    return NULL;
}

static int send_data_frame(ws_server_t *server,
                           int client_id,
                           frame_opcode_t opcode,
                           const void *data,
                           size_t len)
{
    client_t *client = find_client_by_id(server, client_id);
    if (client == NULL)
        return -1;
    bool compressible =
        (opcode == FRAME_OPCODE_TEXT || opcode == FRAME_OPCODE_BINARY);
    // frame_compress takes ownership of frame.payload.binary when the
    // deflate extension is on, so hand it a heap copy we can safely drop.
    uint8_t *payload = NULL;
    if (len > 0)
    {
        payload = xmalloc(len);
        memcpy(payload, data, len);
    }
    frame_t frame = {
        .final = true,
        .permessage_deflate =
            compressible && client->permessage_deflate.enabled,
        .opcode = opcode,
        .payload_length = len,
        .payload.binary = payload,
    };
    client_send_frame(client, &frame);
    free(frame.payload.binary);
    return 0;
}

int ws_server_send_text(ws_server_t *server,
                        int client_id,
                        const char *data,
                        size_t len)
{
    return send_data_frame(server, client_id, FRAME_OPCODE_TEXT, data, len);
}

int ws_server_send_binary(ws_server_t *server,
                          int client_id,
                          const uint8_t *data,
                          size_t len)
{
    return send_data_frame(server, client_id, FRAME_OPCODE_BINARY, data, len);
}

int ws_server_send_ping(ws_server_t *server,
                        int client_id,
                        const uint8_t *data,
                        size_t len)
{
    return send_data_frame(server, client_id, FRAME_OPCODE_PING, data, len);
}

int ws_server_close(ws_server_t *server,
                    int client_id,
                    uint16_t code,
                    const char *reason)
{
    client_t *client = find_client_by_id(server, client_id);
    if (client == NULL)
        return -1;
    size_t reason_len = reason != NULL ? strlen(reason) : 0;
    frame_t close_frame = {
        .final = true,
        .permessage_deflate = false,
        .opcode = FRAME_OPCODE_CLOSE,
        .payload_length = 2 + reason_len,
        .payload.close.status_code = code,
        .payload.close.reason = (char *)reason,
    };
    client_send_frame(client, &close_frame);
    client->closed = true;
    if (client->ssl != NULL)
    {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->fd >= 0)
    {
        close(client->fd);
        client->fd = -1;
    }
    return 0;
}
