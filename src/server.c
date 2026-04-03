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

#include "handshake.h"
#include "server.h"
#include "utils.h"
#include "xlibc.h"

void server_init(server_t *server,
                 uint16_t port,
                 bool ssl_enabled,
                 char *cert_path,
                 char *key_path)
{
    server->clients = xcalloc(SERVER_MAX_CLIENTS, sizeof(client_t));
    if (ssl_enabled)
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
            server->ssl_context, cert_path, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(server->ssl_context, key_path, SSL_FILETYPE_PEM);
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
        .sin_port = htons(port),
        .sin_addr = {.s_addr = INADDR_ANY},
    };
    // Allow the port to be reused after program end
    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int ret = bind(server->fd, (struct sockaddr *)&addr, sizeof addr);
    if (ret < 0)
        xdie("Couldn't bind socket");
    listen(server->fd, 8);
    if (ret < 0)
        xdie("Couldn't listen on socket");
}

static bool sigint_triggered = false;
void sigint_handler(int)
{
    sigint_triggered = true;
}

void server_start(server_t *server)
{
    signal(SIGINT, sigint_handler);
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
        int ret = poll(pollfds, server->clients_count + 1, 10);
        if (ret == 0)  // Timeout
            continue;
        if (sigint_triggered)
        {
            printf("Interrupted by Ctrl-C\n");
            break;
        }
        if (ret < 0)
            xdie("ppoll");

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
            continue;
        }

        // Check if there is any data to receive from active clients
        bool to_remove[SERVER_MAX_CLIENTS];
        memset(to_remove, false, SERVER_MAX_CLIENTS);
        for (size_t i = 0; i < server->clients_count; i++)
        {
            if (pollfds[i + 1].revents & POLLIN)
            {
                uint8_t recv_buffer[RECV_BUFFER_SIZE];
                size_t recv_size;
                client_t *client = &server->clients[i];
                if (client->ssl == NULL)
                {
                    int result = recv(client->fd, recv_buffer, RECV_BUFFER_SIZE, 0);
                    if (result < 0)
                        xdie("Invalid recv");
                    recv_size = result;
                }
                else
                {
                    int result = SSL_read_ex(
                        client->ssl, recv_buffer, RECV_BUFFER_SIZE, &recv_size);
                    if (result != 1)
                    {
                        ERR_print_errors_fp(stderr);
                        xdie("Invalid SSL_read");
                    }
                }
                to_remove[i] = client_ingest(client, recv_buffer, recv_size);
            }
        }

        // Remove clients who are closed
        for (size_t i = 0; i < server->clients_count; i++)
        {
            if (to_remove[i])
            {
                client_close(&server->clients[i], 1000);
                if (server->clients_count > 1)
                    memmove(server->clients + i,
                            server->clients + i + 1,
                            server->clients_count - i - 1);
                server->clients_count--;
                i--;
            }
        }
    }

    printf("Clean exit\n");
    for (size_t i = 0; i <= server->clients_count; i++)
        client_close(&server->clients[i], 1000);
    close(server->fd);
    if (server->ssl_context != NULL)
    {
        SSL_CTX_free(server->ssl_context);
        EVP_cleanup();
    }
}

bool client_ingest(client_t *client, uint8_t *buffer, size_t size)
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
            return true;
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
        return false;
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
            return true;
        }
        else if (ingest_result == FRAME_PARSER_INGEST_RESULT_PENDING)
        {
            return false;
        }
        else if (ingest_result == FRAME_PARSER_INGEST_RESULT_DONE)
        {
            // frame_print(&client->parser.frame);
            bool to_remove = client_handle_frame(client, &client->parser.frame);
            frame_destroy(&client->parser.frame);
            frame_parser_init(&client->parser, client->permessage_deflate.enabled);
            if (to_remove)
            {
                free(client->defragmentation_state.payload);
                return to_remove;
            }
        }
    }
    return false;
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

bool client_handle_frame(client_t *client, frame_t *frame)
{
    switch (frame->opcode)
    {
    case FRAME_OPCODE_CLOSE:
        client_close(client, 1000);
        return true;
    case FRAME_OPCODE_PING:
    {
        frame_t ping_frame = *frame;
        ping_frame.opcode = FRAME_OPCODE_PONG;
        client_send_frame(client, &ping_frame);
        return false;
    }
    case FRAME_OPCODE_PONG:
        return false;
    case FRAME_OPCODE_TEXT:
    case FRAME_OPCODE_BINARY:
    {
        if (client->defragmentation_state.active)
            return true;
        if (frame->final)
        {
            frame_uncompress(frame);
            if (frame->opcode == FRAME_OPCODE_TEXT &&
                !is_valid_utf8(frame->payload.text, frame->payload_length))
                return true;
            client_send_frame(client, frame);
        }
        else
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
        }
        return false;
    }
    case FRAME_OPCODE_CONTINUATION:
        if (!client->defragmentation_state.active)
            return true;
        client->defragmentation_state.payload = xrealloc(
            client->defragmentation_state.payload,
            client->defragmentation_state.payload_length + frame->payload_length);
        memcpy(client->defragmentation_state.payload +
                   client->defragmentation_state.payload_length,
               frame->payload.binary,
               frame->payload_length);
        client->defragmentation_state.payload_length += frame->payload_length;
        if (frame->final)
        {
            frame_t sent_frame = {
                .final = true,
                .permessage_deflate =
                    client->defragmentation_state.permessage_deflate,
                .opcode = client->defragmentation_state.opcode,
                .payload_length = client->defragmentation_state.payload_length,
                .payload.binary = client->defragmentation_state.payload,
            };
            frame_uncompress(&sent_frame);
            if (client->defragmentation_state.opcode == FRAME_OPCODE_TEXT &&
                !is_valid_utf8(sent_frame.payload.text,
                               sent_frame.payload_length))
            {
                free(sent_frame.payload.binary);
                return true;
            }
            client_send_frame(client, &sent_frame);
            free(sent_frame.payload.binary);
            client->defragmentation_state.active = false;
            client->defragmentation_state.payload = NULL;
            client->defragmentation_state.payload_length = 0;
        }
        return false;
    }
    abort();
}

void client_send(client_t *client, void *buffer, size_t size)
{
    size_t send_bytes;
    if (client->ssl == NULL)
    {
        int result = send(client->fd, buffer, size, 0);
        if (result < 0)
            xdie("Counldn't send handshake");
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
}

void client_send_frame(client_t *client, frame_t *frame)
{
    frame_compress(frame);
    void *send_buffer = xmalloc(frame->payload_length + 16);
    size_t send_buffer_size;
    frame_dump(frame, send_buffer, &send_buffer_size);
    client_send(client, send_buffer, send_buffer_size);
}
