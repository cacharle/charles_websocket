#define _GNU_SOURCE

#include "server.h"
#include "handshake.h"
#include "utils.h"
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void
server_init(server_t *server, uint16_t port)
{
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    server->clients_count = 0;
    if (server->fd < 0)
        die("Couldn't create socket");
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {.s_addr = INADDR_ANY},
    };
    int ret = bind(server->fd, (struct sockaddr *)&addr, sizeof addr);
    if (ret < 0)
        die("Couldn't bind socket");
    listen(server->fd, 8);
    if (ret < 0)
        die("Couldn't listen on socket");
}

void
server_start(server_t *server)
{
    sigset_t sigint_mask;
    sigemptyset(&sigint_mask);
    sigaddset(&sigint_mask, SIGINT);

    while (true)
    {
        struct pollfd pollfds[SERVER_MAX_CLIENTS + 1];
        // Poll the server fd for accept and the clients for recv
        pollfds[0].fd = server->fd;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
        for (size_t i = 0; i <= server->clients_count; i++)
        {
            pollfds[i + 1].fd = server->clients[i].fd;
            pollfds[i + 1].events = POLLIN;
            pollfds[i + 1].revents = 0;
        }
        int ret = ppoll(pollfds, server->clients_count + 1, NULL, &sigint_mask);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                printf("Interrupted by Ctrl-C\n");
                break;
            }
            else
            {
                die("ppoll");
            }
        }

        // Accept a new client and add it to the client list
        if (pollfds[0].revents & POLLIN)
        {
            if (server->clients_count == SERVER_MAX_CLIENTS)
                die("Too many clients");
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof client_addr;
            server->clients[server->clients_count].fd = accept(
                server->fd, (struct sockaddr *)&client_addr, &client_addr_len);
            server->clients[server->clients_count].handshake_completed = false;
            server->clients[server->clients_count].defragmentation_state.active =
                false;
            server->clients[server->clients_count].defragmentation_state.payload =
                NULL;
            server->clients[server->clients_count]
                .defragmentation_state.payload_length = 0;
            frame_parser_init(&server->clients[server->clients_count].parser);
            server->clients_count++;
        }

        // Check if there is any data to receive from active clients
        bool to_remove[SERVER_MAX_CLIENTS];
        memset(to_remove, false, SERVER_MAX_CLIENTS);
        for (size_t i = 0; i <= server->clients_count; i++)
        {
            if (pollfds[i + 1].revents & POLLIN)
            {
                uint8_t recv_buffer[RECV_BUFFER_SIZE];
                int recv_size =
                    recv(server->clients[i].fd, recv_buffer, RECV_BUFFER_SIZE, 0);
                if (recv_size < 0)
                    die("Invalid recv");
                to_remove[i] =
                    client_injest(&server->clients[i], recv_buffer, recv_size);
            }
        }

        // Remove clients who are closed
        for (size_t i = 0; i <= server->clients_count; i++)
        {
            if (!to_remove[i])
            {
                if (server->clients_count > 1)
                    memmove(server->clients + i,
                            server->clients + i + 1,
                            server->clients_count - i - 1);
                server->clients_count--;
                i--;
            }
        }
    }

    for (size_t i = 0; i <= server->clients_count; i++)
        close(server->clients[i].fd);
    close(server->fd);
}

bool
client_injest(client_t *client, uint8_t *buffer, size_t size)
{
    if (!client->handshake_completed)
    {
        // FIXME: this handshake code is horrendous
        buffer[size] = '\0';
        char response[1024];
        parse_request_and_generate_response((char *)buffer, response);
        int ret = send(client->fd, response, strlen(response), 0);
        if (ret < 0)
            die("Counldn't send handshake");
        client->handshake_completed = true;
        return false;
    }

    size_t remining_size = size;
    while (remining_size != 0)
    {
        frame_parser_injest_result_t injest_result =
            frame_parser_injest(&client->parser, buffer, size, &remining_size);
        buffer += size - remining_size;
        size = remining_size;
        if (injest_result == FRAME_PARSER_INJEST_RESULT_ERROR)
        {
            client_close(client, 1000);
            return true;
        }
    }

    return false;
}

void
client_close(client_t *client, int close_code)
{
    frame_t close_frame = {
        .final = true,
        .opcode = FRAME_OPCODE_CLOSE,
        .payload_length = 2,
        .payload.close.status_code = close_code,
        .payload.close.reason = NULL,
    };
    frame_send(&close_frame, client->fd);
    close(client->fd);
}
