#include "frame.h"
#include "handshake.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool running = true;
void
stop_signal(int)
{
    running = false;
    signal(SIGINT, SIG_DFL);
}

void
print_bytes(unsigned char *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%x ", bytes[i]);
        if ((i + 1) % 16 == 0)
            fputc('\n', stdout);
    }
    fputc('\n', stdout);
}

int
main()
{
    signal(SIGINT, stop_signal);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd > 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr = {.s_addr = INADDR_ANY},
    };
    int ret = bind(sockfd, (struct sockaddr *)&addr, sizeof addr);
    assert(ret == 0);
    ret = listen(sockfd, 5);
    assert(ret == 0);

    while (running)
    {
        struct sockaddr_in client_addr;
        socklen_t          client_addr_len = sizeof client_addr;
        int                client_fd =
            accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);

        char request[4096 + 1];
        int  nbytes = recv(client_fd, request, 4096, 0);
        assert(nbytes != -1);
        request[nbytes] = '\0';
        char response[1024];
        parse_request_and_generate_response(request, response);

        ret = send(client_fd, response, strlen(response), 0);
        assert(ret != -1);

        while (running)
        {
            uint8_t *buffer = NULL;
            size_t   recv_size = 4096;
            int      nbytes;
            size_t   current_buffer_size = 0;
            bool     recv_error = false;
            do
            {
                buffer = realloc(buffer, current_buffer_size + recv_size + 1);
                nbytes = recv(client_fd, buffer + current_buffer_size, recv_size, 0);
                if (nbytes == -1)
                {
                    recv_error = true;
                    break;
                }
                if (nbytes == 0)
                {
                    printf("Peer closed connection");
                    return 0;
                }
                current_buffer_size += nbytes;
            } while (nbytes == recv_size);
            if (recv_error)
            {
                free(buffer);
                printf("ERROR recv: %s\n", strerror(errno));
                break;
            }
            buffer[current_buffer_size] = '\0';
            // printf("Received %d bytes:\n", nbytes);
            // print_bytes(buffer, nbytes);
            frame_t f;
            bool    ok = frame_parse(&f, buffer, current_buffer_size);
            free(buffer);
            if (!ok)
            {
                printf("ERROR: something bad during parsing\n");
                break;
            }
            frame_print(&f);
            frame_destroy(&f);

            if (f.opcode == FRAME_OPCODE_CLOSE)
            {
                printf("Received close frame, sending close\n");
                frame_t closing_frame = {
                    .final = true,
                    .opcode = FRAME_OPCODE_CLOSE,
                    .payload_length = 2,
                    .payload.close.status_code = 1000,
                };
                uint8_t send_buffer[512];
                size_t  send_buffer_size;
                frame_dump(&closing_frame, send_buffer, &send_buffer_size);
                send(client_fd, send_buffer, send_buffer_size, 0);
                break;
            }
            else if (f.opcode == FRAME_OPCODE_PING)
            {
                printf("Received ping frame, sending pong\n");
                f.opcode = FRAME_OPCODE_PONG;
                uint8_t send_buffer[512];
                size_t  send_buffer_size;
                frame_dump(&f, send_buffer, &send_buffer_size);
                send(client_fd, send_buffer, send_buffer_size, 0);
            }
            else if (f.opcode == FRAME_OPCODE_TEXT ||
                     f.opcode == FRAME_OPCODE_BINARY)
            {
                printf("Received text|binary frame, sending same frame back\n");
                uint8_t *send_buffer = malloc(f.payload_length + 128);
                size_t   send_buffer_size;
                frame_dump(&f, send_buffer, &send_buffer_size);
                send(client_fd, send_buffer, send_buffer_size, 0);
            }
        }
        close(client_fd);
    }

    close(sockfd);
    return 0;
}
