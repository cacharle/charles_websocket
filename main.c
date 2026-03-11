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

#include "handshake.h"
#include "frame.h"
#include "utils.h"

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

static frame_opcode_t current_fragmented_opcode = -1;
static size_t current_fragmented_payload_length = 0;
static void *current_fragmented_payload = NULL;


bool handle_injest_result(frame_parser_injest_result_t injest_result, int client_fd, frame_t *frame)
{
    if (injest_result == FRAME_PARSER_INJEST_RESULT_PENDING)
        return true;
    if (injest_result == FRAME_PARSER_INJEST_RESULT_ERROR) {
        printf("ERROR injest_result\n");
        return false;
    }
    frame_print(frame);
    switch (frame->opcode)
    {
    case FRAME_OPCODE_CLOSE:
        // printf("Received close frame, sending close\n");
        return false;
    case FRAME_OPCODE_PING:
        printf("Received ping frame, sending pong\n");
        frame->opcode = FRAME_OPCODE_PONG;
        uint8_t send_buffer[512];
        size_t  send_buffer_size;
        frame_dump(frame, send_buffer, &send_buffer_size);
        send(client_fd, send_buffer, send_buffer_size, 0);
        return true;
    case FRAME_OPCODE_TEXT:
    case FRAME_OPCODE_BINARY: {
        if (current_fragmented_payload != NULL)
            return false;
        if (frame->final) {
            printf("Received text|binary frame, sending same frame back\n");
            if (frame->opcode == FRAME_OPCODE_TEXT &&
               !is_valid_utf8((unsigned char*)frame->payload.text, frame->payload_length))
                return false;
            uint8_t *send_buffer = malloc(frame->payload_length + 16);
            size_t   send_buffer_size;
            frame_dump(frame, send_buffer, &send_buffer_size);
            send(client_fd, send_buffer, send_buffer_size, 0);
            free(send_buffer);
        } else {
            printf("Non final frame encountered for text|binary");
            current_fragmented_opcode = frame->opcode;
            current_fragmented_payload_length = frame->payload_length;
            current_fragmented_payload =  malloc(frame->payload_length);
            memcpy(current_fragmented_payload, frame->payload.binary, frame->payload_length);
            return true;
        }
        return true;
    case FRAME_OPCODE_PONG:
        printf("FRAME_OPCODE_PONG ignored\n");
        return true;
    case FRAME_OPCODE_CONTINUATION:
        if (current_fragmented_payload == NULL)
            return false;
        printf("FRAME_OPCODE_CONTINUATION handled\n");
        current_fragmented_payload = realloc(
            current_fragmented_payload,
            current_fragmented_payload_length + frame->payload_length);
        memcpy(current_fragmented_payload + current_fragmented_payload_length,
                frame->payload.binary, frame->payload_length);
        current_fragmented_payload_length += frame->payload_length;
        if (frame->final) {
            printf("FRAME_OPCODE_CONTINUATION final\n");

            if (current_fragmented_opcode == FRAME_OPCODE_TEXT &&
                !is_valid_utf8((unsigned char*)current_fragmented_payload, current_fragmented_payload_length))
                return false;
            uint8_t *send_buffer = malloc(current_fragmented_payload_length + 16);
            size_t   send_buffer_size;
            frame_t defragmented_frame = {
                .final = true,
                .opcode = current_fragmented_opcode,
                .payload_length = current_fragmented_payload_length,
                .payload.binary = current_fragmented_payload,
            };
            frame_dump(&defragmented_frame, send_buffer, &send_buffer_size);
            send(client_fd, send_buffer, send_buffer_size, 0);
            free(send_buffer);
            frame_destroy(&defragmented_frame);
            current_fragmented_opcode = -1;
            current_fragmented_payload = NULL;
            current_fragmented_payload_length = 0;
        }
        return true;
    }
    }
    abort();
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

        current_fragmented_opcode = -1;
        current_fragmented_payload_length = 0;
        current_fragmented_payload = NULL;

        size_t remining_data_size = 0;
        uint8_t remining_data[4096];
        while (running)
        {
            frame_parser_t parser;
            frame_parser_init(&parser);
            frame_parser_injest_result_t injest_result = FRAME_PARSER_INJEST_RESULT_PENDING;

            printf("--------REMINDING DATA LOOP START\n");

            bool keep_going = true;
            while (keep_going && remining_data_size != 0) {
                // Injest data that was possibly left from multiple frames in one TCP recv
                size_t initial_remining_data_size = remining_data_size;
                injest_result = frame_parser_injest(&parser, remining_data, remining_data_size, &remining_data_size);
                printf("injest_result %d, initial_remining_data_size %zu, remining_data_size %zu\n", injest_result, initial_remining_data_size, remining_data_size);
                keep_going = handle_injest_result(injest_result, client_fd, &parser.frame);
                printf("here2 keep_going %d\n", keep_going);
                if (injest_result == FRAME_PARSER_INJEST_RESULT_DONE)
                    frame_parser_init(&parser);
                // Advance the remining_data buffer
                memmove(
                    remining_data,
                    remining_data + initial_remining_data_size - remining_data_size,
                    remining_data_size);
            }
            if (!keep_going)
                break;

            printf("--------REMINDING DATA LOOP END\n");

            uint8_t data[4096];
            int      data_size;
            bool     recv_error = false;
            injest_result = FRAME_PARSER_INJEST_RESULT_PENDING;
            while (injest_result == FRAME_PARSER_INJEST_RESULT_PENDING)
            {
                data_size = recv(client_fd, data, sizeof(data), 0);
                printf("RECV: %d\n", data_size);
                if (data_size == -1)
                {
                    recv_error = true;
                    break;
                }
                if (data_size == 0)
                {
                    printf("Peer closed connection");
                    recv_error = true;
                    break;
                }
                injest_result = frame_parser_injest(&parser, data, data_size, &remining_data_size);
                if (remining_data_size > 0) {
                    memcpy(remining_data, data + data_size - remining_data_size, remining_data_size);
                }
            }

            if (recv_error)
            {
                printf("ERROR recv: %s\n", strerror(errno));
                break;
            }
            // frame_print(&f);
            keep_going = handle_injest_result(injest_result, client_fd, &parser.frame);
            printf("here keep_going %d\n", keep_going);
            if (!keep_going)
                break;
            frame_destroy(&parser.frame);
        }

        // Always send close message before closing TCP socket
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

        close(client_fd);

        printf("---------------------------------------------\n");
    }

    close(sockfd);
    return 0;
}
