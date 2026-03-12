#ifndef CHARLES_WEBSOCKET_SERVER_H
#define CHARLES_WEBSOCKET_SERVER_H

#include "frame.h"
#include <stddef.h>
#include <stdint.h>

#define SERVER_MAX_CLIENTS 1024
#define RECV_BUFFER_SIZE 4096

typedef struct
{
    bool active;
    frame_opcode_t opcode;
    size_t payload_length;
    void *payload;
} defragmentation_state_t;

typedef struct
{
    bool closed;
    int fd;
    bool handshake_completed;
    defragmentation_state_t defragmentation_state;
    frame_parser_t parser;
} client_t;

typedef struct
{
    int fd;
    size_t clients_count;
    client_t clients[SERVER_MAX_CLIENTS];
} server_t;

void
server_init(server_t *server, uint16_t port);
void
server_start(server_t *server);
bool
client_injest(client_t *client, uint8_t *buffer, size_t size);
void
client_close(client_t *client, int close_code);
bool client_handle_frame(client_t *client, frame_t *frame);

#endif  // CHARLES_WEBSOCKET_SERVER_H
