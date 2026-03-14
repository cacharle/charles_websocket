#ifndef CHARLES_WEBSOCKET_SERVER_H
#define CHARLES_WEBSOCKET_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/ssl.h>

#include "frame.h"

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
    SSL *ssl;
} client_t;

// typedef int (*read_func_t)(int, void *, size_t);
// typedef int (*write_func_t)(int, void *, size_t);

typedef struct
{
    int fd;
    size_t clients_count;
    client_t clients[SERVER_MAX_CLIENTS];
    SSL_CTX *ssl_context;
    // read_func_t read_func;
    // write_func_t write_func;
} server_t;

void server_init(server_t *server,
                 uint16_t port,
                 bool ssl_enabled,
                 char *cert_path,
                 char *key_path);
void server_start(server_t *server);
bool client_ingest(client_t *client, uint8_t *buffer, size_t size);
void client_close(client_t *client, int close_code);
bool client_handle_frame(client_t *client, frame_t *frame);
void client_send(client_t *client, void *buffer, size_t size);
void client_send_frame(client_t *client, frame_t *frame);

#endif  // CHARLES_WEBSOCKET_SERVER_H
