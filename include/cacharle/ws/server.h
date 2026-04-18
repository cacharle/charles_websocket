#ifndef CACHARLE_WS_SERVER_DRAFT_H
#define CACHARLE_WS_SERVER_DRAFT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/ssl.h>

#include <cacharle/ws/frame.h>
#include <cacharle/ws/handshake.h>

#define SERVER_MAX_CLIENTS 1024
#define RECV_BUFFER_SIZE 8192

typedef struct
{
    bool active;
    bool permessage_deflate;
    frame_opcode_t opcode;
    size_t payload_length;
    void *payload;
} defragmentation_state_t;

typedef struct
{
    bool closed;
    int fd;
    bool handshake_completed;
    permessage_deflate_t permessage_deflate;
    defragmentation_state_t defragmentation_state;
    frame_parser_t parser;
    SSL *ssl;
    uint8_t *recv_overflow;
    size_t recv_overflow_len;
} client_t;

typedef struct
{
    int fd;
    size_t clients_count;
    client_t *clients;
    SSL_CTX *ssl_context;
    uint8_t *last_msg_data;
} ws_server_t;

typedef enum {
    WS_MESSAGE_TEXT,
    WS_MESSAGE_BINARY,
    WS_MESSAGE_PING,
    WS_MESSAGE_PONG,
    WS_MESSAGE_OPEN,
    WS_MESSAGE_CLOSE,
} ws_message_type_t;

typedef struct {
    ws_message_type_t  type;
    int                client_id;   // identifies the client
    uint8_t           *data;        // library-owned, valid until next ws_server_recv
    size_t             len;
    uint16_t           close_code;  // only meaningful for WS_MESSAGE_CLOSE
} ws_message_t;

typedef struct {
    uint16_t    port;
    const char *cert_path;
    const char *key_path;
    bool        permessage_deflate;
    bool        permessage_deflate_context_takeover;
    bool        permessage_deflate_max_window_bits;
} ws_server_config_t;

ws_server_t *ws_server_new(const ws_server_config_t *config);
void         ws_server_destroy(ws_server_t *server);

// Blocks until a complete message is available from any client.
// Handles accept, handshake, defragmentation, and decompression internally.
// Returns 0 on success, 1 on timeout -1 on error.
int ws_server_recv(ws_server_t *server, ws_message_t *msg, int timeout);

int ws_server_send_text(ws_server_t *server, int client_id, const char *data, size_t len);
int ws_server_send_binary(ws_server_t *server, int client_id, const uint8_t *data, size_t len);
int ws_server_send_ping(ws_server_t *server, int client_id, const uint8_t *data, size_t len);
int ws_server_close(ws_server_t *server, int client_id, uint16_t code, const char *reason);

#endif  // CACHARLE_WS_SERVER_DRAFT_H
