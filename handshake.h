#ifndef CHARLES_WEBSOCKET_HANDSHAKE_H
#define CHARLES_WEBSOCKET_HANDSHAKE_H

#include <stddef.h>

typedef struct
{
    bool enabled;
    int client_max_window_bits;
    int server_max_window_bits;
    bool client_no_context_takeover;
    bool server_no_context_takeover;
} permessage_deflate_t;

typedef struct
{
    char *host;
    char *path;
    char *websocket_key;
    char *websocket_accept;
    permessage_deflate_t permessage_deflate;
} handshake_t;

void handshake_init(handshake_t *handshake);
void handshake_destroy(handshake_t *handshake);
bool handshake_parse_request(handshake_t *handshake,
                             char *request,
                             size_t request_size);
void handshake_write_response(handshake_t *handshake,
                              char *response,
                              size_t response_size);

#endif  // CHARLES_WEBSOCKET_HANDSHAKE_H
