#ifndef CACHARLE_WS_SERVER_H
#define CACHARLE_WS_SERVER_H

typedef struct
{
} ws_server_t;

ws_server_t *ws_server_new();
void ws_server_destroy(ws_server_t *server);

#endif  // CACHARLE_WS_SERVER_H
