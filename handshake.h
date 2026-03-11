#ifndef CHARLES_WEBSOCKET_HANDSHAKE_H
#define CHARLES_WEBSOCKET_HANDSHAKE_H

void
websocket_accept(const char *client_key, char *out);
void
parse_request_and_generate_response(char *request, char *response);

#endif  // CHARLES_WEBSOCKET_HANDSHAKE_H
