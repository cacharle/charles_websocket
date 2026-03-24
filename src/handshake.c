#include <assert.h>
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <string.h>

#include "handshake.h"
#include "xlibc.h"

void handshake_init(handshake_t *handshake)
{
    handshake->host = NULL;
    handshake->path = NULL;
    handshake->websocket_key = NULL;
    handshake->websocket_accept = NULL;
    handshake->permessage_deflate.enabled = false;
    handshake->permessage_deflate.client_no_context_takeover = false;
    handshake->permessage_deflate.server_no_context_takeover = false;
    handshake->permessage_deflate.client_max_window_bits = 15;
    handshake->permessage_deflate.server_max_window_bits = 15;
}

void handshake_destroy(handshake_t *handshake)
{
    free(handshake->host);
    free(handshake->path);
    free(handshake->websocket_key);
    free(handshake->websocket_accept);
}

bool handshake_parse_request(handshake_t *handshake,
                             char *request,
                             size_t request_size)
{
    (void)request_size;
    char *end_of_line = strstr(request, "\r\n");
    if (end_of_line == NULL)
        return false;
    *end_of_line++ = '\0';
    *end_of_line++ = '\0';

    char *first_line_split_ptr = strchr(request, ' ');
    if (first_line_split_ptr == NULL)
        return false;
    *first_line_split_ptr++ = '\0';
    if (strcmp(request, "GET") != 0)
        return false;

    char *tmp = first_line_split_ptr;
    first_line_split_ptr = strchr(first_line_split_ptr, ' ');
    if (first_line_split_ptr == NULL)
        return false;
    *first_line_split_ptr++ = '\0';
    if (tmp[0] != '/')
        return false;
    handshake->path = xstrdup(tmp);

    // null byte added at the start
    if (strcmp(first_line_split_ptr, "HTTP/1.1") != 0)
        return false;

    char *header_upgrade = NULL;
    char *header_connection = NULL;
    char *header_websocket_version = NULL;
    for (char *current_line = end_of_line;
         (end_of_line = strstr(current_line, "\r\n")) != NULL;
         current_line = end_of_line)
    {
        char *value = strstr(current_line, ": ");
        if (value == NULL)
            break;
        *value++ = '\0';
        *value++ = '\0';
        while (isspace(*value))
            value++;
        *end_of_line++ = '\0';
        *end_of_line++ = '\0';
        for (int end = strlen(value) - 1; end >= 0 && isspace(value[end]); end--)
            value[end] = '\0';

        if (strcasecmp(current_line, "Upgrade") == 0)
            header_upgrade = value;
        if (strcasecmp(current_line, "Connection") == 0)
            header_connection = value;
        if (strcasecmp(current_line, "Sec-WebSocket-Version") == 0)
            header_websocket_version = value;
        if (strcasecmp(current_line, "Host") == 0)
            handshake->host = xstrdup(value);
        if (strcasecmp(current_line, "Sec-WebSocket-Key") == 0)
            handshake->websocket_key = xstrdup(value);
        if (strcasecmp(current_line, "Sec-WebSocket-Extensions") == 0)
        {
            char *token;
            while ((token = strsep(&value, "; ")) != NULL)
            {
                if (*token == '\0')
                    continue;
                if (strcasecmp(token, "permessage-deflate") == 0)
                {
                    handshake->permessage_deflate.enabled = true;
                }
                else if (strcasecmp(token, "client_no_context_takeover") == 0)
                {
                    handshake->permessage_deflate.client_no_context_takeover = true;
                }
                else if (strcasecmp(token, "server_no_context_takeover") == 0)
                {
                    handshake->permessage_deflate.server_no_context_takeover = true;
                }
                else
                {
                    char *equal_sign = strchr(token, '=');
                    if (equal_sign != NULL)
                    {
                        *equal_sign++ = '\0';
                        if (strcasecmp(token, "client_max_window_bits") == 0)
                            handshake->permessage_deflate.client_max_window_bits =
                                atoi(equal_sign);
                        else if (strcasecmp(token, "server_max_window_bits") == 0)
                            handshake->permessage_deflate.server_max_window_bits =
                                atoi(equal_sign);
                    }
                }
            }
        }
    }
    if (handshake->host == NULL || handshake->websocket_key == NULL ||
        strcasecmp(header_upgrade, "WebSocket") != 0 ||
        strcasecmp(header_connection, "Upgrade") != 0 ||
        strcasecmp(header_websocket_version, "13") != 0)
        return false;
    return true;
}

void handshake_write_response(handshake_t *handshake,
                              char *response,
                              size_t response_size)
{
    const char *magic_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[256];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    snprintf(
        combined, sizeof(combined), "%s%s", handshake->websocket_key, magic_guid);
    SHA1((unsigned char *)combined, strlen(combined), sha1);
    char accept_key[512];
    int len = EVP_EncodeBlock((unsigned char *)accept_key, sha1, SHA_DIGEST_LENGTH);
    accept_key[len] = '\0';

    char *response_start = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept:";
    char *next = stpcpy(response, response_start);
    next = stpcpy(next, accept_key);
    next = stpcpy(next, "\r\n");
    if (handshake->permessage_deflate.enabled)
    {
        next = stpcpy(next,
                      "Sec-WebSocket-Extensions: permessage-deflate; "
                      "server_max_window_bits=");
        next += sprintf(
            next, "%d", handshake->permessage_deflate.server_max_window_bits);
        next += sprintf(next,
                        "; client_max_window_bits=%d",
                        handshake->permessage_deflate.client_max_window_bits);
        if (handshake->permessage_deflate.server_no_context_takeover)
            next = stpcpy(next, ";  server_no_context_takeover");
        if (handshake->permessage_deflate.client_no_context_takeover)
            next = stpcpy(next, ";  client_no_context_takeover");
        next = stpcpy(next, "\r\n");
    }
    strncat(response, "\r\n", response_size);
    printf("Sending: %s\n", response);
}
