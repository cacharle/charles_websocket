#include <assert.h>
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

// LLM generated
void
websocket_accept(const char *client_key, char *out)
{
    const char   *magic_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char          combined[256];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    snprintf(combined, sizeof(combined), "%s%s", client_key, magic_guid);
    SHA1((unsigned char *)combined, strlen(combined), sha1);
    int len = EVP_EncodeBlock((unsigned char *)out, sha1, SHA_DIGEST_LENGTH);
    out[len] = '\0';
}

void
parse_request_and_generate_response(char *request, char *response)
{
    char *result = strstr(request, "Sec-WebSocket-Key:");
    assert(result != NULL);
    result += strlen("Sec-WebSocket-Key:");
    while (isspace(*result))
        result++;
    char *newline = strchr(result, '\r');
    *newline = '\0';
    char accept_key[512];
    websocket_accept(result, accept_key);
    char format[] = "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: %s\r\n\r\n";
    sprintf(response, format, accept_key);
}
