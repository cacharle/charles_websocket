#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "frame.h"

// LLM generated
void websocket_accept(const char *client_key, char *out)
{
    const char *guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    char combined[256];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    snprintf(combined, sizeof(combined), "%s%s", client_key, guid);
    SHA1((unsigned char*)combined, strlen(combined), sha1);
    int len = EVP_EncodeBlock((unsigned char*)out, sha1, SHA_DIGEST_LENGTH);
    out[len] = '\0';
}

static bool running = true;
void stop_signal(int) { running = false;
    signal(SIGINT, SIG_DFL);
}

void print_bytes(unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%x ", bytes[i]);
        if ((i+1) % 16 == 0)
            fputc('\n', stdout);
    }
    fputc('\n', stdout);
}

int main()
{
    signal(SIGINT, stop_signal);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd > 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr = { .s_addr = INADDR_ANY },
    };
    int ret = bind(sockfd, (struct sockaddr*)&addr, sizeof addr);
    assert(ret == 0);
    ret = listen(sockfd, 5);
    assert(ret == 0);

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof client_addr;
        int client_fd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);

        char buffer[4096 + 1];
        int nbytes = recv(client_fd, buffer, 4096, 0);
        assert(nbytes != -1);
        buffer[nbytes] = '\0';
        printf("Received initial: %s\n", buffer);

        char *result = strstr(buffer, "Sec-WebSocket-Key:");
        assert(result != NULL);
        result += strlen("Sec-WebSocket-Key:");
        while (isspace(*result))
            result++;
        char *newline = strchr(result, '\r');
        *newline = '\0';
        printf("\n\nHere result: '%s'\n", result);
        char accept_key[512];
        websocket_accept(result, accept_key);

        char format[] =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n";
        char response[1024];
        sprintf(response, format, accept_key);
        printf("Sending: %s\n", response);

        ret = send(client_fd, response, strlen(response), 0);
        printf("sent initial response back\n");
        assert(ret != -1);

        while (running) {
            unsigned char buffer[4096 + 1];
            int nbytes = recv(client_fd, buffer, 4096, 0);
            if (nbytes == 0) {
                printf("Peer closed connection");
                return 0;
            }
            assert(nbytes != -1);
            buffer[nbytes] = '\0';
            printf("Received %d bytes:\n", nbytes);
            print_bytes(buffer, nbytes);
            frame_t f;
            frame_parse(&f, buffer, sizeof buffer);
            frame_print(&f);
        }
        close(client_fd);
    }

    close(sockfd);
    return 0;
}
