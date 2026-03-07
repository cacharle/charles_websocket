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

#include "handshake.h"
#include "frame.h"

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

        char request[4096 + 1];
        int nbytes = recv(client_fd, request, 4096, 0);
        assert(nbytes != -1);
        request[nbytes] = '\0';
        char response[1024];
        parse_request_and_generate_response(request, response);

        ret = send(client_fd, response, strlen(response), 0);
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
