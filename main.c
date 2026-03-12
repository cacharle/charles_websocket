#include "server.h"

int main()
{
    server_t server;
    server_init(&server, 8080);
    server_start(&server);
    return 0;
}
