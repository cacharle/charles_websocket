#include "server.h"

int main()
{
    server_t server;
    server_init(&server, 8080, false, "cert.pem", "key.pem");
    server_start(&server);
    return 0;
}
