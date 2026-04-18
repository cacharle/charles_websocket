#include <cacharle/ws/server.h>

int main(void)
{
    ws_server_t *srv = ws_server_new(
        &(ws_server_config_t){.port = 8080, .permessage_deflate = true});

    ws_message_t msg;
    int result;
    while ((result = ws_server_recv(srv, &msg, 1000) != -1))
    {
        if (result == 1)
            continue;
        switch (msg.type)
        {
        case WS_MESSAGE_TEXT:
            ws_server_send_text(srv, msg.client_id, (char *)msg.data, msg.len);
            break;
        case WS_MESSAGE_BINARY:
            ws_server_send_binary(srv, msg.client_id, msg.data, msg.len);
            break;
        case WS_MESSAGE_CLOSE:
            ws_server_close(srv, msg.client_id, 1000, NULL);
            break;
        default:
            break;
        }
    }

    ws_server_destroy(srv);
}
