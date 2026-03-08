#ifndef CHARLES_WEBSOCKET_FRAME_H
#define CHARLES_WEBSOCKET_FRAME_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef enum
{
    FRAME_OPCODE_CONTINUATION = 0x0,
    FRAME_OPCODE_TEXT  = 0x1,
    FRAME_OPCODE_BINARY =  0x2,
    FRAME_OPCODE_CLOSE  = 0x8,
    FRAME_OPCODE_PING  = 0x9,
    FRAME_OPCODE_PONG  = 0xA
} frame_opcode_t;

typedef struct  {
    bool final;
    frame_opcode_t opcode;
    size_t payload_length;
    union {
        char *text;
        uint8_t *binary;
        struct {
            uint16_t status_code;
            uint8_t *reason;
        } close;
    } payload;
} frame_t;

void frame_dump(frame_t* frame, uint8_t *dest, size_t *dest_size);
bool frame_parse(frame_t* dest, void *bytes, size_t size);
void frame_print(const frame_t *frame);
void frame_destroy(frame_t *frame);

#endif // CHARLES_WEBSOCKET_FRAME_H
