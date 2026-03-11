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

typedef struct {
    frame_t frame;
    uint32_t masking_key;
    bool header_parsed;
    size_t injested_payload_length;
    uint8_t header_buffer[16];
    size_t header_buffer_position;
} frame_parser_t;

typedef enum {
    FRAME_PARSER_INJEST_RESULT_DONE,
    FRAME_PARSER_INJEST_RESULT_PENDING,
    FRAME_PARSER_INJEST_RESULT_ERROR,
} frame_parser_injest_result_t;

void
frame_parser_init(frame_parser_t *parser);
frame_parser_injest_result_t
frame_parser_injest(frame_parser_t *parser, uint8_t *data, size_t size, size_t *remining_data_size);

void frame_dump(frame_t* frame, uint8_t *dest, size_t *dest_size);
void frame_send(frame_t *frame, int fd);
void frame_print(const frame_t *frame);
void frame_destroy(frame_t *frame);

#endif // CHARLES_WEBSOCKET_FRAME_H
