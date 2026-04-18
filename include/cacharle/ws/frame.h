#ifndef CHARLES_WEBSOCKET_FRAME_H
#define CHARLES_WEBSOCKET_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum
{
    FRAME_OPCODE_CONTINUATION = 0x0,
    FRAME_OPCODE_TEXT = 0x1,
    FRAME_OPCODE_BINARY = 0x2,
    FRAME_OPCODE_CLOSE = 0x8,
    FRAME_OPCODE_PING = 0x9,
    FRAME_OPCODE_PONG = 0xA
} frame_opcode_t;

typedef struct
{
    bool final;
    bool permessage_deflate;
    frame_opcode_t opcode;
    size_t payload_length;
    union
    {
        char *text;
        uint8_t *binary;
        struct
        {
            uint16_t status_code;
            char *reason;
        } close;
    } payload;
} frame_t;

typedef struct
{
    frame_t frame;
    uint32_t masking_key;
    bool header_parsed;
    size_t ingested_payload_length;
    uint8_t header_buffer[16];
    size_t header_buffer_position;
    bool permessage_deflate_allowed;
} frame_parser_t;

typedef enum
{
    FRAME_PARSER_INGEST_RESULT_DONE,
    FRAME_PARSER_INGEST_RESULT_PENDING,
    FRAME_PARSER_INGEST_RESULT_ERROR,
    FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL,
    FRAME_PARSER_INGEST_RESULT_ERROR_UNSUPPORTED_DATA,
    FRAME_PARSER_INGEST_RESULT_ERROR_INVALID_PAYLOAD,
    FRAME_PARSER_INGEST_RESULT_ERROR_POLICY_VIOLATION,
    FRAME_PARSER_INGEST_RESULT_ERROR_TOO_BIG,
    FRAME_PARSER_INGEST_RESULT_ERROR_EXTENSION_NEEDED,
    FRAME_PARSER_INGEST_RESULT_ERROR_INTERNAL,
} frame_parser_ingest_result_t;

#define FRAME_PARSER_INGEST_RESULT_IS_ERROR(e) \
    ((e) >= FRAME_PARSER_INGEST_RESULT_ERROR)

void frame_parser_init(frame_parser_t *parser, bool permessage_deflate_allowed);
frame_parser_ingest_result_t frame_parser_ingest(frame_parser_t *parser,
                                                 uint8_t *data,
                                                 size_t size,
                                                 size_t *remaining_data_size);

void frame_dump(frame_t *frame, uint8_t *dest, size_t *dest_size);
void frame_print(const frame_t *frame);
void frame_destroy(frame_t *frame);

void frame_compress(frame_t *frame);
void frame_uncompress(frame_t *frame);

#endif  // CHARLES_WEBSOCKET_FRAME_H
