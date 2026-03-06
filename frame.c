#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "frame.h"

struct frame_header_layout {
    // First byte in network order (logical protocol order is final->reserverd->opcode)
    uint8_t opcode : 4;
    uint8_t reserved : 3;
    uint8_t final_frame : 1;
    // Second byte in network order (logical protocol order is mask->payload_length_start)
    uint8_t payload_length_start : 7;
    uint8_t mask : 1;
};

void frame_parse(frame_t* frame, const void *bytes, size_t size)
{
    const struct frame_header_layout *layout = bytes;
    frame->final = layout->final_frame;
    frame->opcode = layout->opcode;
    const void *bytes_rest = bytes + sizeof(struct frame_header_layout);
    if (layout->payload_length_start < 126) {
        frame->payload_length = layout->payload_length_start;
    }
    else if (layout->payload_length_start == 126) {
        frame->payload_length = *(uint16_t*)bytes_rest;
        bytes_rest += sizeof(uint16_t);
    }
    else if (layout->payload_length_start == 127) {
        frame->payload_length = *(uint64_t*)bytes_rest;
        bytes_rest += sizeof(uint64_t);
    }
    uint32_t masking_key = 0;
    if (layout->mask) {
        masking_key = *(uint32_t*)bytes_rest;
        bytes_rest += sizeof(uint32_t);
    }
    switch (frame->opcode) {
    case FRAME_OPCODE_BINARY:
        frame->payload.binary = malloc(frame->payload_length);
        memcpy(frame->payload.binary, bytes_rest, frame->payload_length);
        break;
    case FRAME_OPCODE_TEXT:
        frame->payload.text = malloc(frame->payload_length + 1);
        memcpy(frame->payload.text, bytes_rest, frame->payload_length);
        frame->payload.text[frame->payload_length] = '\0';
        break;
    default:
        break;
    }
    if (layout->mask) {
        for (size_t i = 0; i < frame->payload_length; i++)
            frame->payload.binary[i] = frame->payload.binary[i] ^ ((uint8_t*)&masking_key)[i % 4];
    }
}

char *opcode_to_string[] = {
    [FRAME_OPCODE_CONTINUATION] = "continuation",
    [FRAME_OPCODE_TEXT]  = "text",
    [FRAME_OPCODE_BINARY] =  "binary",
    [FRAME_OPCODE_CLOSE]  = "close",
    [FRAME_OPCODE_PING]  = "ping",
    [FRAME_OPCODE_PONG]  = "pong",
};

void frame_print(const frame_t *frame)
{
    printf(
        "frame{final: %d, opcode: %s, payload_length: %zu, payload: ",
        frame->final,
        opcode_to_string[frame->opcode],
        frame->payload_length);
    switch (frame->opcode) {
    case FRAME_OPCODE_BINARY:
        printf("[");
        for (size_t i = 0; i <frame->payload_length; i++)
            printf("%x", frame->payload.binary[i]);
        printf("]");
        break;
    case FRAME_OPCODE_TEXT:
        printf("\"%s\"", frame->payload.text);
        break;
    default:
        printf("none");
    }
    printf("}\n");
}
