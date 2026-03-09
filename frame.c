#include "frame.h"
#include "utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct frame_header_layout
{
    // First byte in network order (logical protocol order is
    // final->reserverd->opcode)
    uint8_t opcode      : 4;
    uint8_t reserved    : 3;
    uint8_t final_frame : 1;
    // Second byte in network order (logical protocol order is
    // mask->payload_length_start)
    uint8_t payload_length_start : 7;
    uint8_t mask                 : 1;
};

void
frame_parser_init(frame_parser_t *parser)
{
    parser->header_parsed = false;
    parser->injested_payload_length = 0;
    parser->header_buffer_position = 0;
}

frame_parser_injest_result_t
frame_parser_injest(frame_parser_t *parser, uint8_t *data, size_t size)
{
    if (!parser->header_parsed)
    {
        size_t copied_size = MIN(size, sizeof(parser->header_buffer) - parser->header_buffer_position);
        memcpy(
            parser->header_buffer + parser->header_buffer_position,
            data,
            copied_size);
        size_t initial_header_buffer_position = parser->header_buffer_position;
        parser->header_buffer_position += copied_size;
        if (parser->header_buffer_position < sizeof(struct frame_header_layout))
            return FRAME_PARSER_INJEST_RESULT_PENDING;

        struct frame_header_layout *layout = (void *)parser->header_buffer;
        parser->frame.final = layout->final_frame;
        parser->frame.opcode = layout->opcode;
        // Check if the start layout is valid
        if (parser->frame.opcode != FRAME_OPCODE_CONTINUATION &&
            parser->frame.opcode != FRAME_OPCODE_TEXT &&
            parser->frame.opcode != FRAME_OPCODE_BINARY &&
            parser->frame.opcode != FRAME_OPCODE_CLOSE &&
            parser->frame.opcode != FRAME_OPCODE_PING &&
            parser->frame.opcode != FRAME_OPCODE_PONG)
            return FRAME_PARSER_INJEST_RESULT_ERROR;
        if ((parser->frame.opcode == FRAME_OPCODE_CLOSE ||
             parser->frame.opcode == FRAME_OPCODE_PING ||
             parser->frame.opcode == FRAME_OPCODE_PONG) &&
            layout->payload_length_start > 125)
            return FRAME_PARSER_INJEST_RESULT_ERROR;
        if (layout->reserved != 0)
            return FRAME_PARSER_INJEST_RESULT_ERROR;
        // Client to server MUST be masked
        if (!layout->mask)
            return FRAME_PARSER_INJEST_RESULT_ERROR;
        size_t size_of_payload_length = 0;
        uint8_t *header_buffer_ptr = parser->header_buffer + sizeof(struct frame_header_layout);
        // Extract the payload size
        if (layout->payload_length_start < 126)
            parser->frame.payload_length = layout->payload_length_start;
        else if (layout->payload_length_start == 126)
        {
            size_of_payload_length = sizeof(uint16_t);
            if (parser->header_buffer_position < sizeof(struct frame_header_layout) + size_of_payload_length)
                return FRAME_PARSER_INJEST_RESULT_PENDING;
            parser->frame.payload_length = ntohs(*(uint16_t *)header_buffer_ptr);
        }
        else if (layout->payload_length_start == 127)
        {
            size_of_payload_length = sizeof(uint64_t);
            if (parser->header_buffer_position < sizeof(struct frame_header_layout) + size_of_payload_length)
                return FRAME_PARSER_INJEST_RESULT_PENDING;
            parser->frame.payload_length = be64toh(*(uint64_t *)header_buffer_ptr);
        }
        header_buffer_ptr += size_of_payload_length;

        if (parser->header_buffer_position < sizeof(struct frame_header_layout) + size_of_payload_length + sizeof(uint32_t))
            return FRAME_PARSER_INJEST_RESULT_PENDING;
        parser->masking_key = *(uint32_t *)header_buffer_ptr;
        parser->header_parsed = true;

        size_t final_size = sizeof(struct frame_header_layout) + size_of_payload_length + sizeof(uint32_t);
        size_t used_size = final_size - initial_header_buffer_position;
        data += used_size;
        size -= used_size;

        if (size > parser->frame.payload_length) {
            printf("Error: this is strange\n");
            return FRAME_PARSER_INJEST_RESULT_ERROR;
        }

        // Initialize empty payload
        switch (parser->frame.opcode)
        {
        case FRAME_OPCODE_BINARY:
        case FRAME_OPCODE_PING:
        case FRAME_OPCODE_PONG:
            parser->frame.payload.binary = xmalloc(parser->frame.payload_length);
            break;
        case FRAME_OPCODE_TEXT:
            parser->frame.payload.text = xmalloc(parser->frame.payload_length + 1);
            break;
        case FRAME_OPCODE_CLOSE:
            parser->frame.payload.close.status_code = 0;
            if (parser->frame.payload_length > 2)
                parser->frame.payload.close.reason =
                    xmalloc(parser->frame.payload_length - 2);
            else
                parser->frame.payload.close.reason = NULL;
            break;
        case FRAME_OPCODE_CONTINUATION:
            break;
        }
        printf("Parsed header: %zu size: %zu\n", parser->frame.payload_length, size);
    }
    // Unmask data payload
    for (size_t i = 0; i < size; i++) {
        size_t offset = i + parser->injested_payload_length;
        data[i] ^= ((uint8_t *)&parser->masking_key)[offset % 4];
    }

    printf("Injesting data for %zu of %zu -> %zu\n", parser->frame.payload_length, parser->injested_payload_length, size);
    switch (parser->frame.opcode)
    {
    case FRAME_OPCODE_BINARY:
    case FRAME_OPCODE_PING:
    case FRAME_OPCODE_PONG:
        memcpy(parser->frame.payload.binary + parser->injested_payload_length, data, size);
        break;
    case FRAME_OPCODE_TEXT:
        memcpy(parser->frame.payload.text + parser->injested_payload_length, data, size);
        if (parser->injested_payload_length + size == parser->frame.payload_length)
            parser->frame.payload.text[parser->frame.payload_length] = '\0';
        break;
    case FRAME_OPCODE_CLOSE:
        if (parser->injested_payload_length == 0 && size >= 2)
        {
            parser->frame.payload.close.status_code = ntohs(*(uint16_t *)data);
            data += sizeof(uint16_t);
            size -= sizeof(uint16_t);
            parser->injested_payload_length += 2;
        }
        if (parser->frame.payload_length > parser->injested_payload_length)
            memcpy(parser->frame.payload.close.reason, data, size);
        break;
    default:
        break;
    }
    // Check if we're done parsing the frame
    parser->injested_payload_length += size;
    if (parser->injested_payload_length > parser->frame.payload_length)
        return FRAME_PARSER_INJEST_RESULT_ERROR;
    if (parser->injested_payload_length == parser->frame.payload_length)
        return FRAME_PARSER_INJEST_RESULT_DONE;
    else
        return FRAME_PARSER_INJEST_RESULT_PENDING;
}

void
frame_dump(frame_t *frame, uint8_t *dest, size_t *dest_size)
{
    struct frame_header_layout *layout = (void *)dest;
    layout->final_frame = frame->final;
    layout->reserved = 0;
    layout->opcode = frame->opcode;
    layout->mask = 0;
    void *bytes_rest = (void *)dest + sizeof(struct frame_header_layout);
    if (frame->payload_length < 126)
        layout->payload_length_start = frame->payload_length;
    else if (frame->payload_length <= USHRT_MAX)
    {
        layout->payload_length_start = 126;
        *(uint16_t *)bytes_rest = htons(frame->payload_length);
        bytes_rest += sizeof(uint16_t);
    }
    else
    {
        layout->payload_length_start = 127;
        *(uint64_t *)bytes_rest = htobe64(frame->payload_length);
        bytes_rest += sizeof(uint64_t);
    }
    switch (frame->opcode)
    {
    case FRAME_OPCODE_BINARY:
    case FRAME_OPCODE_PING:
    case FRAME_OPCODE_PONG:
        if (frame->payload.binary != NULL)
            memcpy(bytes_rest, frame->payload.binary, frame->payload_length);
        break;
    case FRAME_OPCODE_TEXT:
        if (frame->payload.text != NULL)
            memcpy(bytes_rest, frame->payload.text, frame->payload_length);
        break;
    case FRAME_OPCODE_CLOSE:
        *(uint16_t *)bytes_rest = htons(frame->payload.close.status_code);
        bytes_rest += sizeof(uint16_t);
        if (frame->payload_length > 2 && frame->payload.close.reason != NULL)
            memcpy(
                bytes_rest, frame->payload.close.reason, frame->payload_length - 2);
        bytes_rest -= sizeof(uint16_t);  // HACK: for dest_size after
        break;
    default:
        break;
    }
    size_t header_size = bytes_rest - (void *)layout;
    *dest_size = header_size + frame->payload_length;
}

// bool
// frame_parse(frame_t *frame, void *bytes, size_t size)
// {
//     size_t current_size = 0;
//     current_size += sizeof(struct frame_header_layout);
//     if (size < current_size)
//         return false;
//     struct frame_header_layout *layout = bytes;
//     frame->final = layout->final_frame;
//     frame->opcode = layout->opcode;
//     void *bytes_rest = bytes + sizeof(struct frame_header_layout);
//
//     if (frame->opcode != FRAME_OPCODE_CONTINUATION &&
//         frame->opcode != FRAME_OPCODE_TEXT && frame->opcode != FRAME_OPCODE_BINARY &&
//         frame->opcode != FRAME_OPCODE_CLOSE && frame->opcode != FRAME_OPCODE_PING &&
//         frame->opcode != FRAME_OPCODE_PONG)
//         return false;
//
//     if ((frame->opcode == FRAME_OPCODE_CLOSE || frame->opcode == FRAME_OPCODE_PING ||
//          frame->opcode == FRAME_OPCODE_PONG) &&
//         layout->payload_length_start > 125)
//         return false;
//
//     if (layout->payload_length_start < 126)
//     {
//         frame->payload_length = layout->payload_length_start;
//     }
//     else if (layout->payload_length_start == 126)
//     {
//         current_size += sizeof(uint16_t);
//         if (size < current_size)
//             return false;
//         frame->payload_length = ntohs(*(uint16_t *)bytes_rest);
//         bytes_rest += sizeof(uint16_t);
//     }
//     else if (layout->payload_length_start == 127)
//     {
//         current_size += sizeof(uint64_t);
//         if (size < current_size)
//             return false;
//         frame->payload_length = be64toh(*(uint64_t *)bytes_rest);
//         bytes_rest += sizeof(uint64_t);
//     }
//     if (!layout->mask)
//         return false;  // client to server MUST be masked
//
//     current_size += sizeof(uint32_t);
//     if (size < current_size)
//         return false;
//     uint32_t masking_key = *(uint32_t *)bytes_rest;
//     bytes_rest += sizeof(uint32_t);
//     uint8_t *tmp = bytes_rest;
//     if (size < current_size + frame->payload_length)
//         return false;
//     for (size_t i = 0; i < frame->payload_length; i++)
//         tmp[i] = tmp[i] ^ ((uint8_t *)&masking_key)[i % 4];
//
//     switch (frame->opcode)
//     {
//     case FRAME_OPCODE_BINARY:
//     case FRAME_OPCODE_PING:
//     case FRAME_OPCODE_PONG:
//         frame->payload.binary = malloc(frame->payload_length);
//         memcpy(frame->payload.binary, bytes_rest, frame->payload_length);
//         break;
//     case FRAME_OPCODE_TEXT:
//         frame->payload.text = malloc(frame->payload_length + 1);
//         memcpy(frame->payload.text, bytes_rest, frame->payload_length);
//         frame->payload.text[frame->payload_length] = '\0';
//         break;
//     case FRAME_OPCODE_CLOSE:
//         frame->payload.close.status_code = 0;
//         frame->payload.close.reason = NULL;
//         if (frame->payload_length >= 2)
//         {
//             frame->payload.close.status_code = ntohs(*(uint16_t *)bytes_rest);
//             bytes_rest += sizeof(uint16_t);
//             if (frame->payload_length > 2)
//             {
//                 frame->payload.close.reason = malloc(frame->payload_length - 2);
//                 memcpy(frame->payload.close.reason,
//                        bytes_rest,
//                        frame->payload_length - 2);
//             }
//         }
//         break;
//     default:
//         break;
//     }
//     return true;
// }

char *opcode_close_status_string[] = {
    [1000] = "Normal closure",
    [1001] = "Going away",
    [1002] = "Protocol error",
    [1003] = "Unsupported data",
    [1008] = "Policy violation",
    [1011] = "Internal error",
};

char *opcode_to_string[] = {
    [FRAME_OPCODE_CONTINUATION] = "continuation",
    [FRAME_OPCODE_TEXT] = "text",
    [FRAME_OPCODE_BINARY] = "binary",
    [FRAME_OPCODE_CLOSE] = "close",
    [FRAME_OPCODE_PING] = "ping",
    [FRAME_OPCODE_PONG] = "pong",
};

void
frame_print(const frame_t *frame)
{
    printf("frame{final: %d, opcode: %s, payload_length: %zu, payload: ",
           frame->final,
           opcode_to_string[frame->opcode],
           frame->payload_length);
    switch (frame->opcode)
    {
    case FRAME_OPCODE_BINARY:
        printf("[");
        if (frame->payload_length < 100)
        {
            for (size_t i = 0; i < frame->payload_length; i++)
                printf("%x", frame->payload.binary[i]);
        }
        else
            printf("too long to print");
        printf("]");
        break;
    case FRAME_OPCODE_TEXT:
        if (frame->payload_length < 100)
        {
            printf("\"%s\"", frame->payload.text);
        }
        else {
            char x = frame->payload.text[0];
            int count = 0;
            for (size_t i = 0; i < frame->payload_length; i++) {
                if (frame->payload.text[i] != x) {
                    printf("payload at %zu, different: %x vs %x\n", i, x, frame->payload.text[i]);
                    count++;
                    break;
                }
            }
            printf("too long to print %zu", count);
        }
        break;
    case FRAME_OPCODE_CLOSE:
        printf("[%u] ", frame->payload.close.status_code);
        if (frame->payload.close.reason != NULL)
        {
            for (size_t i = 0; i < frame->payload_length - 2; i++)
                printf("%c", frame->payload.close.reason[i]);
        }
        break;
    default:
        printf("none");
    }
    printf("}\n");
}

void
frame_destroy(frame_t *frame)
{
    switch (frame->opcode)
    {
    case FRAME_OPCODE_BINARY:
        free(frame->payload.binary);
        break;
    case FRAME_OPCODE_TEXT:
        free(frame->payload.text);
        break;
    case FRAME_OPCODE_CLOSE:
        free(frame->payload.close.reason);
        break;
    default:
        break;
    }
}
