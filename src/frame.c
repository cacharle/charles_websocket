#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "frame.h"
#include "utils.h"
#include "xlibc.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct frame_header_layout
{
    // First byte in network order (logical protocol order is
    // final->reserved->opcode)
    uint8_t opcode : 4;
    uint8_t reserved : 2;
    uint8_t permessage_deflate : 1;
    uint8_t final_frame : 1;
    // Second byte in network order (logical protocol order is
    // mask->payload_length_start)
    uint8_t payload_length_start : 7;
    uint8_t mask : 1;
};

void frame_parser_init(frame_parser_t *parser, bool permessage_deflate_allowed)
{
    parser->header_parsed = false;
    parser->ingested_payload_length = 0;
    parser->header_buffer_position = 0;
    memset(&parser->frame, 0, sizeof(frame_t));
    parser->frame.opcode = -1;
    parser->permessage_deflate_allowed = permessage_deflate_allowed;
}

static uint16_t valid_close_codes[] = {
    1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011};
constexpr size_t valid_close_codes_length =
    sizeof(valid_close_codes) / sizeof(valid_close_codes[0]);

frame_parser_ingest_result_t frame_parser_ingest(frame_parser_t *parser,
                                                 uint8_t *data,
                                                 size_t size,
                                                 size_t *remaining_data_size)
{
    *remaining_data_size = 0;

    if (!parser->header_parsed)
    {
        size_t copied_size = MIN(
            size, sizeof(parser->header_buffer) - parser->header_buffer_position);
        memcpy(parser->header_buffer + parser->header_buffer_position,
               data,
               copied_size);
        size_t initial_header_buffer_position = parser->header_buffer_position;
        parser->header_buffer_position += copied_size;
        if (parser->header_buffer_position < sizeof(struct frame_header_layout))
            return FRAME_PARSER_INGEST_RESULT_PENDING;

        struct frame_header_layout *layout = (void *)parser->header_buffer;
        parser->frame.final = layout->final_frame;
        parser->frame.permessage_deflate = layout->permessage_deflate;
        parser->frame.opcode = layout->opcode;
        // Check if the start layout is valid
        if (parser->frame.opcode != FRAME_OPCODE_CONTINUATION &&
            parser->frame.opcode != FRAME_OPCODE_TEXT &&
            parser->frame.opcode != FRAME_OPCODE_BINARY &&
            parser->frame.opcode != FRAME_OPCODE_CLOSE &&
            parser->frame.opcode != FRAME_OPCODE_PING &&
            parser->frame.opcode != FRAME_OPCODE_PONG)
            return FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL;
        if ((parser->frame.opcode == FRAME_OPCODE_CLOSE ||
             parser->frame.opcode == FRAME_OPCODE_PING ||
             parser->frame.opcode == FRAME_OPCODE_PONG) &&
            (layout->payload_length_start > 125 || !parser->frame.final ||
             parser->frame.permessage_deflate))
            return FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL;

        if (layout->reserved != 0)
            return FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL;
        if (layout->permessage_deflate && !parser->permessage_deflate_allowed)
            return FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL;
        // Client to server MUST be masked
        if (!layout->mask)
            return FRAME_PARSER_INGEST_RESULT_ERROR;
        size_t size_of_payload_length = 0;
        uint8_t *header_buffer_ptr =
            parser->header_buffer + sizeof(struct frame_header_layout);
        // Extract the payload size
        if (layout->payload_length_start < 126)
            parser->frame.payload_length = layout->payload_length_start;
        else if (layout->payload_length_start == 126)
        {
            size_of_payload_length = sizeof(uint16_t);
            if (parser->header_buffer_position <
                sizeof(struct frame_header_layout) + size_of_payload_length)
                return FRAME_PARSER_INGEST_RESULT_PENDING;
            parser->frame.payload_length = ntohs(*(uint16_t *)header_buffer_ptr);
        }
        else if (layout->payload_length_start == 127)
        {
            size_of_payload_length = sizeof(uint64_t);
            if (parser->header_buffer_position <
                sizeof(struct frame_header_layout) + size_of_payload_length)
                return FRAME_PARSER_INGEST_RESULT_PENDING;
            parser->frame.payload_length = be64toh(*(uint64_t *)header_buffer_ptr);
        }
        header_buffer_ptr += size_of_payload_length;

        if (parser->header_buffer_position < sizeof(struct frame_header_layout) +
                                                 size_of_payload_length +
                                                 sizeof(uint32_t))
            return FRAME_PARSER_INGEST_RESULT_PENDING;
        parser->masking_key = *(uint32_t *)header_buffer_ptr;
        parser->header_parsed = true;

        size_t final_size = sizeof(struct frame_header_layout) +
                            size_of_payload_length + sizeof(uint32_t);
        size_t used_size = final_size - initial_header_buffer_position;
        data += used_size;
        size -= used_size;

        // Initialize empty payload
        switch (parser->frame.opcode)
        {
        case FRAME_OPCODE_BINARY:
        case FRAME_OPCODE_PING:
        case FRAME_OPCODE_PONG:
        case FRAME_OPCODE_CONTINUATION:
            parser->frame.payload.binary = xmalloc(parser->frame.payload_length);
            break;
        case FRAME_OPCODE_TEXT:
            parser->frame.payload.text = xmalloc(parser->frame.payload_length);
            break;
        case FRAME_OPCODE_CLOSE:
            parser->frame.payload.close.status_code = 0;
            if (parser->frame.payload_length > 2)
                parser->frame.payload.close.reason =
                    xmalloc(parser->frame.payload_length - 2);
            else
                parser->frame.payload.close.reason = NULL;
            break;
        }
    }

    if (parser->ingested_payload_length + size > parser->frame.payload_length)
    {
        size_t size_to_consume =
            parser->frame.payload_length - parser->ingested_payload_length;
        *remaining_data_size = size - size_to_consume;
        size = size_to_consume;
    }

    // Unmask data payload
    for (size_t i = 0; i < size; i++)
    {
        size_t offset = i + parser->ingested_payload_length;
        data[i] ^= ((uint8_t *)&parser->masking_key)[offset % 4];
    }

    switch (parser->frame.opcode)
    {
    case FRAME_OPCODE_BINARY:
    case FRAME_OPCODE_PING:
    case FRAME_OPCODE_PONG:
    case FRAME_OPCODE_CONTINUATION:
        memcpy(parser->frame.payload.binary + parser->ingested_payload_length,
               data,
               size);
        break;
    case FRAME_OPCODE_TEXT:
        // printf("here ingested = %zu, payload_length = %zu, size = %zu\n",
        // parser->ingested_payload_length, parser->frame.payload_length, size);
        memcpy(parser->frame.payload.text + parser->ingested_payload_length,
               data,
               size);
        break;
    case FRAME_OPCODE_CLOSE:
        // The code has to be 2 bytes or absent, it makes no sense to get a 1 byte
        // payload for a close frame
        if (parser->frame.payload_length == 1)
            return FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL;
        if (parser->ingested_payload_length == 0 && size >= 2)
        {
            parser->frame.payload.close.status_code = ntohs(*(uint16_t *)data);
            bool is_valid = false;
            for (size_t i = 0; i < valid_close_codes_length; i++)
                if (valid_close_codes[i] == parser->frame.payload.close.status_code)
                    is_valid = true;
            // 3000-3999 are valid reserved for custom use by libraries
            if (3000 <= parser->frame.payload.close.status_code &&
                parser->frame.payload.close.status_code <= 3999)
                is_valid = true;
            // 4000-4999 are valid reserved for custom use by private code
            if (4000 <= parser->frame.payload.close.status_code &&
                parser->frame.payload.close.status_code <= 4999)
                is_valid = true;
            if (!is_valid)
                return FRAME_PARSER_INGEST_RESULT_ERROR_PROTOCOL;
            data += sizeof(uint16_t);
            size -= sizeof(uint16_t);
            parser->ingested_payload_length += 2;
        }
        if (parser->ingested_payload_length >= 2 &&
            parser->frame.payload_length > parser->ingested_payload_length)
            memcpy(parser->frame.payload.close.reason +
                       parser->ingested_payload_length - 2,
                   data,
                   size);
        break;
    default:
        break;
    }
    // Check if we're done parsing the frame
    parser->ingested_payload_length += size;
    if (parser->ingested_payload_length > parser->frame.payload_length)
        return FRAME_PARSER_INGEST_RESULT_ERROR;
    if (parser->ingested_payload_length == parser->frame.payload_length)
    {
        if (parser->frame.opcode == FRAME_OPCODE_CLOSE &&
            parser->frame.payload.close.reason != NULL &&
            !is_valid_utf8(parser->frame.payload.close.reason,
                           parser->frame.payload_length - 2))
            return FRAME_PARSER_INGEST_RESULT_ERROR_INVALID_PAYLOAD;
        return FRAME_PARSER_INGEST_RESULT_DONE;
    }
    else
        return FRAME_PARSER_INGEST_RESULT_PENDING;
}

void frame_compress(frame_t *frame)
{
    if (!frame->permessage_deflate)
        return;
    if (frame->opcode != FRAME_OPCODE_BINARY && frame->opcode != FRAME_OPCODE_TEXT)
        return;
    // From:
    // https://github.com/machinezone/IXWebSocket/blob/master/ixwebsocket/IXWebSocketPerMessageDeflateCodec.cpp#L106
    if (frame->payload_length == 0)
    {
        frame->payload.binary = xmalloc(2);
        memcpy(frame->payload.binary, "\x02\x00", 2);
        frame->payload_length = 2;
        return;
    }

    z_stream stream;
    memset(&stream, 0, sizeof stream);
    int result = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -1 * 15, 4, Z_DEFAULT_STRATEGY);
    if (result != Z_OK)
        xdie("Unable to deflateInit2: %s", zError(result));

    stream.next_in = frame->payload.binary;
    stream.avail_in = frame->payload_length;
    uint8_t buffer[4096];
    void *compressed = NULL;
    size_t compressed_length = 0;
    do
    {
        stream.avail_out = 4096;
        stream.next_out = buffer;
        deflate(&stream, Z_FULL_FLUSH);
        size_t output_size = 4096 - stream.avail_out;
        compressed = xrealloc(compressed, compressed_length + output_size);
        memcpy(compressed + compressed_length, buffer, output_size);
        compressed_length += output_size;
    } while (stream.avail_out == 0);

    // Remove the empty uncompressed block if there is any at the end
    if (compressed_length > 4 &&
        memcmp(compressed + compressed_length - 4, "\x00\x00\xff\xff", 4) == 0)
        compressed_length -= 4;
    free(frame->payload.binary);
    frame->payload.binary = compressed;
    frame->payload_length = compressed_length;
    deflateEnd(&stream);
}

void frame_uncompress(frame_t *frame)
{
    if (!frame->permessage_deflate)
        return;
    if (frame->opcode != FRAME_OPCODE_BINARY && frame->opcode != FRAME_OPCODE_TEXT)
        return;
    // Reappropriated from ixWebsocket:
    // https://github.com/machinezone/IXWebSocket/blob/master/ixwebsocket/IXWebSocketPerMessageDeflateCodec.cpp#L209
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    int result = inflateInit2(&stream, -1 * 15);  // 15 is inflate bits
    if (result != Z_OK)
        xdie("Unable to inflateInit2: %s", zError(result));

    // Append the 4 magic bytes at the end of the payload
    size_t input_size = frame->payload_length + 4;
    frame->payload.binary = xrealloc(frame->payload.binary, input_size);
    memcpy(frame->payload.binary + frame->payload_length, "\x00\x00\xff\xff", 4);
    stream.avail_in = input_size;
    stream.next_in = frame->payload.binary;

    uint8_t buffer[4096];
    void *decompressed = NULL;
    size_t decompressed_length = 0;
    do
    {
        stream.avail_out = 4096;
        stream.next_out = buffer;
        result = inflate(&stream, Z_SYNC_FLUSH);
        if (result != Z_OK && result != Z_STREAM_END && result != Z_BUF_ERROR)
            xdie("Unable to inflate: %s", zError(result));
        size_t output_size = 4096 - stream.avail_out;
        decompressed = xrealloc(decompressed, decompressed_length + output_size);
        memcpy(decompressed + decompressed_length, buffer, output_size);
        decompressed_length += output_size;
    } while (stream.avail_out == 0);
    free(frame->payload.binary);
    frame->payload.binary = decompressed;
    frame->payload_length = decompressed_length;
    // printf("HERE AFTER UNCOMPRESS\n");
    // frame_print(frame);
    inflateEnd(&stream);
}

void frame_dump(frame_t *frame, uint8_t *dest, size_t *dest_size)
{
    struct frame_header_layout *layout = (void *)dest;
    layout->final_frame = frame->final;
    layout->reserved = 0;
    layout->permessage_deflate = frame->permessage_deflate;
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
    size_t header_size = bytes_rest - (void *)layout;
    switch (frame->opcode)
    {
    case FRAME_OPCODE_BINARY:
    case FRAME_OPCODE_PING:
    case FRAME_OPCODE_PONG:
    case FRAME_OPCODE_TEXT:
        if (frame->payload.binary != NULL)
            memcpy(bytes_rest, frame->payload.binary, frame->payload_length);
        break;
    case FRAME_OPCODE_CLOSE:
        *(uint16_t *)bytes_rest = htons(frame->payload.close.status_code);
        if (frame->payload_length > 2 && frame->payload.close.reason != NULL)
            memcpy(bytes_rest + sizeof(uint16_t),
                   frame->payload.close.reason,
                   frame->payload_length - 2);
        break;
    default:
        break;
    }
    *dest_size = header_size + frame->payload_length;
}

char *opcode_to_string[] = {
    [FRAME_OPCODE_CONTINUATION] = "continuation",
    [FRAME_OPCODE_TEXT] = "text",
    [FRAME_OPCODE_BINARY] = "binary",
    [FRAME_OPCODE_CLOSE] = "close",
    [FRAME_OPCODE_PING] = "ping",
    [FRAME_OPCODE_PONG] = "pong",
};

void frame_print(const frame_t *frame)
{
    printf("frame{final: %d, deflate: %d, opcode: %s, payload_length: %zu, "
           "payload: ",
           frame->final,
           frame->permessage_deflate,
           opcode_to_string[frame->opcode],
           frame->payload_length);
    switch (frame->opcode)
    {
    case FRAME_OPCODE_BINARY:
    case FRAME_OPCODE_CONTINUATION:
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
        if (frame->payload_length < 256)
        {
            printf("\"");
            for (size_t i = 0; i < frame->payload_length; i++)
            {
                if (frame->payload.text[i] == '\\')
                    printf("\\\\");
                else if (frame->payload.text[i] == '"')
                    printf("\\\"");
                else if (frame->payload.text[i] != ' ' &&
                         isspace(frame->payload.text[i]))
                {
                    char lookup[] = {
                        ['\f'] = 'f',
                        ['\n'] = 'n',
                        ['\r'] = 'r',
                        ['\t'] = 't',
                        ['\v'] = 'v',
                    };
                    printf("\\%c", lookup[(int)frame->payload.text[i]]);
                }
                else if (isprint(frame->payload.text[i]))
                    printf("%c", frame->payload.text[i]);
                else
                    printf("\\x%02x", (unsigned char)frame->payload.text[i]);
            }
            printf("\"");
        }
        else
            printf("too long to print");
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

void frame_destroy(frame_t *frame)
{
    switch (frame->opcode)
    {
    case FRAME_OPCODE_BINARY:
    case FRAME_OPCODE_PING:
    case FRAME_OPCODE_PONG:
    case FRAME_OPCODE_CONTINUATION:
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
