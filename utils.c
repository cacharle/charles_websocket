#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

void *
xmalloc(size_t size)
{
    void *ret = malloc(size);
    if (ret == NULL)
        abort();
    return ret;
}

// LLM generated
bool is_valid_utf8(const unsigned char *s, size_t len) {
    size_t i = 0;

    while (i < len) {
        uint32_t codepoint;
        unsigned char c = s[i];

        if (c <= 0x7F) {
            // 1-byte ASCII
            i += 1;
            continue;
        }

        else if ((c & 0xE0) == 0xC0) {
            // 2-byte sequence
            if (i + 1 >= len) return false;
            unsigned char c1 = s[i+1];
            if ((c1 & 0xC0) != 0x80) return false;
            codepoint = ((c & 0x1F) << 6) | (c1 & 0x3F);
            if (codepoint < 0x80) return false; // overlong
            i += 2;
        }

        else if ((c & 0xF0) == 0xE0) {
            // 3-byte sequence
            if (i + 2 >= len) return false;
            unsigned char c1 = s[i+1];
            unsigned char c2 = s[i+2];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return false;
            codepoint = ((c & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);
            if (codepoint < 0x800) return false; // overlong
            if (codepoint >= 0xD800 && codepoint <= 0xDFFF) return false; // surrogate
            i += 3;
        }

        else if ((c & 0xF8) == 0xF0) {
            // 4-byte sequence
            if (i + 3 >= len) return false;
            unsigned char c1 = s[i+1];
            unsigned char c2 = s[i+2];
            unsigned char c3 = s[i+3];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80)
                return false;
            codepoint = ((c & 0x07) << 18) | ((c1 & 0x3F) << 12) |
                        ((c2 & 0x3F) << 6) | (c3 & 0x3F);
            if (codepoint < 0x10000 || codepoint > 0x10FFFF) return false; // overlong or out of range
            i += 4;
        }

        else {
            return false; // invalid leading byte
        }
    }

    return true;
}
