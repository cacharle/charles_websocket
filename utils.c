#include <stdlib.h>
#include <stdbool.h>

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
        if (s[i] <= 0x7F) {
            i += 1;
        } else if ((s[i] & 0xE0) == 0xC0) {
            if (i + 1 >= len) return false;
            if ((s[i+1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((s[i] & 0xF0) == 0xE0) {
            if (i + 2 >= len) return false;
            if ((s[i+1] & 0xC0) != 0x80 || (s[i+2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((s[i] & 0xF8) == 0xF0) {
            if (i + 3 >= len) return false;
            if ((s[i+1] & 0xC0) != 0x80 || (s[i+2] & 0xC0) != 0x80 || (s[i+3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}
