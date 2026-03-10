#ifndef CHARLES_WEBSOCKET_UTILS_H
#define CHARLES_WEBSOCKET_UTILS_H

#include <stddef.h>

void *xmalloc(size_t size);
bool is_valid_utf8(const unsigned char *s, size_t len);

#endif // CHARLES_WEBSOCKET_UTILS_H
