#ifndef CHARLES_WEBSOCKET_UTILS_H
#define CHARLES_WEBSOCKET_UTILS_H

#include <stddef.h>

bool is_valid_utf8(const char *s_origin, size_t len);
void die(const char *format, ...);

#endif  // CHARLES_WEBSOCKET_UTILS_H
