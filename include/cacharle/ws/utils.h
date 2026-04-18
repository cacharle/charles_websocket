#ifndef CHARLES_WEBSOCKET_UTILS_H
#define CHARLES_WEBSOCKET_UTILS_H

#include <stdbool.h>
#include <stddef.h>

bool is_valid_utf8(const char *s_origin, size_t len);

#endif  // CHARLES_WEBSOCKET_UTILS_H
