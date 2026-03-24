// Author: Charles Cabergs <me@cacharle.xyz>
// URL: https://github.com/cacharle/xlibc

#ifndef XLIBC_H
#define XLIBC_H

#include <stddef.h>

void xset_program_name(const char *name);
void xdie(const char *format, ...);
void *xmalloc(size_t size);
void *xcalloc(size_t n, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *ptr);
char *xstrndup(const char *ptr, size_t size);

#endif  // XLIBC_H

#ifdef XLIBC_IMPLEMENTATION

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *xprogram_name = NULL;

void xset_program_name(const char *name)
{
    xprogram_name = name;
}

void xdie(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    if (xprogram_name != NULL)
        fputs("cws: ", stderr);
    vfprintf(stderr, format, ap);
    fprintf(stderr, ": %s\n", strerror(errno));
    va_end(ap);
    exit(EXIT_FAILURE);
}

void *xmalloc(size_t size)
{
    void *ret = malloc(size);
    if (ret == NULL)
        xdie("Unable to malloc");
    return ret;
}

void *xcalloc(size_t n, size_t size)
{
    void *ret = calloc(n, size);
    if (ret == NULL)
        xdie("Unable to calloc");
    return ret;
}

void *xrealloc(void *ptr, size_t size)
{
    if (size == 0)
        return NULL;
    void *ret = realloc(ptr, size);
    if (ret == NULL)
        xdie("Unable to realloc");
    return ret;
}

char *xstrdup(const char *s)
{
    void *ret = strdup(s);
    if (ret == NULL)
        xdie("Unable to strdup");
    return ret;
}

char *xstrndup(const char *s, size_t size)
{
    void *ret = strndup(s, size);
    if (ret == NULL)
        xdie("Unable to strndup");
    return ret;
}

#endif
