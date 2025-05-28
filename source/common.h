#pragma once
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>

#define align_up(x, align) __builtin_align_up(x, align)

#define print_error(func, ret, ...) do { fprintf(stderr, "%s:%i : " func " failed (ret=%i)\n", __FILE_NAME__, __LINE__, ##__VA_ARGS__, ret); } while (0);

#define CHECK_STRUCT_SIZE(X, Y) _Static_assert(sizeof(X) == Y, "sizeof(" #X ") is incorrect! (should be " #Y ")")

static inline void hexdump(const char* fmt, const void* x, size_t len, ...) {
    va_list ap;
    va_start(ap, len);
    vprintf(fmt, ap);
    va_end(ap);

    const uint8_t* data = (const uint8_t *)x;
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);

        if ((i+1) % 16 == 0 || i + 1 >= len)
            putchar('\n');
        else if ((i+1) % 4 == 0)
            printf("| ");
    }
}
