#include "logging.h"

void printHex(unsigned char* buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x",buf[i]);
    }
    fprintf(stderr, "\n");
}