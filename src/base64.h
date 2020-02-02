#ifndef BASE64_H
#define BASE64_H

#include "addrwatch.h"
#include <stdint.h>

void base64_encode(const uint8_t *src, char *dst, int ssize, int dsize);
char *base64_encode_packet(struct pkt *p);

#endif
