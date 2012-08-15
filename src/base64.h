#pragma once

#include "addrwatch.h"
#include <stdint.h>

void base64_encode(uint8_t *src, char *dest, int ssize, int dsize);
char *base64_encode_packet(struct pkt *p);

