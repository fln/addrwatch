#ifndef CHECK_H
#define CHECK_H

#include "addrwatch.h"

int check_arp(struct pkt *p);
int check_ns(struct pkt *p);
int check_na(struct pkt *p);

#endif
