#pragma once

#include "addrwatch.h"

int check_arp(struct pkt *p);
int check_ns(struct pkt *p);
int check_na(struct pkt *p);

