#pragma once

#include "addrwatch.h"

void process_arp(struct pkt *p);
void process_ns(struct pkt *p);
void process_na(struct pkt *p);

