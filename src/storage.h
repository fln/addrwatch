#pragma once

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "addrwatch.h"

enum origin {
	ARP_REQ,
	ARP_REP,
	ARP_ACD,
	ND_NS,
	ND_NA,
	ND_DAD,
};

void sqlite_init();
void sqlite_close();

void datafile_init();
void datafile_close();

void save_ipv4_mapping(uint8_t *l2_addr, uint8_t *ip_addr, struct pkt *p);
void save_ipv6_mapping(uint8_t *l2_addr, uint8_t *ip_addr, struct pkt *p);

