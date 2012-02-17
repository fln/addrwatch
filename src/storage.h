#pragma once

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "addrwatch.h"

enum pkt_origin {
	ARP_REQ,
	ARP_REP,
	ARP_ACD,
	ND_NS,
	ND_NA,
	ND_DAD,
};

enum ip_type_len {
	IP4_LEN = 4,
	IP6_LEN = 16,
};

void sqlite_init();
void sqlite_close();

void datafile_init();
void datafile_close();

void save_pairing(uint8_t *l2_addr, uint8_t *ip_addr, struct pkt *p,
	uint8_t addr_len, enum pkt_origin o);

