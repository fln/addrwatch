#pragma once

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "addrwatch.h"

enum ip_type_len {
	IP4_LEN = 4,
	IP6_LEN = 16,
};

void datafile_init();
void datafile_close();

void blacklist_add(char *ip_str);
void blacklist_free();
struct ip_node *blacklist_match(uint8_t *ip_addr, uint8_t addr_len);

void save_pairing(struct pkt *p);

