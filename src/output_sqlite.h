#pragma once

#include "addrwatch.h"

void output_sqlite_init();
void output_sqlite_reload();
void output_sqlite_save(struct pkt *p, char *mac_addr, char *ip_addr);
void output_sqlite_close();

