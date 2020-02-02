#ifndef OUTPUT_SQLITE_H
#define OUTPUT_SQLITE_H

#include "addrwatch.h"

void output_sqlite_init();
void output_sqlite_reload();
void output_sqlite_save(struct pkt *p, char *mac_str, char *ip_str);
void output_sqlite_close();

#endif
