#pragma once

#include "addrwatch.h"

void output_mysql_init();
void output_mysql_reload();
void output_mysql_save(struct pkt *p, char *mac_str, char *ip_str);
void output_mysql_close();

