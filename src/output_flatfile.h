#ifndef OUTPUT_FLATFILE_H
#define OUTPUT_FLATFILE_H

#include "addrwatch.h"

void output_flatfile_init();
void output_flatfile_reload();
void output_flatfile_save(struct pkt *p, char *mac_str, char *ip_str);
void output_flatfile_close();

#endif
