#ifndef UTIL_H
#define UTIL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <inttypes.h>
#include <stdio.h>

#include <syslog.h>

void log_open(char *ident);
void log_max_priority(int priority);
void log_syslog_only(int flag);
void log_msg(int priority, const char *format, ...);
void log_close();

#endif
