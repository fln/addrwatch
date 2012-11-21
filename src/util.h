#pragma once

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>

#include <syslog.h>

void log_open();
void log_msg(int priority, const char *format, ...);
void log_close();

