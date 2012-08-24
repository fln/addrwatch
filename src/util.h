#pragma once

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>

#include <syslog.h>

#include <arpa/inet.h>

static inline void ether_ntoa_m(uint8_t addr[], char *str)
{
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static inline void ip4_ntoa(void *addr, char *str)
{
	inet_ntop(AF_INET, addr, str, INET_ADDRSTRLEN);
}

static inline void ip6_ntoa(void *addr, char *str)
{
	inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
}

void log_open();
void log_msg(int priority, const char *format, ...);
void log_close();

