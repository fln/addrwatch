#ifndef COMMON_H
#define COMMON_H

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/socket.h>

#define MAC_STR_LEN 18

enum pkt_origin {
	ARP_REQ,
	ARP_REP,
	ARP_ACD,
	ND_NS,
	ND_NA,
	ND_DAD,
};

static inline void ether_ntoa_m(uint8_t addr[], char *str)
{
	snprintf(str, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0],
		addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static inline void ip4_ntoa(void *addr, char *str)
{
	inet_ntop(AF_INET, addr, str, INET_ADDRSTRLEN);
}

static inline void ip6_ntoa(void *addr, char *str)
{
	inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
}

#endif
