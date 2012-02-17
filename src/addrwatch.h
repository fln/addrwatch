#pragma once

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "mcache.h"

#include <pcap.h>
#include <event.h>
#include <time.h>
#if HAVE_LIBSQLITE3
	#include <sqlite3.h>
#endif

#include <net/ethernet.h>
#include <net/if.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>

#define PROG_NAME "addrwatch"
#define SNAP_LEN 9000

struct iface_config {
	char *name;
	struct event *event;

	struct bpf_program pcap_filter;
	pcap_t *pcap_handle;

	struct mcache_node *cache;

	struct iface_config *next;
};

struct addrwatch_config {
	int ratelimit;
	int promisc;
	int quiet;

	uint8_t v4_flag;
	uint8_t v6_flag;
	uint8_t syslog_flag;
	uint8_t daemon_flag;

	char *uname;
	
	char *data_file;
	FILE *data_fd;

#if HAVE_LIBSQLITE3
	char *sql_file;
	sqlite3 *sql_conn;
	sqlite3_stmt *sql_stmt4;
	sqlite3_stmt *sql_stmt6;
#endif

	struct event_base *eb;
	struct event *sigint_ev;
	struct event *sigterm_ev;
	struct event *sighup_ev;

	struct iface_config *interfaces;
};

struct pkt {
	uint8_t	*raw_packet;
	int	raw_len;

	uint8_t *pos;
	int	len;

	struct iface_config	*ifc;
	const struct pcap_pkthdr	*pcap_header;

	struct ether_header	*ether;
	struct ether_arp	*arp;
	struct ip6_hdr	*ip6;
	struct icmp6_hdr        *icmp6;
	struct nd_neighbor_solicit	*ns;
	struct nd_neighbor_advert	*na;
	struct nd_opt_hdr	*opt_slla;
	struct nd_opt_hdr	*opt_tlla;
};

extern struct addrwatch_config cfg;

