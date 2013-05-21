#pragma once

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <pcap.h>
#include <event.h>
#include <time.h>
#if HAVE_LIBSQLITE3
	#include <sqlite3.h>
#endif
#if HAVE_LIBMYSQLCLIENT
	#include <mysql/mysql.h>
#endif

#include <net/ethernet.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>

#include "mcache.h"

#define SNAP_LEN       9000
#define MAC_STR_LEN    18

enum pkt_origin {
	ARP_REQ,
	ARP_REP,
	ARP_ACD,
	ND_NS,
	ND_NA,
	ND_DAD,
};

struct iface_config {
	char *name;
#if HAVE_LIBEVENT2
	struct event *event;
#else
	struct event event;
#endif

	struct bpf_program pcap_filter;
	pcap_t *pcap_handle;

	struct mcache_node **cache;

	struct iface_config *next;
};

struct addrwatch_config {
	int ratelimit;
	int hashsize;
	int quiet;

	int promisc_flag;
	uint8_t v4_flag;
	uint8_t v6_flag;
	uint8_t syslog_flag;
	uint8_t daemon_flag;
	uint8_t verbose_flag;

	char *uname;
	long  hostname_len;
	char *hostname;

	struct ip_node *blacklist;
	
	char *pid_file;
	char *data_file;
	FILE *data_fd;

#if HAVE_LIBSQLITE3
	char *sqlite_file;
	char *sqlite_table;
	sqlite3      *sqlite_conn;
	sqlite3_stmt *sqlite_stmt;
#endif
#if HAVE_LIBMYSQLCLIENT
	uint8_t     mysql_flag;
	char       *mysql_db;
	char       *mysql_config;
	char       *mysql_table;
	MYSQL      *mysql_conn;
	MYSQL_STMT *mysql_stmt;
	MYSQL_BIND  mysql_bind[6];
	struct {
		long long int timestamp;
		char          hostname[256];
		unsigned long hostname_len;
		char          iface[IFNAMSIZ];
		unsigned long iface_len;
		int           vlan;
		//char          mac[ETHER_ADDR_LEN];
		char          mac[MAC_STR_LEN];
		unsigned long mac_len;
		char          ip[INET6_ADDRSTRLEN];
		unsigned long ip_len;
		char          origin[8];
		unsigned long origin_len;
	} mysql_vars;
#endif

	struct event_base *eb;
#if HAVE_LIBEVENT2
	struct event *sigint_ev;
	struct event *sigterm_ev;
	struct event *sighup_ev;
#else
	struct event sigint_ev;
	struct event sigterm_ev;
	struct event sighup_ev;
#endif

	struct iface_config *interfaces;
};

struct pkt {
	uint8_t *raw_packet;

	uint8_t *pos;
	int len;

	struct iface_config *ifc;
	const struct pcap_pkthdr *pcap_header;

	uint16_t vlan_tag;
	struct ether_header *ether;
	struct ether_arp *arp;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_solicit *ns;
	struct nd_neighbor_advert *na;
	struct nd_opt_hdr *opt_slla;
	struct nd_opt_hdr *opt_tlla;

	uint8_t         *l2_addr;
	uint8_t         *ip_addr;
	uint8_t          ip_len;
	enum pkt_origin  origin;
};

struct ip_node {
	uint8_t ip_addr[16];
	uint8_t addr_len;

	struct ip_node *next;
};

extern struct addrwatch_config cfg;
extern const char *pkt_origin_str[];
