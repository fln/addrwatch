#include "storage.h"
#include "util.h"
#include "mcache.h"
#include "output_flatfile.h"
#include "output_sqlite.h"
#include "output_mysql.h"

#include <stdlib.h>

#define IP4_LEN	4
#define IP6_LEN 16

const char *pkt_origin_str[] = {
	"ARP_REQ",
	"ARP_REP",
	"ARP_ACD",
	"ND_NS",
	"ND_NA",
	"ND_DAD",
};

void blacklist_add(char *ip_str)
{
	struct ip_node *ip;
	int rc;

	ip = (struct ip_node *) calloc(sizeof(struct ip_node), 1);

	rc = inet_pton(AF_INET, ip_str, ip->ip_addr);
	if (rc == 1) {
		ip->addr_len = IP4_LEN;
		ip->next = cfg.blacklist;
		cfg.blacklist = ip;
		return;
	}

	rc = inet_pton(AF_INET6, ip_str, ip->ip_addr);
	if (rc == 1) {
		ip->addr_len = IP6_LEN;
		ip->next = cfg.blacklist;
		cfg.blacklist = ip;
		return;
	}

	free(ip);
	log_msg(LOG_ERR, "Unable to blacklist, '%s' is not a valid IPv4 or IPv6 address", ip_str);
}

void blacklist_free()
{
	struct ip_node *ip;
	struct ip_node *ip_next;

	for (ip = cfg.blacklist; ip; ip = ip_next) {
		ip_next = ip->next;
		free(ip);
	}

	cfg.blacklist = NULL;
}

struct ip_node *blacklist_match(uint8_t *ip_addr, uint8_t addr_len)
{
	struct ip_node *ip;

	for (ip = cfg.blacklist; ip; ip = ip->next) {
		if (addr_len != ip->addr_len)
			continue;

		if (memcmp(ip_addr, ip->ip_addr, addr_len))
			continue;

		return ip;
	}

	return NULL;
}

inline uint16_t pkt_hash(uint8_t *l2_addr, uint8_t *ip_addr, uint8_t len, uint16_t vlan_tag)
{
	int i;
	uint16_t sum;

	sum = 0;
	for (i = 0; i < 6; i += 2)
		sum = sum ^ *(uint16_t *)(l2_addr+i);

	for (i = 0; i < len; i += 2)
		sum = sum ^ *(uint16_t *)(ip_addr+i);

	sum = sum ^ vlan_tag;

	return sum;
}

void save_pairing(struct pkt *p)
{
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];
	time_t tstamp;
	uint16_t hash;

	if (blacklist_match(p->ip_addr, p->ip_len))
		return;

	tstamp = p->pcap_header->ts.tv_sec;

	if (cfg.ratelimit) {
		hash = pkt_hash(p->l2_addr, p->ip_addr, p->ip_len, p->vlan_tag);
		hash = hash % cfg.hashsize;
		if(cache_lookup(p->l2_addr, p->ip_addr, p->ip_len, tstamp, p->vlan_tag, p->ifc->cache + hash))
			return;
	}

	ether_ntoa_m(p->l2_addr, mac_str);
	if (p->ip_len == IP6_LEN)
		ip6_ntoa(p->ip_addr, ip_str);
	else
		ip4_ntoa(p->ip_addr, ip_str);

	if (!cfg.quiet) {
		printf("%lu %s %u %s %s %s\n", tstamp, p->ifc->name, p->vlan_tag, 
			mac_str, ip_str, pkt_origin_str[p->origin]);
		fflush(stdout);
	}

	if (cfg.syslog_flag)
		log_msg(LOG_INFO, "%lu %s %u %s %s %s", tstamp, p->ifc->name, p->vlan_tag, mac_str, ip_str, pkt_origin_str[p->origin]);

	if (cfg.data_fd)
		output_flatfile_save(p, mac_str, ip_str);

#if HAVE_LIBMYSQLCLIENT
	if (cfg.mysql_conn)
		output_mysql_save(p, mac_str, ip_str);
#endif
#if HAVE_LIBSQLITE3
	if (cfg.sqlite_file)
		output_sqlite_save(p, mac_str, ip_str);
#endif

	if (cfg.ratelimit)
		cache_add(p->l2_addr, p->ip_addr, p->ip_len, tstamp, p->vlan_tag, p->ifc->cache + hash);
}

