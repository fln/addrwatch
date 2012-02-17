#include "check.h"
#include "util.h"

#define IN6_IS_ADDR_SN_MULTICAST(a,b) \
	(  ((__const uint32_t *) (a))[0] == htonl (0xff020000)            \
	&& ((__const uint32_t *) (a))[1] ==                 0             \
	&& ((__const uint32_t *) (a))[2] == htonl (0x00000001)            \
	&& ((__const uint8_t *) (a))[12] == 0xff                          \
	&& ((__const uint8_t *) (a))[13] == ((__const uint8_t *) (b))[13] \
	&& ((__const uint8_t *) (a))[14] == ((__const uint8_t *) (b))[14] \
	&& ((__const uint8_t *) (a))[15] == ((__const uint8_t *) (b))[15] )

int check_arp(struct pkt *p)
{
	struct ether_arp *arp;
	char l2_addr1[MAC_STR_LEN];
	char l2_addr2[MAC_STR_LEN];
	char ip_addr[INET_ADDRSTRLEN];
	int rc;

	arp = p->arp;
	rc = 0;

	if (arp->ea_hdr.ar_hln != ETH_ALEN) {
		log_msg(LOG_WARNING, "%s: Malformed ARP packet. Wrong hardware size.", p->ifc->name);
		rc = -1;
	}

	if (arp->ea_hdr.ar_pln != 4) {
		log_msg(LOG_WARNING, "%s: Malformed ARP packet. Wrong protocol size.", p->ifc->name);
		rc = -1;
	}

	if (memcmp(p->ether->ether_shost, arp->arp_sha, ETH_ALEN) != 0) {
		ether_ntoa_m(p->ether->ether_shost, l2_addr1);
		ether_ntoa_m(arp->arp_sha, l2_addr2);
		ip4_ntoa(arp->arp_spa, ip_addr);
		log_msg(LOG_WARNING, "%s: Malformed ARP packet. Erhernet and ARP source address missmatch (%s != %s) [%s].", p->ifc->name, l2_addr1, l2_addr2, ip_addr);
		rc = -1;
	}

	return rc;
}

int check_ns(struct pkt *p)
{
	struct nd_neighbor_solicit *ns;
	struct ip6_hdr *ip6;
	char ip6_addr[INET6_ADDRSTRLEN];
	char ip6_addr2[INET6_ADDRSTRLEN];
	int rc;

	ns = p->ns;
	ip6 = p->ip6;
	rc = 0;


	if (ip6->ip6_hlim != 255) {
		log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NS packet. IPv6 Hop Limit is not 255.", p->ifc->name);
		rc = -1;
	}

	if (p->icmp6->icmp6_code != 0) {
		log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NS packet. ICMPv6 Code is not 0.", p->ifc->name);
		rc = -1;
	}


	if (IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target)) {
		ip6_ntoa((uint8_t *) &ns->nd_ns_target, ip6_addr);
		log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NS packet. Target address is multicast (%s).", p->ifc->name, ip6_addr);
		rc = -1;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
		if (!IN6_IS_ADDR_SN_MULTICAST(&ip6->ip6_dst, &ns->nd_ns_target)) {
			ip6_ntoa((uint8_t *) &ip6->ip6_dst, ip6_addr);
			ip6_ntoa((uint8_t *) &ns->nd_ns_target, ip6_addr2);
			log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NS packet. Src IP is unspecified and dst IP is not solicited-note multicast address (%s, %s).", p->ifc->name, ip6_addr, ip6_addr2);
			rc = -1;
		}
		if (p->opt_slla) {
			log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NS packet. Src IP is unspecified and source link-layer address option is present.", p->ifc->name);
			rc = -1;
		}
	}

	return rc;
}

int check_na(struct pkt *p)
{
	struct nd_neighbor_advert *na;
	struct ip6_hdr *ip6;
	char ip6_addr[INET6_ADDRSTRLEN];
	int rc;

	na = p->na;
	ip6 = p->ip6;
	rc = 0;

	if (ip6->ip6_hlim != 255) {
		log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NA packet. IPv6 Hop Limit is not 255.", p->ifc->name);
		rc = -1;
	}

	if (p->icmp6->icmp6_code != 0) {
		log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NA packet. ICMPv6 Code is not 0.", p->ifc->name);
		rc = -1;
	}

	if (IN6_IS_ADDR_MULTICAST(&na->nd_na_target)) {
		ip6_ntoa((uint8_t *) &na->nd_na_target, ip6_addr);
		log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NA packet. Target address is multicast (%s).", p->ifc->name, ip6_addr);
		rc = -1;
	}

	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) 
		&& na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED) {
		log_msg(LOG_WARNING, "%s: Malformed ICMPv6 NA packet. Dst IP is multicast address, but Solicited flag is set.", p->ifc->name);
		rc = -1;
	}

	return rc;
}
