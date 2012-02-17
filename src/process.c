#include "process.h"
#include "util.h"
#include "base64.h"
#include "storage.h"

#define MAC_STR_LEN     18

void process_arp(struct pkt *p)
{
	struct ether_arp *arp;

	arp = p->arp;

	if (*(uint32_t *)arp->arp_spa == INADDR_ANY) {
//		printf("%s: ARP ACD packet\n", p->ifc->name);
		save_ipv4_mapping(arp->arp_sha, arp->arp_tpa, p);
		return;
	}

	if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
//		printf("%s: ARP REQ packet\n", p->ifc->name);
		save_ipv4_mapping(arp->arp_sha, arp->arp_spa, p);
		return;
	}

}

void process_ns(struct pkt *p)
{
	if (IN6_IS_ADDR_UNSPECIFIED(&p->ip6->ip6_src)) {
//		printf("%s: IPv6 DAD packet\n", p->ifc->name);
		save_ipv6_mapping(p->ether->ether_shost, (uint8_t *) &p->ns->nd_ns_target, p);
		return;
	}

	if (p->opt_slla) {
//		printf("%s: IPv6 NS packet\n", p->ifc->name);
		save_ipv6_mapping((uint8_t *)(p->opt_slla + 1), (uint8_t *) &p->ip6->ip6_src, p);
		return;
	}
}

void process_na(struct pkt *p)
{
	if (p->opt_tlla)
		save_ipv6_mapping((uint8_t *)(p->opt_tlla + 1), (uint8_t *) &p->na->nd_na_target, p);
}

