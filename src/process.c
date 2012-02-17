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
		save_pairing(arp->arp_sha, arp->arp_tpa, p, IP4_LEN, ARP_ACD);
		return;
	}

	if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
		save_pairing(arp->arp_sha, arp->arp_spa, p, IP4_LEN, ARP_REQ);
		return;
	}

	if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
		save_pairing(arp->arp_sha, arp->arp_spa, p, IP4_LEN, ARP_REP);
		return;
	}

}

void process_ns(struct pkt *p)
{
	if (IN6_IS_ADDR_UNSPECIFIED(&p->ip6->ip6_src)) {
		save_pairing(p->ether->ether_shost,
			(uint8_t *) &p->ns->nd_ns_target, p, IP6_LEN, ND_DAD);
		return;
	}

	if (p->opt_slla) {
		save_pairing((uint8_t *)(p->opt_slla + 1), 
			(uint8_t *) &p->ip6->ip6_src, p, IP6_LEN, ND_NS);
		return;
	}
}

void process_na(struct pkt *p)
{
	if (p->opt_tlla)
		save_pairing((uint8_t *)(p->opt_tlla + 1),
			(uint8_t *) &p->na->nd_na_target, p, IP6_LEN, ND_NA);
}

