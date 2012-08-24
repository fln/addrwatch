#include "process.h"
#include "util.h"
#include "base64.h"
#include "storage.h"

#define MAC_STR_LEN     18

void process_arp(struct pkt *p)
{
	struct ether_arp *arp;

	arp = p->arp;

	p->ip_len = IP4_LEN;

	if (*(uint32_t *)arp->arp_spa == INADDR_ANY) {
		p->l2_addr = arp->arp_sha;
		p->ip_addr = arp->arp_tpa;
		p->origin = ARP_ACD;
		save_pairing(p);
		return;
	}

	if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
		p->l2_addr = arp->arp_sha;
		p->ip_addr = arp->arp_spa;
		p->origin = ARP_REQ;
		save_pairing(p);
		return;
	}

	if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
		p->l2_addr = arp->arp_sha;
		p->ip_addr = arp->arp_spa;
		p->origin = ARP_REP;
		save_pairing(p);
		return;
	}

}

void process_ns(struct pkt *p)
{
	p->ip_len = IP6_LEN;

	if (IN6_IS_ADDR_UNSPECIFIED(&p->ip6->ip6_src)) {
		p->l2_addr = p->ether->ether_shost;
		p->ip_addr = (uint8_t *) &p->ns->nd_ns_target;
		p->origin = ND_DAD;
		save_pairing(p);
		return;
	}

	if (p->opt_slla) {
		p->l2_addr = (uint8_t *)(p->opt_slla + 1);
		p->ip_addr = (uint8_t *) &p->ip6->ip6_src;
		p->origin = ND_NS;
		save_pairing(p);
		return;
	}
}

void process_na(struct pkt *p)
{
	p->ip_len = IP6_LEN;

	if (p->opt_tlla) {
		p->l2_addr = (uint8_t *)(p->opt_tlla + 1);
		p->ip_addr = (uint8_t *) &p->na->nd_na_target;
		p->origin = ND_NA;
		save_pairing(p);
		return;
	}
}

