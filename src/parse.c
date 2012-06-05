//#include <stdint.h>
//#include <stdio.h>
//#include <stdlib.h>

#include "parse.h"
#include "util.h"

int parse_arp(struct pkt *p)
{
	struct ether_arp	*arp;

	if (p->len < sizeof(struct ether_arp)) {
		log_msg(LOG_WARNING, "%s: Error parsing ARP packet. Packet is too small (%d of %d bytes)", p->ifc->name, p->len, sizeof(struct ether_arp));
		return -2;
	}

	arp = (struct ether_arp *) p->pos;
	p->arp = arp;
	p->pos += sizeof(struct ether_arp);
	p->len -= sizeof(struct ether_arp);

	/* Skip non ARP packets */
	if (ntohs(arp->ea_hdr.ar_hrd) != ARPHRD_ETHER)
		return -1;

	/* Skip non IP ARP packets */
	if (ntohs(arp->ea_hdr.ar_pro) != ETHERTYPE_IP)
		return -1;

	return 0;
}

int parse_nd(struct pkt *p)
{
	struct nd_neighbor_solicit	*ns;
	struct nd_neighbor_advert	*na;
	struct nd_opt_hdr	*opt;

	if (p->len < sizeof(struct nd_neighbor_solicit)) {
		log_msg(LOG_WARNING, "%s: Error parsing ICMPv6 ND packet. Packet is too small (%d of %d bytes)", p->ifc->name, p->len, sizeof(struct nd_neighbor_solicit));
		return -2;
	}

	if (p->icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
		ns = (struct nd_neighbor_solicit *) p->pos;
		p->ns = ns;
	} else if (p->icmp6->icmp6_type == ND_NEIGHBOR_ADVERT) {
		na = (struct nd_neighbor_advert *) p->pos;
		p->na = na;
	} else {
		return -1;
	}

	p->pos += sizeof(struct nd_neighbor_solicit);
	p->len -= sizeof(struct nd_neighbor_solicit);

	while (1) {
		if (p->len < sizeof(struct nd_opt_hdr))
			break;

		opt = (struct nd_opt_hdr *)p->pos;
		
		if (opt->nd_opt_len == 0) {
			log_msg(LOG_WARNING, "%s: Error parsing ICMPv6 ND options. Option length is 0.", p->ifc->name);
			return -2;
		}

		if (p->len < opt->nd_opt_len * 8) {
			log_msg(LOG_WARNING, "%s: Error parsing ICMPv6 ND options. Option header is too small (%d of %d bytes)", p->ifc->name, p->len, opt->nd_opt_len * 8);
			return -2;
		}
		p->pos += opt->nd_opt_len * 8;
		p->len -= opt->nd_opt_len * 8;

		switch(opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
			p->opt_slla = opt;
			break;
		case ND_OPT_TARGET_LINKADDR:
			p->opt_tlla = opt;
			break;
		default:
			break;
		}
	}

	return 0;
}

int parse_ipv6(struct pkt *p)
{
	struct ip6_hdr	*ip6;
	struct ip6_ext	*ip6e;
	struct icmp6_hdr	*icmp6;
	int	next_header;
	int	rc;

	if (p->len < sizeof(struct ip6_hdr)) {
		log_msg(LOG_WARNING, "%s: Error parsing IPv6 packet. Packet is too small (%d of %d bytes)", p->ifc->name, p->len, sizeof(struct ip6_hdr));
		return -2;
	}

	ip6 = (struct ip6_hdr *)p->pos;
	p->ip6 = ip6;
	p->pos += sizeof(struct ip6_hdr);
	p->len -= sizeof(struct ip6_hdr);

	next_header = ip6->ip6_nxt;
	// Skip IPv6 extension headers
	while (next_header != IPPROTO_ICMPV6 && next_header != -1) {
		switch (next_header) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_DSTOPTS:
			if (p->len < 8) {
				next_header = -1;
				log_msg(LOG_WARNING, "%s: Error parsing IPv6 packet. Extension header is too small (%d of %d bytes)", p->ifc->name, p->len, 8);
				return -2;
			}
			ip6e = (struct ip6_ext *)p->pos;
			if (p->len < (ip6e->ip6e_len + 1) * 8) {
				next_header = -1;
				log_msg(LOG_WARNING, "%s: Error parsing IPv6 packet. Extension header is too small (%d of %d bytes)", p->ifc->name, p->len, (ip6e->ip6e_len + 1) * 8);
				return -2;
			}
			p->pos += (ip6e->ip6e_len + 1) * 8;
			p->len -= (ip6e->ip6e_len + 1) * 8;
			next_header = ip6e->ip6e_nxt;
			break;
		default:
			next_header = -1;
			break;
		}
	}

	if (next_header == -1)
		return -1;

	if (p->len < sizeof(struct icmp6_hdr)) {
		log_msg(LOG_WARNING, "%s: Error parsing ICMPv6 packet. Header is too small (%d of %d bytes)", p->ifc->name, p->len, sizeof(struct icmp6_hdr));
		return -2;
	}

	icmp6 = (struct icmp6_hdr *)p->pos;
	p->icmp6 = icmp6;

	switch(icmp6->icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
		rc = parse_nd(p);
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

/*
 * Returns:
 * 	0	packet parsed either arp, ns or na
 * 	-1	packet is of some other type
 * 	-2	packet is malformed
 */
int parse_packet(struct pkt *p)
{
	int	rc;
	uint16_t ether_type;

	if (p->len < sizeof(struct ether_header)) {
		log_msg(LOG_WARNING, "%s: Error parsing Ethernet packet. Packet is too small (%d of %d bytes)", p->ifc->name, p->len, sizeof(struct ether_header));
		return -2;
	}

	p->ether = (struct ether_header *)p->pos;
	p->pos += sizeof(struct ether_header);
	p->len -= sizeof(struct ether_header);

	ether_type = ntohs(p->ether->ether_type);
	if (ether_type == ETHERTYPE_VLAN) {
		p->vlan_tag = ntohs(*(uint16_t *)p->pos) & 0xfff;
		p->pos += 4;
		p->len -= 4;
		ether_type = ntohs(*(uint16_t *)(p->pos -2));
	}

	switch (ether_type) {
	case ETHERTYPE_ARP:
		rc = parse_arp(p);
		break;
	case ETHERTYPE_IPV6:
		rc = parse_ipv6(p);
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

