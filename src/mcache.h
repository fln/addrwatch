#pragma once
#include "addrwatch.h"

#include <stdint.h>
#include <net/ethernet.h>

struct mcache_node {
	uint8_t l2_addr[ETHER_ADDR_LEN];
	uint8_t ip_addr[16];
	time_t tstamp;
	uint8_t addr_len;
	uint16_t vlan_tag;

	struct mcache_node *next;
};

void cache_prune(struct mcache_node *dead_node, struct mcache_node **cache);
void cache_del(struct mcache_node *dead_node, struct mcache_node **cache);
void cache_add(uint8_t *l2_addr, uint8_t *ip_addr, uint8_t len, time_t tstamp, uint16_t vlan_tag, struct mcache_node **cache);
struct mcache_node *cache_lookup(uint8_t *l2_addr, uint8_t *ip_addr, uint8_t len, time_t tstamp, uint16_t vlan_tag, struct mcache_node **cache);

