#include "mcache.h"
#include "util.h"

#include <stdlib.h>
#include <assert.h>

#define IP4_LEN	4
#define IP6_LEN 16

struct mcache_node *cache_prune_node(struct mcache_node *n)
{
	struct mcache_node *next;

	next = n->next;
	free(n);

	return next;
};

// Delete dead_node and all nodes linked from dead_node
void cache_prune(struct mcache_node *dead_node, struct mcache_node **cache)
{
	struct mcache_node *node;

	if (dead_node == *cache) {
		*cache = NULL;
	} else {
		for (node = *cache;
			node && node->next != dead_node;
			node = node->next);

		assert(node->next == dead_node);
		node->next = NULL;
	}

	/* Delete remaining list */
	for (node = dead_node; node; node = cache_prune_node(node));
}

void cache_del(struct mcache_node *dead_node, struct mcache_node **cache)
{
	struct mcache_node *node;

	if (dead_node == *cache) {
		*cache = dead_node->next;
	} else {
		for (node = *cache;
			node && node->next != dead_node;
			node = node->next);

		assert(node->next == dead_node);
		node->next = dead_node->next;
	}

	free(dead_node);
}

struct mcache_node *cache_lookup(uint8_t *l2_addr, uint8_t *ip_addr, uint8_t len, time_t t, struct mcache_node **cache)
{
	struct mcache_node *node;

	for (node = *cache; node != NULL; node = node->next) {

		if (cfg.ratelimit > 0 && t > node->tstamp + cfg.ratelimit) {
			cache_prune(node, cache);
			return NULL;
		}

		if (len != node->addr_len)
			continue;

		if (memcmp(ip_addr, node->ip_addr, len))
			continue;

		if (memcmp(l2_addr, node->l2_addr, sizeof(node->l2_addr))) {
			cache_del(node, cache);
			return NULL;
		}

		return node;
	}

	return NULL;
}

