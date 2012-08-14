#include "mcache.h"
#include "util.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// Delete dead_node and all following nodes from cache
void cache_prune(struct mcache_node *dead_node, struct mcache_node **cache)
{
	struct mcache_node *node;
	struct mcache_node *next;

	if (dead_node == *cache) {
		*cache = NULL;
	} else {
		for (node = *cache;
			node && node->next != dead_node;
			node = node->next);

		/* Assert that dead_node was found in the cache */
		assert(node->next == dead_node);
		node->next = NULL;
	}

	/* Delete remaining list */
	for (node = dead_node; node; node = next) {
		next = node->next;
		free(node);
	}
}

// Delete only deda_node from the cache
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

// Add new node to the cache
void cache_add(uint8_t *l2_addr, uint8_t *ip_addr, uint8_t len,
	time_t tstamp, uint16_t vlan_tag, struct mcache_node **cache)
{
	struct mcache_node *node;

	node = (struct mcache_node *) calloc(sizeof(*node), 1);

	if (!node)
		log_msg(LOG_ERR, "%s: unable to allocate memory for new cache node", __FUNCTION__);

	memcpy(node->l2_addr, l2_addr, sizeof(node->l2_addr));
	memcpy(node->ip_addr, ip_addr, len);
	node->tstamp = tstamp;
	node->addr_len = len;
	node->vlan_tag = vlan_tag;

	node->next = *cache;
	*cache = node;
}

struct mcache_node *cache_lookup(uint8_t *l2_addr, uint8_t *ip_addr, 
	uint8_t len, time_t tstamp, uint16_t vlan_tag, struct mcache_node **cache)
{
	struct mcache_node *node;

	for (node = *cache; node != NULL; node = node->next) {
		/* New cache nodes are inserted at the begining of the list
		 * resulting cache list ordered by timestamp.
		 *
		 * If we find old cache node we can safely delete it and all
		 * following nodes.
		 */
		if (cfg.ratelimit > 0 && tstamp > node->tstamp + cfg.ratelimit) {
			cache_prune(node, cache);
			return NULL;
		}

		if (vlan_tag != node->vlan_tag)
			continue;

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

