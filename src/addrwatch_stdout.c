#include "shm.h"
#include "shm_client.h"

#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>

void process_entry(struct shm_log_entry *e, void *arg)
{
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];
	ether_ntoa_m(e->mac_address, mac_str);

	if (e->ip_len == 16) {
		ip6_ntoa(e->ip_address, ip_str);
	} else {
		ip4_ntoa(e->ip_address, ip_str);
	}

	printf("%" PRId64 " %s %u %s %s %s\n", e->timestamp, e->interface,
		e->vlan_tag, mac_str, ip_str, pkt_origin_str[e->origin]);
}

int main(int argc, char *argv[])
{
	main_loop(process_entry, NULL);
	return 0;
}
