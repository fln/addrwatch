#include "shm.h"

#include <stdio.h>
#include <netinet/in.h>

#define MAC_STR_LEN    18

void process_entry(struct shm_log_entry *e)
{
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];
	ether_ntoa_m(e->mac_address, mac_str);

	if (e->ip_len == 16)
		ip6_ntoa(e->ip_address, ip_str);
	else
		ip4_ntoa(e->ip_address, ip_str);

	printf("%lu %s %u %s %s %s\n", e->timestamp, e->interface, e->vlan_tag, 
	                        mac_str, ip_str, origin_to_string(e->origin));

}

int main(int argc, char *argv[])
{
	main_loop(process_entry);

}
