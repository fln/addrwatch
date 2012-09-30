#pragma once

#include <stdint.h>
#include <net/if.h>

#define ADDRWATCH_SHM_NAME "addrwatch-shm-log"
#define MAGIC 0xc0decafe

struct shm_log_entry {
	uint64_t timestamp;
	uint8_t  interface[IFNAMSIZ];
	uint8_t  ip_address[16];
	uint8_t  mac_address[6];
	uint8_t  ip_len;
	uint8_t  origin;
	uint16_t vlan_tag;
};

struct shm_log {
	uint64_t magic;
	uint64_t size;
	uint64_t last_idx;
	struct shm_log_entry data[];
};

