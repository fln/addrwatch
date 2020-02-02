#ifndef SHM_H
#define SHM_H

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#define DEFAULT_SHM_LOG_NAME "addrwatch-shm-log"
#define MAGIC 0xc0decafe
#define POLL_INTERVAL 50
#define WAIT_INTERVAL 500

struct shm_log_entry {
	uint64_t timestamp;
	uint8_t interface[IFNAMSIZ];
	uint8_t ip_address[16];
	uint8_t mac_address[ETHER_ADDR_LEN];
	uint8_t ip_len;
	uint8_t origin;
	uint16_t vlan_tag;
};

struct shm_log {
	uint64_t magic;
	uint64_t size;
	uint64_t last_idx;
	struct shm_log_entry data[];
};

typedef void (*entry_callback_t)(struct shm_log_entry *e, void *arg);

#endif
