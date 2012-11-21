#pragma once

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "common.h"

#define ADDRWATCH_SHM_NAME "addrwatch-shm-log"
#define MAGIC 0xc0decafe
#define POLL_INTERVAL 50
#define WAIT_INTERVAL 500

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

typedef void (* entry_callback_t)(struct shm_log_entry *e);

static inline char *origin_to_string(uint8_t origin)
{
	switch (origin) {
		case ARP_REQ:
			return "ARP_REQ";
		case ARP_REP:
			return "ARP_REP";
		case ARP_ACD:
			return "ARP_ACD";
		case ND_NS:
			return "ND_NS";
		case ND_NA:
			return "ND_NA";
		case ND_DAD:
			return "ND_DAD";
	}
}

static inline void close_log(void *addr, size_t mem_size)
{
	if (munmap(addr, mem_size) == -1) {
		perror("munmap");
		exit(EXIT_FAILURE);
	}
}

static inline struct shm_log *open_log(size_t *mem_size)
{
	int             fd;
	struct stat     info;
	struct shm_log *addr;

	fd = shm_open(ADDRWATCH_SHM_NAME, O_RDONLY, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		perror("shm_open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &info) == -1) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	*mem_size = info.st_size;
	addr = mmap(NULL, *mem_size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	if (close(fd) == -1) {
		perror("close");
		exit(EXIT_FAILURE);
	}

	return addr;
}

static inline void main_loop(entry_callback_t cb)
{
	size_t          mem_size;
	uint64_t        size;
	uint64_t        idx;
	struct shm_log *log;

	log = open_log(&mem_size);

	while (log->magic != MAGIC)
		usleep(WAIT_INTERVAL*1000);

	size = log->size;
	idx = log->last_idx;

	while(1) {
		if (log->magic != MAGIC)
			return;

		if (size != log->size) {
			close_log(log, mem_size);
			log = open_log(&mem_size);
			idx = idx % log->size;
			continue;
		}

		if (idx == log->last_idx) {
			usleep(POLL_INTERVAL*1000);
			continue;
		}

		idx = (idx + 1) % size;

		cb(&log->data[idx]);
	}
}

