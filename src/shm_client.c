#include "shm_client.h"

#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

const char *pkt_origin_str[] = { "ARP_REQ", "ARP_REP", "ARP_ACD", "ND_NS",
	"ND_NA", "ND_DAD", NULL };

const char *pkt_origin_desc[] = { "ARP Request packet", "ARP Reply packet",
	"ARP Address collision detection packet", "Neighbor Solicitation packet",
	"Neighbor Advertisement packet", "Duplicate Address Detection packet", NULL };

static inline void close_log(void *addr, size_t mem_size)
{
	if (munmap(addr, mem_size) == -1) {
		perror("munmap");
		exit(EXIT_FAILURE);
	}
}

static inline struct shm_log *open_log(size_t *mem_size)
{
	int fd;
	struct stat info;
	struct shm_log *addr;

	fd = shm_open(DEFAULT_SHM_LOG_NAME, O_RDONLY, S_IRUSR | S_IWUSR);
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

void main_loop(entry_callback_t cb, void *arg)
{
	size_t mem_size;
	uint64_t size;
	uint64_t idx;
	struct shm_log *log;

	log = open_log(&mem_size);

	while (log->magic != MAGIC) {
		usleep(WAIT_INTERVAL * 1000);
	}

	size = log->size;
	idx = log->last_idx;

	while (1) {
		if (log->magic != MAGIC) {
			return;
		}

		if (size != log->size) {
			close_log(log, mem_size);
			log = open_log(&mem_size);
			idx = idx % log->size;
			continue;
		}

		if (idx == log->last_idx) {
			usleep(POLL_INTERVAL * 1000);
			continue;
		}

		idx = (idx + 1) % size;

		cb(&log->data[idx], arg);
	}
}
