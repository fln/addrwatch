#include "output_shm.h"
#include "util.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

void output_shm_init()
{
	int fd;
	size_t mem_size;
	void *addr;

	mem_size = sizeof(struct shm_log)
		   + sizeof(struct shm_log_entry) * cfg.shm_data.size;

	fd = shm_open(cfg.shm_data.name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1)
		log_msg(LOG_ERR, "Error creating shared memory");

	if (ftruncate(fd, mem_size) == -1)
		log_msg(LOG_ERR, "Error setting shared memory size");

	addr = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED)
		log_msg(LOG_ERR, "Error mapping shared memory");

	close(fd);

	cfg.shm_data.log = (struct shm_log *)addr;
}

void output_shm_reload()
{
}

void output_shm_save(struct pkt *p, char *mac_str, char *ip_str)
{
	struct shm_log *log;
	struct shm_log_entry *e;
	uint64_t idx;

	log = cfg.shm_data.log;
	if (log->magic != MAGIC)
		idx = 0;
	else
		idx = (log->last_idx + 1) % cfg.shm_data.size;

	e = &log->data[idx];

	e->timestamp = p->pcap_header->ts.tv_sec;
	strncpy((char *)e->interface, p->ifc->name, IFNAMSIZ);
	memcpy(e->ip_address, p->ip_addr, p->ip_len);
	memcpy(e->mac_address, p->l2_addr, sizeof(e->mac_address));
	e->ip_len = p->ip_len;
	e->origin = p->origin;
	e->vlan_tag = p->vlan_tag;

	log->last_idx = idx;
	log->size = cfg.shm_data.size;
	if (log->magic != MAGIC)
		log->magic = MAGIC;
}

void output_shm_close()
{
	if (munmap(cfg.shm_data.log, cfg.shm_data.log->size) == -1)
		log_msg(LOG_ERR, "Error unmapping shared memory");
}
