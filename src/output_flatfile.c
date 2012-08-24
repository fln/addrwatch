#include "output_flatfile.h"
#include "util.h"

void output_flatfile_init()
{
	if (cfg.data_file) {
		cfg.data_fd = fopen(cfg.data_file, "a");
		if (!cfg.data_fd)
			log_msg(LOG_ERR, "Unable to open flat file %s",
				cfg.data_file);

		log_msg(LOG_DEBUG, "Saving results to '%s' flat file",
			cfg.data_file);
	}
}

void output_flatfile_reload()
{
	output_flatfile_close();
	output_flatfile_init();
}

void output_flatfile_save(struct pkt *p, char *mac_str, char *ip_str)
{
	if (cfg.data_fd) {
		fprintf(cfg.data_fd, "%lu %s %u %s %s %s\n", p->pcap_header->ts.tv_sec, p->ifc->name, p->vlan_tag, mac_str, ip_str, pkt_origin_str[p->origin]);
		fflush(cfg.data_fd);
	}
}

void output_flatfile_close()
{
	if (cfg.data_fd)
		fclose(cfg.data_fd);
}

