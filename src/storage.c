#include "storage.h"
#include "util.h"
#include "mcache.h"

#include <stdlib.h>

#define IP4_LEN	4
#define IP6_LEN 16

static const char sql_create4[] = "\
CREATE TABLE IF NOT EXISTS ip4(\
timestamp UNSIGNED BIG INT, \
interface varchar(16), \
mac_address varchar(17), \
ip_address varchar(16), \
origin TINYINT\
);";
static const char sql_create6[] = "\
CREATE TABLE IF NOT EXISTS ip6(\
timestamp UNSIGNED BIG INT, \
interface varchar(16), \
mac_address varchar(17), \
ip_address varchar(42), \
origin TINYINT\
);";
static const char sql_insert4[] = "INSERT INTO ip4 VALUES(?, ?, ?, ?, ?);";
static const char sql_insert6[] = "INSERT INTO ip6 VALUES(?, ?, ?, ?, ?);";

static const char *pkt_origin_str[] = {
	"ARP_REQ",
	"ARP_REP",
	"ARP_ACD",
	"ND_NS",
	"ND_NA",
	"ND_DAD",
};

void sqlite_init()
{
#if HAVE_LIBSQLITE3
	int rc;

	if(!cfg.sql_file)
		return;

	rc = sqlite3_open(cfg.sql_file, &cfg.sql_conn);
	if (rc)
		log_msg(LOG_ERR, "Unable to open sqlite3 database file %s",
			cfg.sql_file);

	rc = sqlite3_exec(cfg.sql_conn, sql_create4, 0, 0, 0);
	if (rc)
		log_msg(LOG_ERR, "Unable to create sqlite3 map_ip4 table");

	rc = sqlite3_exec(cfg.sql_conn, sql_create6, 0, 0, 0);
	if (rc)
		log_msg(LOG_ERR, "Unable to create sqlite3 map_ip4 table");

	rc = sqlite3_prepare_v2(cfg.sql_conn, sql_insert4, sizeof(sql_insert4), 
		&cfg.sql_stmt4, NULL);
	if (rc)
		log_msg(LOG_ERR, "Error preparing ipv4 address insert statement");

	rc = sqlite3_prepare_v2(cfg.sql_conn, sql_insert6, sizeof(sql_insert6), 
		&cfg.sql_stmt6, NULL);
	if (rc)
		log_msg(LOG_ERR, "Error preparing ipv6 address insert statement");

	sqlite3_busy_timeout(cfg.sql_conn, 100);
	log_msg(LOG_DEBUG, "Saving results to %s sqlite database", cfg.sql_file);
#endif
}

void sqlite_close()
{
#if HAVE_LIBSQLITE3
	if (cfg.sql_conn) {
		sqlite3_finalize(cfg.sql_stmt4);
		sqlite3_finalize(cfg.sql_stmt6);
		sqlite3_close(cfg.sql_conn);
	}
#endif
}

void datafile_init()
{
	if (cfg.data_file) {
		cfg.data_fd = fopen(cfg.data_file, "a");
		if (!cfg.data_fd)
			log_msg(LOG_ERR, "Unable to open data file %s",
				cfg.data_file);

		log_msg(LOG_DEBUG, "Saving results to '%s' flat file",
			cfg.data_file);
	}
}

void datafile_close()
{
	if (cfg.data_fd)
		fclose(cfg.data_fd);
}

void save_pairing(uint8_t *l2_addr, uint8_t *ip_addr, struct pkt *p,
	uint8_t addr_len, enum pkt_origin o)
{
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];
	struct mcache_node *cnode;
	time_t tstamp;
	int rc;
#if HAVE_LIBSQLITE3
	sqlite3_stmt *stmt;
#endif

	ether_ntoa_m(l2_addr, mac_str);
	if (addr_len == IP6_LEN)
		ip6_ntoa(ip_addr, ip_str);
	else
		ip4_ntoa(ip_addr, ip_str);

	tstamp = 0;
	time(&tstamp);

	if (cfg.ratelimit
		&& cache_lookup(l2_addr, ip_addr, addr_len, tstamp, &p->ifc->cache))
		return;

	if (!cfg.quiet) {
		printf("%lu %s %s %s %s\n", tstamp, p->ifc->name, mac_str,
			ip_str, pkt_origin_str[o]);
		fflush(stdout);
	}

	if (cfg.syslog_flag)
		log_msg(LOG_INFO, "%lu %s %s %s %s", tstamp, p->ifc->name, mac_str, ip_str, pkt_origin_str[o]);

	if (cfg.data_fd) {
		fprintf(cfg.data_fd, "%lu %s %s %s %s\n", tstamp, p->ifc->name, mac_str, ip_str, pkt_origin_str[o]);
		fflush(cfg.data_fd);
	}

#if HAVE_LIBSQLITE3
	if (cfg.sql_conn) {
		if (addr_len == IP6_LEN)
			stmt = cfg.sql_stmt6;
		else
			stmt = cfg.sql_stmt4;

		rc = sqlite3_bind_int64(stmt, 1, tstamp);
		rc += sqlite3_bind_text(stmt, 2, p->ifc->name, -1, NULL);
		rc += sqlite3_bind_text(stmt, 3, mac_str, -1, NULL);
		rc += sqlite3_bind_text(stmt, 4, ip_str, -1, NULL);
		rc += sqlite3_bind_int(stmt, 5, o);
		if (rc)
			log_msg(LOG_ERR, "Unable to bind values to sql statement");

		rc = sqlite3_step(stmt);
		switch(rc) {
		case SQLITE_DONE:
			break;
		case SQLITE_BUSY:
			log_msg(LOG_WARNING, "Unable to execute sqlite prepared statement, database is locked (%ld, %s, %s, %s)", tstamp, p->ifc->name, mac_str, ip_str);
			break;
		default:
			log_msg(LOG_ERR, "Error executing sqlite prepared statement (%d)", rc);
			break;
		}

		rc = sqlite3_reset(stmt);
		if (rc && rc != SQLITE_BUSY)
			log_msg(LOG_ERR, "Error reseting sqlite prepared statement (%d)", rc);
	}
#endif

	if (cfg.ratelimit) {
		cnode = (struct mcache_node *) calloc(sizeof(struct mcache_node), 1);
		memcpy(cnode->l2_addr, l2_addr, sizeof(cnode->l2_addr));
		memcpy(cnode->ip_addr, ip_addr, addr_len);
		cnode->tstamp = tstamp;
		cnode->addr_len = addr_len;

		cnode->next = p->ifc->cache;
		p->ifc->cache = cnode;
	}

}

