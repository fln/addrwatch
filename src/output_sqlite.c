#include "output_sqlite.h"
#include "util.h"

#include <stdlib.h>

static const char sql_create[] = "\
CREATE TABLE IF NOT EXISTS addrwatch(\
timestamp UNSIGNED BIG INT, \
interface varchar(16), \
vlan_tag UNSIGNED INT, \
mac_address varchar(17), \
ip_address varchar(42), \
origin TINYINT\
);";

static const char sql_insert[] = "INSERT INTO addrwatch VALUES(?, ?, ?, ?, ?, ?);";

void output_sqlite_init()
{
#if HAVE_LIBSQLITE3
	int rc;

	if(!cfg.sqlite_file)
		return;

	rc = sqlite3_open(cfg.sqlite_file, &cfg.sqlite_conn);
	if (rc)
		log_msg(LOG_ERR, "Unable to open sqlite3 database file %s",
			cfg.sqlite_file);

	rc = sqlite3_exec(cfg.sqlite_conn, sql_create, 0, 0, 0);
	if (rc)
		log_msg(LOG_ERR, "Error creating table `addrwatch` in sqlite3 database");

	rc = sqlite3_prepare_v2(cfg.sqlite_conn, sql_insert, sizeof(sql_insert), 
		&cfg.sqlite_stmt, NULL);
	if (rc)
		log_msg(LOG_ERR, "Error preparing ipv6 address insert statement");

	sqlite3_busy_timeout(cfg.sqlite_conn, 100);
	log_msg(LOG_DEBUG, "Saving results to %s sqlite database", cfg.sqlite_file);
#endif
}

void output_sqlite_reload()
{
	output_sqlite_close();
	output_sqlite_init();
}

void output_sqlite_save(struct pkt *p, char *mac_str, char *ip_str)
{
#if HAVE_LIBSQLITE3
	int rc;

	if (!cfg.sqlite_conn)
		return;

	rc = sqlite3_bind_int64(cfg.sqlite_stmt, 1, p->pcap_header->ts.tv_sec);
	rc += sqlite3_bind_text(cfg.sqlite_stmt, 2, p->ifc->name, -1, NULL);
	rc += sqlite3_bind_int(cfg.sqlite_stmt, 3, p->vlan_tag);
	rc += sqlite3_bind_text(cfg.sqlite_stmt, 4, mac_str, -1, NULL);
	rc += sqlite3_bind_text(cfg.sqlite_stmt, 5, ip_str, -1, NULL);
	rc += sqlite3_bind_int(cfg.sqlite_stmt, 6, p->origin);
	if (rc)
		log_msg(LOG_ERR, "Unable to bind values to sql statement");

	rc = sqlite3_step(cfg.sqlite_stmt);
	switch(rc) {
	case SQLITE_DONE:
		break;
	case SQLITE_BUSY:
		log_msg(LOG_WARNING, "Unable to execute sqlite prepared statement, database is locked (%ld, %s, %s, %s)", p->pcap_header->ts.tv_sec, p->ifc->name, mac_str, ip_str);
		break;
	default:
		log_msg(LOG_ERR, "Error executing sqlite prepared statement (%d)", rc);
		break;
	}

	rc = sqlite3_reset(cfg.sqlite_stmt);
	if (rc && rc != SQLITE_BUSY)
		log_msg(LOG_ERR, "Error reseting sqlite prepared statement (%d)", rc);
#endif
}

void output_sqlite_close()
{
#if HAVE_LIBSQLITE3
	if (cfg.sqlite_conn) {
		sqlite3_finalize(cfg.sqlite_stmt);
		sqlite3_close(cfg.sqlite_conn);
	}
#endif
}

