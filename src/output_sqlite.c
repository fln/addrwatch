#include "output_sqlite.h"
#include "util.h"

#include <stdlib.h>

static const char sqlite_create_template[] = "\
CREATE TABLE IF NOT EXISTS %s(\
timestamp UNSIGNED BIG INT, \
interface varchar(16), \
vlan_tag UNSIGNED INT, \
mac_address varchar(17), \
ip_address varchar(42), \
origin TINYINT\
);";

static const char sqlite_create_template_compact[] = "\
CREATE TABLE IF NOT EXISTS %s(\
timestamp_first UNSIGNED BIG INT, \
timestamp UNSIGNED BIG INT, \
interface varchar(16), \
vlan_tag UNSIGNED INT, \
mac_address varchar(17), \
ip_address varchar(42), \
origin TINYINT,\
count UNSIGNED BIG INT \
);";

static const char sqlite_insert_template[] = "INSERT INTO %s VALUES(?, ?, ?, ?, ?, ?);";
static const char sqlite_insert_template_compact[] = "INSERT INTO %s VALUES(?, ?, ?, ?, ?, ?, ?, 1);";
static const char sqlite_update_template_compact[] = "UPDATE %s SET timestamp=?, count=count+1 WHERE interface=? AND vlan_tag=? AND mac_address=? AND ip_address=? AND origin=?;";

void output_sqlite_init()
{
#if HAVE_LIBSQLITE3
	int rc;
	char create_query[sizeof(sqlite_create_template) + 64];
	char insert_query[sizeof(sqlite_insert_template) + 64];
	char create_query_compact[sizeof(sqlite_create_template_compact) + 64];
	char insert_query_compact[sizeof(sqlite_insert_template_compact) + 64];
	char update_query_compact[sizeof(sqlite_update_template_compact) + 64];

	if (!cfg.sqlite_file) {
		return;
	}

	snprintf(create_query, sizeof(create_query), sqlite_create_template, cfg.sqlite_table);
	snprintf(insert_query, sizeof(insert_query), sqlite_insert_template, cfg.sqlite_table);
	snprintf(update_query_compact, sizeof(update_query_compact), sqlite_update_template_compact, cfg.sqlite_table);
	snprintf(create_query_compact, sizeof(create_query_compact), sqlite_create_template_compact, cfg.sqlite_table);
	snprintf(insert_query_compact, sizeof(insert_query_compact), sqlite_insert_template_compact, cfg.sqlite_table);

	rc = sqlite3_open(cfg.sqlite_file, &cfg.sqlite_conn);
	if (rc) {
		log_msg(LOG_ERR, "Unable to open sqlite3 database file %s", cfg.sqlite_file);
	}


	if (cfg.sqlite_compact) {
		log_msg(LOG_DEBUG, "Using sqlite create query: %s", create_query_compact);
		rc = sqlite3_exec(cfg.sqlite_conn, create_query_compact, 0, 0, 0);
		if (rc) {
			log_msg(LOG_ERR, "Error creating table `addrwatch` in sqlite3 database");
		}

		log_msg(LOG_DEBUG, "Using sqlite insert query: %s", insert_query_compact);
		rc = sqlite3_prepare_v2(cfg.sqlite_conn, insert_query_compact,
			sizeof(insert_query_compact), &cfg.sqlite_stmt2, NULL);
		if (rc) {
			log_msg(LOG_ERR, "Error preparing sqlite insert statement");
		}

		log_msg(LOG_DEBUG, "Using sqlite update query: %s", update_query_compact);
		rc = sqlite3_prepare_v2(cfg.sqlite_conn, update_query_compact,
			sizeof(update_query_compact), &cfg.sqlite_stmt, NULL);
		if (rc) {
			log_msg(LOG_ERR, "Error preparing sqlite update statement");
		}
	} else {
		log_msg(LOG_DEBUG, "Using sqlite create query: %s", create_query);
		rc = sqlite3_exec(cfg.sqlite_conn, create_query, 0, 0, 0);
		if (rc) {
			log_msg(LOG_ERR, "Error creating table `addrwatch` in sqlite3 database");
		}

		log_msg(LOG_DEBUG, "Using sqlite insert query: %s", insert_query);
		rc = sqlite3_prepare_v2(cfg.sqlite_conn, insert_query,
			sizeof(insert_query), &cfg.sqlite_stmt, NULL);
		if (rc) {
			log_msg(LOG_ERR, "Error preparing sqlite insert statement");
		}
	}

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

	if (!cfg.sqlite_conn) {
		return;
	}

	rc = sqlite3_bind_int64(cfg.sqlite_stmt, 1, p->pcap_header->ts.tv_sec);
	rc += sqlite3_bind_text(cfg.sqlite_stmt, 2, p->ifc->name, -1, NULL);
	rc += sqlite3_bind_int(cfg.sqlite_stmt, 3, p->vlan_tag);
	rc += sqlite3_bind_text(cfg.sqlite_stmt, 4, mac_str, -1, NULL);
	rc += sqlite3_bind_text(cfg.sqlite_stmt, 5, ip_str, -1, NULL);
	rc += sqlite3_bind_int(cfg.sqlite_stmt, 6, p->origin);
	if (rc) {
		log_msg(LOG_ERR, "Unable to bind values to sql statement");
	}

	rc = sqlite3_step(cfg.sqlite_stmt);
	switch (rc) {
	case SQLITE_DONE:
		break;
	case SQLITE_BUSY:
		log_msg(LOG_WARNING, "Unable to execute sqlite prepared statement, database is locked (%ld, %s, %s, %s)",
			p->pcap_header->ts.tv_sec, p->ifc->name, mac_str, ip_str);
		break;
	default:
		log_msg(LOG_ERR, "Error executing sqlite prepared statement (%d)", rc);
		break;
	}

	rc = sqlite3_reset(cfg.sqlite_stmt);
	if (rc && rc != SQLITE_BUSY) {
		log_msg(LOG_ERR, "Error reseting sqlite prepared statement (%d)", rc);
	}

	if (cfg.sqlite_compact) {
		// If no rows have bee affected by the update statement,
		// insert a new row
		if (sqlite3_changes(cfg.sqlite_conn) == 0) {
			rc = sqlite3_bind_int64(cfg.sqlite_stmt2, 1, p->pcap_header->ts.tv_sec);
			rc += sqlite3_bind_int64(cfg.sqlite_stmt2, 2, p->pcap_header->ts.tv_sec);
			rc += sqlite3_bind_text(cfg.sqlite_stmt2, 3, p->ifc->name, -1, NULL);
			rc += sqlite3_bind_int(cfg.sqlite_stmt2, 4, p->vlan_tag);
			rc += sqlite3_bind_text(cfg.sqlite_stmt2, 5, mac_str, -1, NULL);
			rc += sqlite3_bind_text(cfg.sqlite_stmt2, 6, ip_str, -1, NULL);
			rc += sqlite3_bind_int(cfg.sqlite_stmt2, 7, p->origin);
			if (rc) {
				log_msg(LOG_ERR, "Unable to bind values to sql statement");
			}

			rc = sqlite3_step(cfg.sqlite_stmt2);
			switch (rc) {
			case SQLITE_DONE:
				break;
			case SQLITE_BUSY:
				log_msg(LOG_WARNING, "Unable to execute sqlite prepared statement, database is locked (%ld, %s, %s, %s)",
					p->pcap_header->ts.tv_sec, p->ifc->name, mac_str, ip_str);
				break;
			default:
				log_msg(LOG_ERR, "Error executing sqlite prepared statement (%d)", rc);
				break;
			}

			rc = sqlite3_reset(cfg.sqlite_stmt2);
			if (rc && rc != SQLITE_BUSY) {
				log_msg(LOG_ERR, "Error reseting sqlite prepared statement (%d)", rc);
			}
		}
	}
#endif
}

void output_sqlite_close()
{
#if HAVE_LIBSQLITE3
	if (cfg.sqlite_conn) {
		sqlite3_finalize(cfg.sqlite_stmt);
		if (cfg.sqlite_compact) {
			sqlite3_finalize(cfg.sqlite_stmt2);
		}
		sqlite3_close(cfg.sqlite_conn);
	}
#endif
}
