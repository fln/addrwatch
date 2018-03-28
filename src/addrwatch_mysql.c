#if HAVE_CONFIG_H
	#include <config.h>
#endif

#include "shm.h"
#include "shm_client.h"
#include "util.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <mysql/mysql.h>
#include <argp.h>

#define HOSTNAME_LEN 255
#define STRINGIFY(s) #s
#define STR(s) STRINGIFY(s)

const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;


struct ctx_s {
	int         foreground;
	char       *config_file;
	char       *prefix;
	MYSQL      *dbh;
	MYSQL_STMT *stmt;
	MYSQL_BIND  bind[7];
	struct {
		long long int timestamp;
		char          hostname[HOSTNAME_LEN];
		unsigned long hostname_len;
		char          iface[IFNAMSIZ];
		unsigned long iface_len;
		int           vlan_tag;
		char          mac[ETHER_ADDR_LEN];
		unsigned long mac_len;
		char          ip[16];
		unsigned long ip_len;
		int           origin;
	} bind_data;
};


static const char sql_create_log_template[] = "\
CREATE TABLE IF NOT EXISTS `%slog` (\
	`tstamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,\
	`hostname` varchar(" STR(HOSTNAME_LEN) ") NOT NULL DEFAULT \"localhost\",\
	`interface` varchar(16) NOT NULL,\
	`vlan_tag` int(11) NOT NULL DEFAULT 0,\
	`mac_address` BINARY(6) NOT NULL,\
	`ip_address` VARBINARY(16) NOT NULL,\
	`origin_id` INT(11) NOT NULL,\
\
	KEY `interface` (`interface`),\
	KEY `vlan_tag` (`vlan_tag`),\
	KEY `mac_address` (`mac_address`),\
	KEY `interface_vlan_tag` (`interface`,`vlan_tag`)\
)";

static const char sql_create_origin_template[] = "\
CREATE TABLE IF NOT EXISTS `%sorigin` (\
	`id` INT(11) NOT NULL,\
	`name` VARCHAR(16) NOT NULL,\
	`description` VARCHAR(255) NOT NULL,\
\
	PRIMARY KEY (`id`)\
)";

static const char sql_create_plaintext_template[] = "\
CREATE OR REPLACE VIEW `%slog_plaintext` AS \
SELECT \
	l.`tstamp`, \
	l.`hostname`, \
	l.`interface`, \
	l.`vlan_tag`, \
	HEX(l.`mac_address`) AS `mac_address`, \
	HEX(l.`ip_address`) AS `ip_address`, \
	o.`name` AS `origin` \
FROM `%slog` AS l \
INNER JOIN `%sorigin` as o \
	ON o.`id` = l.`origin_id`";

static const char sql_insert_log_template[] = "\
INSERT INTO `%slog` (\
	`tstamp`, `hostname`, `interface`, `vlan_tag`, `mac_address`, `ip_address`, `origin_id`\
) \
VALUES(\
	FROM_UNIXTIME(?), ?, ?, ?, ?, ?, ?\
)";

static const char sql_insert_origin_template[] = "\
INSERT INTO `%sorigin` (\
	`id`, `name`, `description`\
) \
VALUES(\
	%u, '%s', '%s'\
)";

static inline void *malloc_c(size_t size)
{
	void *data = malloc(size);
	if (!data)
		log_msg(LOG_ERR, "Error allocating memory");
	return data;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct ctx_s *ctx;
	
	ctx = (struct ctx_s *)state->input;
	switch(key) {
		case 'f':
			ctx->foreground = 1;
			break;
		case 'p':
			ctx->prefix = arg;
			break;
		case 'c':
			ctx->config_file = arg;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
			break;
	}
	return 0;
}

static void mysql_simple_query(MYSQL *dbh, const char *format, ...)
{
	va_list pvar;
	char    buf[BUFSIZ];

	va_start(pvar, format);
	vsnprintf(buf, sizeof(buf), format, pvar);
	va_end (pvar);

	if (mysql_query(dbh, buf))
		log_msg(LOG_ERR, "Error executing query: %s", mysql_error(dbh));
}


static void mysql_init_tables(MYSQL *dbh, char *prefix)
{
	int i;

	mysql_simple_query(dbh, sql_create_log_template, prefix);
	mysql_simple_query(dbh, sql_create_origin_template, prefix);
	
	if (!mysql_warning_count(dbh)) {	
		for (i = 0; pkt_origin_str[i]; i++) {
			mysql_simple_query(dbh, sql_insert_origin_template,
						prefix,
						i,
						pkt_origin_str[i],
						pkt_origin_desc[i]);
		}
	}

	mysql_simple_query(dbh, sql_create_plaintext_template, prefix, prefix, prefix);
}

void stmt_init(struct ctx_s *data)
{
	int   rc;
	int   len;
	char *buf;

	data->stmt = mysql_stmt_init(data->dbh);
	if (!data->stmt)
		log_msg(LOG_ERR, "Error allocating MySQL statement object");

	len = sizeof(sql_insert_log_template) + strlen(data->prefix); 
	buf = (char *)malloc_c(len);
	snprintf(buf, len, sql_insert_log_template, data->prefix);
	
	rc = mysql_stmt_prepare(data->stmt, buf, strnlen(buf, len));
	if (rc)
		log_msg(LOG_ERR, "Error preparing MySQL statement object: %s",
					mysql_stmt_error(data->stmt));
	free(buf);

	if (mysql_stmt_bind_param(data->stmt, data->bind))
		log_msg(LOG_ERR, "Error binding MySQL statement object: %s",
				mysql_stmt_error(data->stmt));
}

int db_connect(struct ctx_s *data)
{
	int        rc;
	MYSQL_RES *res;
	my_bool    t = 1;
	
	data->dbh = mysql_init(data->dbh);
	if (!data->dbh)
		log_msg(LOG_ERR, "Error allocating MySQL object");
	
	if (data->config_file) {
		rc = mysql_options(data->dbh, MYSQL_READ_DEFAULT_FILE, data->config_file);
		if (rc)
			log_msg(LOG_ERR, "Failed to read config file %s: %s",
				data->config_file, mysql_error(data->dbh));
	}

	rc = mysql_options(data->dbh, MYSQL_READ_DEFAULT_GROUP, PACKAGE);
	if (rc)
		log_msg(LOG_ERR, "Failed to read [" PACKAGE "] section from my.cnf: %s", mysql_error(data->dbh));

	if (!mysql_real_connect(data->dbh, NULL, NULL, NULL, NULL, 0, NULL, 0)) {
		log_msg(LOG_WARNING, "Failed to connect to database: %s", mysql_error(data->dbh));
		return -1;
	}

	mysql_init_tables(data->dbh, data->prefix);
	stmt_init(data);

	return 0;
}

void db_disconnect(struct ctx_s *data)
{
	if (data->stmt) {
		mysql_stmt_close(data->stmt);
		data->stmt = NULL;
	}
	mysql_close(data->dbh);
	data->dbh = NULL;
}

static inline void db_reconnect(struct ctx_s *data) {
	while (1) {
		if (data->dbh)
			db_disconnect(data);
		if (!db_connect(data))
			break;
		sleep(1);
	}
}

void bind_init(struct ctx_s *data)
{
	memset(data->bind, 0, sizeof(data->bind));

	data->bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	data->bind[0].buffer = &data->bind_data.timestamp;

	data->bind[1].buffer_type = MYSQL_TYPE_STRING;
	data->bind[1].buffer = &data->bind_data.hostname;
	data->bind[1].length = &data->bind_data.hostname_len;

	data->bind[2].buffer_type = MYSQL_TYPE_STRING;
	data->bind[2].buffer = &data->bind_data.iface;
	data->bind[2].length = &data->bind_data.iface_len;

	data->bind[3].buffer_type = MYSQL_TYPE_LONG;
	data->bind[3].buffer = &data->bind_data.vlan_tag;

	data->bind[4].buffer_type = MYSQL_TYPE_BLOB;
	data->bind[4].buffer = &data->bind_data.mac;
	data->bind[4].length = &data->bind_data.mac_len;

	data->bind[5].buffer_type = MYSQL_TYPE_BLOB;
	data->bind[5].buffer = &data->bind_data.ip;
	data->bind[5].length = &data->bind_data.ip_len;

	data->bind[6].buffer_type = MYSQL_TYPE_LONG;
	data->bind[6].buffer = &data->bind_data.origin;
}

void process_entry(struct shm_log_entry *e, void *arg)
{
	struct ctx_s *data;
	int  rc;
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];

	data = (struct ctx_s *)arg;

	data->bind_data.timestamp = e->timestamp;
	memcpy(data->bind_data.iface, e->interface, sizeof(data->bind_data.iface));
	data->bind_data.iface_len = strnlen(data->bind_data.iface, sizeof(data->bind_data.iface));
	data->bind_data.vlan_tag = e->vlan_tag;
	memcpy(data->bind_data.mac, e->mac_address, sizeof(e->mac_address));
	data->bind_data.mac_len = sizeof(data->bind_data.mac);
	memcpy(data->bind_data.ip, e->ip_address, e->ip_len);
	data->bind_data.ip_len = e->ip_len;
	data->bind_data.origin = e->origin;

	while (1) {
		if (!mysql_stmt_execute(data->stmt))
			return;
		log_msg(LOG_WARNING, "Error inserting data to MySQL database: %s\n",
					mysql_stmt_error(data->stmt));

		db_reconnect(data);
	}
}

static void get_hostname(char *hostname, unsigned long *len)
{
	if (gethostname(hostname, *len)) 
		log_msg(LOG_ERR, "Error gethostbyname failed");
	
	*len = strnlen(hostname, *len);
}

int main(int argc, char *argv[])
{
	int rc;
	struct ctx_s ctx;
	struct argp_option options[] = {
		{"foreground",    'f', 0,      0, "Start as a foreground process" },
		{"prefix",        'p', "STR",  0, "Prepend STR_ prefix to table names" },
		{"config",        'c', "FILE",  0, "Use FILE for MySQL config" },
		{ 0 }
	};
	char doc[] = "FIXME\vFIXME";
	struct argp argp = { options, parse_opt, NULL, doc };

	memset(&ctx, 0, sizeof(ctx));
	ctx.prefix = "";

	log_open("addrwatch_mysql");

	argp_parse(&argp, argc, argv, 0, NULL, &ctx);
	
	ctx.bind_data.hostname_len = sizeof(ctx.bind_data.hostname);
	get_hostname(ctx.bind_data.hostname, &ctx.bind_data.hostname_len);

	rc = mysql_library_init(0, NULL, NULL);
	if (rc)
		log_msg(LOG_ERR, "Error initializing MySQL library (%d)", rc);

	bind_init(&ctx);
	db_reconnect(&ctx);

	if (!ctx.foreground) {
		log_syslog_only(1);
		if (daemon(0, 0))
			log_msg(LOG_ERR, "Failed to become daemon: %s", strerror(errno));
			
	}

	main_loop(process_entry, &ctx);

	mysql_library_end();

	log_close();
}
