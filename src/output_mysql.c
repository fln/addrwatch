#include "output_mysql.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char mysql_create_template[] = "\
CREATE TABLE IF NOT EXISTS `%s` (\
	`tstamp` timestamp NOT NULL,\
	`hostname` varchar(256) NOT NULL,\
	`interface` varchar(16) NOT NULL,\
	`vlan_tag` int(11) NOT NULL,\
	`mac_address` varchar(17) NOT NULL,\
	`ip_address` varchar(42) NOT NULL,\
	`origin` varchar(8) NOT NULL,\
	KEY `interface` (`interface`),\
	KEY `vlan_tag` (`vlan_tag`),\
	KEY `interface_vlan_tag` (`interface`,`vlan_tag`)\
)";

static const char mysql_insert_template[] = "\
INSERT INTO `%s`(\
	`tstamp`,\
	`hostname`, \
	`interface`,\
	`vlan_tag`,\
	`mac_address`,\
	`ip_address`,\
	`origin`\
) VALUES(FROM_UNIXTIME(?), ?, ?, ?, ?, ?, ?)";

void output_mysql_init()
{
#if HAVE_LIBMYSQLCLIENT
	int rc;
	char    create_query[sizeof(mysql_create_template) +64];
	char    insert_query[sizeof(mysql_insert_template) +64];

	if (!cfg.mysql_flag)
		return;

	snprintf(create_query, sizeof(create_query), mysql_create_template, cfg.mysql_table);
	snprintf(insert_query, sizeof(insert_query), mysql_insert_template, cfg.mysql_table);

	rc = mysql_library_init(0, NULL, NULL);
	if (rc)
		log_msg(LOG_ERR, "Error initializing MySQL library (%d)", rc);

	cfg.mysql_conn = mysql_init(cfg.mysql_conn);
	if (!cfg.mysql_conn)
		log_msg(LOG_ERR, "Error allocating MySQL object");
	
	if (cfg.mysql_config) {
		if (mysql_options(cfg.mysql_conn, MYSQL_READ_DEFAULT_FILE, cfg.mysql_config)) {
			log_msg(LOG_ERR, "Failed to read config file %s: %s",
					cfg.mysql_config, mysql_error(cfg.mysql_conn));
		}
	}
	
	mysql_options(cfg.mysql_conn, MYSQL_READ_DEFAULT_GROUP, PACKAGE);
	if (!mysql_real_connect(cfg.mysql_conn, NULL, NULL, NULL, cfg.mysql_db, 0, NULL, 0))
		log_msg(LOG_ERR, "Failed to connect to database: Error: %s", 
	    			mysql_error(cfg.mysql_conn));

	log_msg(LOG_DEBUG, "Using MySQL create query: %s",
	                create_query);
	if(mysql_query(cfg.mysql_conn, create_query))
		log_msg(LOG_ERR, "Error creating table `addrwatch` in MySQL database: %s",
				mysql_error(cfg.mysql_conn));

	cfg.mysql_stmt = mysql_stmt_init(cfg.mysql_conn);
	if (!cfg.mysql_stmt)
		log_msg(LOG_ERR, "Error allocating MySQL statement object");
	
	log_msg(LOG_DEBUG, "Using MySQL insert query: %s [%d]",
	                insert_query, sizeof(insert_query));
	rc = mysql_stmt_prepare(cfg.mysql_stmt, insert_query, strnlen(insert_query, sizeof(insert_query)));
	if (rc)
		log_msg(LOG_ERR, "Error preparing MySQL statement object: %s",
				mysql_stmt_error(cfg.mysql_stmt));
	
	bzero(cfg.mysql_bind, sizeof(cfg.mysql_bind));

	cfg.mysql_bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	cfg.mysql_bind[0].buffer = &cfg.mysql_vars.timestamp;
	cfg.mysql_bind[0].is_null = 0;
	cfg.mysql_bind[0].length = 0;

	cfg.mysql_bind[1].buffer_type = MYSQL_TYPE_VAR_STRING;
	cfg.mysql_bind[1].buffer = cfg.mysql_vars.hostname;
	cfg.mysql_bind[1].is_null = 0;
	cfg.mysql_bind[1].length = &cfg.mysql_vars.hostname_len;

	cfg.mysql_bind[2].buffer_type = MYSQL_TYPE_VAR_STRING;
	cfg.mysql_bind[2].buffer = cfg.mysql_vars.iface;
	cfg.mysql_bind[2].is_null = 0;
	cfg.mysql_bind[2].length = &cfg.mysql_vars.iface_len;

	cfg.mysql_bind[3].buffer_type = MYSQL_TYPE_LONG;
	cfg.mysql_bind[3].buffer = &cfg.mysql_vars.vlan;
	cfg.mysql_bind[3].is_null = 0;
	cfg.mysql_bind[3].length = 0;

	//cfg.mysql_vars.mac_len = ETHER_ADDR_LEN;
	//cfg.mysql_bind[3].buffer_type = MYSQL_TYPE_STRING;
	cfg.mysql_bind[4].buffer_type = MYSQL_TYPE_VAR_STRING;
	cfg.mysql_bind[4].buffer = cfg.mysql_vars.mac;
	cfg.mysql_bind[4].is_null = 0;
	cfg.mysql_bind[4].length = &cfg.mysql_vars.mac_len;

	cfg.mysql_bind[5].buffer_type = MYSQL_TYPE_VAR_STRING;
	cfg.mysql_bind[5].buffer = cfg.mysql_vars.ip;
	cfg.mysql_bind[5].is_null = 0;
	cfg.mysql_bind[5].length = &cfg.mysql_vars.ip_len;

	cfg.mysql_bind[6].buffer_type = MYSQL_TYPE_VAR_STRING;
	cfg.mysql_bind[6].buffer = cfg.mysql_vars.origin;
	cfg.mysql_bind[6].is_null = 0;
	cfg.mysql_bind[6].length = &cfg.mysql_vars.origin_len;

	if (mysql_stmt_bind_param(cfg.mysql_stmt, cfg.mysql_bind))
		log_msg(LOG_ERR, "Error binding MySQL statement object: %s",
				mysql_stmt_error(cfg.mysql_stmt));
#endif
}

void output_mysql_reload()
{
	output_mysql_close();
	output_mysql_init();
}


void output_mysql_save(struct pkt *p, char *mac_str, char *ip_str)
{
#if HAVE_LIBMYSQLCLIENT
	if (!cfg.mysql_conn)
		return;
	
	cfg.mysql_vars.timestamp = p->pcap_header->ts.tv_sec;

	strncpy(cfg.mysql_vars.hostname, cfg.hostname, sizeof(cfg.mysql_vars.hostname));
	cfg.mysql_vars.hostname_len = strnlen(cfg.mysql_vars.hostname, sizeof(cfg.mysql_vars.hostname));

	strncpy(cfg.mysql_vars.iface, p->ifc->name, sizeof(cfg.mysql_vars.iface));
	cfg.mysql_vars.iface_len = strnlen(cfg.mysql_vars.iface, sizeof(cfg.mysql_vars.iface));

	cfg.mysql_vars.vlan = p->vlan_tag;

	//memcpy(cfg.mysql_vars.mac, p->l2_addr, ETHER_ADDR_LEN);
	strcpy(cfg.mysql_vars.mac, mac_str);
	cfg.mysql_vars.mac_len = strlen(mac_str);

	strcpy(cfg.mysql_vars.ip, ip_str);
	cfg.mysql_vars.ip_len = strlen(ip_str);

	strcpy(cfg.mysql_vars.origin, pkt_origin_str[p->origin]);
	cfg.mysql_vars.origin_len = strlen(pkt_origin_str[p->origin]);

	if (mysql_stmt_execute(cfg.mysql_stmt))
		log_msg(LOG_WARNING, "Error inserting data to MySQL database: %s",
				mysql_stmt_error(cfg.mysql_stmt));

#endif
}

void output_mysql_close()
{
#if HAVE_LIBMYSQLCLIENT
	if (cfg.mysql_stmt)
		mysql_stmt_close(cfg.mysql_stmt);
	if (cfg.mysql_conn) {
		mysql_close(cfg.mysql_conn);
		cfg.mysql_conn = NULL;
	}

	mysql_library_end();
#endif
}

