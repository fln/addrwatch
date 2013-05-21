#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <argp.h>

#include <sys/stat.h>

#include "addrwatch.h"
#include "parse.h"
#include "check.h"
#include "process.h"
#include "util.h"
#include "mcache.h"
#include "storage.h"
#include "output_flatfile.h"
#include "output_sqlite.h"
#include "output_mysql.h"

const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
static char args_doc[] = "[INTERFACE1 INTERFACE2 ...]";
static char doc[] =
"Keep track of ethernet/ip address pairings for IPv4 and IPv6.\
\vIf no interfaces given, then first non loopback interface is used. IP \
address blacklisting opetion '-b' can be used multiple times.";

static struct argp_option options[] = {
	{0, 0, 0, 0, "Options for data output:" },
	{"syslog",    'l', 0,      0, "Output data to syslog (daemon facility)." },
	{"output",    'o', "FILE", 0, "Output data to plain text FILE." },
	{"quiet",     'q', 0,      0, "Suppress any output to stdout and stderr." },
	{"verbose",   'v', 0,      0, "Enable debug messages." },
#if HAVE_LIBMYSQLCLIENT
	{"mysql",     'm', "DB",      OPTION_ARG_OPTIONAL, "Output data to MySQL database DB (default is DB from ~/.my.cnf)." },
	{"mysql-table", 1, "TBL",  0, "Use MySQL table TBL (default: " PACKAGE ")." },
	{"mysql-config", 'c',"FILE",  0, "Use FILE for MySQL client configuration." },
#endif
#if HAVE_LIBSQLITE3
	{"sqlite3",   's', "FILE", 0, "Output data to sqlite3 database FILE." },
	{"sqlite3-table", 2, "TBL",  0, "Use sqlite table TBL (default: " PACKAGE")." },
#endif
	{0, 0, 0, 0, "Options for data filtering:" },
	{"ipv4-only", '4', 0,      0, "Capture only IPv4 packets." },
	{"ipv6-only", '6', 0,      0, "Capture only IPv6 packets." },
	{"blacklist", 'b', "IP",   0, "Ignore pairings with specified IP." },
	{"ratelimit", 'r', "NUM",  0, "Ratelimit duplicate ethernet/ip pairings to 1 every NUM seconds. If NUM = 0, ratelimiting is disabled. If NUM = -1, suppress duplicate entries indefinitely. Default is 0." },
	{"hashsize",  'H', "NUM",  0, "Size of ratelimit hash table. Default is 1 (no hash table)." },
	{0, 0, 0, 0, "Misc options:" },
	{"daemon",    'd', 0,      0, "Start as a daemon." },
	{"pid",       'p', "FILE", 0, "Write process id to FILE." },
	{"no-promisc",'P', 0,      0, "Disable promisc mode on network interfaces." },
	{"user",      'u', "USER", 0, "Suid to USER after opening network interfaces." },
	{"hostname",  'h', "HOSTNAME", 0, "Use HOSTNAME instead of real machine hostname." },
	{ 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static struct argp argp = { options, parse_opt, args_doc, doc };

struct addrwatch_config  cfg;

static const char ip4_filter[] = "arp";
static const char ip6_filter[] = "ip6 and not tcp and not udp and not esp and not ah";
static const char def_filter[] = "ip6 and not tcp and not udp and not esp and not ah or arp";

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{

	switch(key) {
	case '4':
		cfg.v4_flag = 1;
		cfg.v6_flag = 0;
		break;
	case '6':
		cfg.v6_flag = 1;
		cfg.v4_flag = 0;
		break;
	case 'b':
		blacklist_add(arg);
		break;
	case 'd':
		cfg.daemon_flag = 1;
		cfg.quiet = 1;
		break;
	case 'H':
		cfg.hashsize = atoi(arg);
		break;
	case 'l':
		cfg.syslog_flag = 1;
		break;
	case 'o':
		cfg.data_file = arg;
		break;
	case 'p':
		cfg.pid_file = arg;
		break;
	case 'P':
		cfg.promisc_flag = 0;
		break;
	case 'q':
		cfg.quiet = 1;
		break;
	case 'r':
		cfg.ratelimit = atoi(arg);
		if (cfg.ratelimit < -1)
			cfg.ratelimit = -1;
		break;
#if HAVE_LIBSQLITE3
	case 's':
		cfg.sqlite_file = arg;
		break;
	case 2:
		cfg.sqlite_table = arg;
		break;
#endif
#if HAVE_LIBMYSQLCLIENT
	case 'm':
		cfg.mysql_flag = 1;
		if (arg)
			cfg.mysql_db = arg;
		break;
	case 1:
		cfg.mysql_table = arg;
		break;
	case 'c':
		cfg.mysql_config = arg;
		break;
#endif
	case 'u':
		cfg.uname = arg;
		break;
	case 'h':
		cfg.hostname = strdup(arg);
		cfg.hostname_len = strlen(arg) + 1;
		break;
	case 'v':
		cfg.verbose_flag = 1;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
		break;
	}

	return 0;
}

void drop_root(const char *uname)
{
	struct passwd *pw;

	pw = getpwnam(uname);

	if(!pw)
		log_msg(LOG_ERR, "User %s not found", uname);
	
	if (initgroups(uname, pw->pw_gid) != 0
		|| setgid(pw->pw_gid) != 0
		|| setuid(pw->pw_uid) != 0
		|| setenv("HOME", pw->pw_dir, 1) != 0)
		log_msg(LOG_ERR, "Unable to setuid to %s, uid=%d, gid=%d",
			uname, pw->pw_uid, pw->pw_gid);

	log_msg(LOG_DEBUG, "Changed user to %s, uid = %d, gid = %d",
		uname, pw->pw_uid, pw->pw_gid);
}

void pcap_callback(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
	struct pkt	p;
	int	rc;

	bzero(&p, sizeof(p));

	p.raw_packet = (uint8_t *)packet;

	p.pos = (uint8_t *)packet;
	p.len = header->caplen;

	p.ifc = (struct iface_config *) args;
	p.pcap_header = header;

	rc = parse_packet(&p);

	if (rc < 0)
		return;

	if (p.arp) {
		if (!check_arp(&p))
		process_arp(&p);
	} else if (p.ns) {
		if (!check_ns(&p))
			process_ns(&p);
	} else if (p.na) {
		if (!check_na(&p))
			process_na(&p);
	}

}

#if HAVE_LIBEVENT2
void read_cb(evutil_socket_t fd, short events, void *arg)
#else
void read_cb(int fd, short events, void *arg)
#endif
{
	struct pcap_pkthdr	header;
	const uint8_t	*packet;
	struct iface_config	*ifc;

	ifc = (struct iface_config *) arg;
	packet = pcap_next(ifc->pcap_handle, &header);

	if(packet)
		pcap_callback(arg, &header, packet);
}

void add_iface(char *iface)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char const *filter;
	struct iface_config *ifc;
	int rc;

	if (cfg.v4_flag)
		filter = ip4_filter;
	else if (cfg.v6_flag)
		filter = ip6_filter;
	else
		filter = def_filter;

	ifc = (struct iface_config *) calloc(1, sizeof(struct iface_config));

	ifc->name = iface;

	ifc->pcap_handle = pcap_open_live(iface, SNAP_LEN, cfg.promisc_flag, 1000, errbuf);
	if (ifc->pcap_handle == NULL) {
		log_msg(LOG_WARNING, "Skipping interface %s, %s", iface, errbuf);
		goto error;
	}

	rc = pcap_datalink(ifc->pcap_handle);
	if (rc != DLT_EN10MB) {
		log_msg(LOG_WARNING, "Skipping interface %s, invalid data link layer %s (%s).", 
			iface,
			pcap_datalink_val_to_name(rc),
			pcap_datalink_val_to_description(rc));
		goto error_pcap;
	}

	rc = pcap_compile(ifc->pcap_handle, &ifc->pcap_filter, filter, 0, 0);
	if (rc == -1) {
		log_msg(LOG_WARNING, "Skipping interface %s, %s",
			iface, pcap_geterr(ifc->pcap_handle));
		goto error_pcap;
	}

	rc = pcap_setfilter(ifc->pcap_handle, &ifc->pcap_filter);
	if (rc == -1) {
		log_msg(LOG_WARNING, "Skipping iface %s, %s",
			iface, pcap_geterr(ifc->pcap_handle));
		goto error_filter;
	}

	rc = pcap_fileno(ifc->pcap_handle);

#if HAVE_LIBEVENT2
	ifc->event = event_new(cfg.eb, rc, EV_READ|EV_PERSIST, read_cb, ifc);
	if(!ifc->event)
		log_msg(LOG_ERR, "%s: event_new(...)", __FUNCTION__);

	event_add(ifc->event, NULL);
#else
	event_set(&ifc->event, rc, EV_READ|EV_PERSIST, read_cb, ifc);
	event_add(&ifc->event, NULL);
#endif

	if (cfg.hashsize < 1 || cfg.hashsize > 65536)
		log_msg(LOG_ERR, "%s: hash size (%d) must be >= 1 and <= 65536", __FUNCTION__, cfg.hashsize);

	if (cfg.ratelimit) {
		ifc->cache = calloc(cfg.hashsize, sizeof(*ifc->cache));
		if (!ifc->cache)
			log_msg(LOG_ERR, "%s: unable to allocate memory for hash cache", __FUNCTION__);
	}

	ifc->next = cfg.interfaces;
	cfg.interfaces = ifc;

	log_msg(LOG_DEBUG, "Opened interface %s (%s)",
		iface,
		pcap_datalink_val_to_description(pcap_datalink(ifc->pcap_handle)));

	return;

error_filter:
	pcap_freecode(&ifc->pcap_filter);
error_pcap:
	pcap_close(ifc->pcap_handle);
error:
	free(ifc);
}

struct iface_config *del_iface(struct iface_config *ifc)
{
	struct iface_config	*next;
	int	i;

	next = ifc->next;

#if HAVE_LIBEVENT2
	event_free(ifc->event);
#endif
	pcap_freecode(&ifc->pcap_filter);
	pcap_close(ifc->pcap_handle);

	log_msg(LOG_DEBUG, "Closed interface %s", ifc->name);

	if (ifc->cache) {
		for (i = 0; i < cfg.hashsize; i++)
			if (*(ifc->cache + i))
				cache_prune(*(ifc->cache+i), ifc->cache+i);
		free(ifc->cache);
	}

	free(ifc);
	
	return next;

}

#if HAVE_LIBEVENT2
void reload_cb(evutil_socket_t fd, short events, void *arg)
#else
void reload_cb(int fd, short events, void *arg)
#endif
{
	log_msg(LOG_DEBUG, "Received signal (%d), %s", fd, sys_siglist[fd]);
	log_msg(LOG_DEBUG, "Reopening output files");

	output_flatfile_reload();
	output_sqlite_reload();
	output_mysql_reload();
}

#if HAVE_LIBEVENT2
void stop_cb(evutil_socket_t fd, short events, void *arg)
#else
void stop_cb(int fd, short events, void *arg)
#endif
{
	log_msg(LOG_DEBUG, "Received signal (%d), %s", fd, sys_siglist[fd]);
#if HAVE_LIBEVENT2
	event_base_loopbreak(cfg.eb);
#else
	event_loopbreak();
#endif
}



void libevent_init()
{
#if HAVE_LIBEVENT2
	cfg.eb = event_base_new();

	if (!cfg.eb)
		log_msg(LOG_ERR, "%s: event_base_new() failed", __FUNCTION__);
#else
	event_init();
#endif

#if HAVE_LIBEVENT2
	cfg.sigint_ev = event_new(cfg.eb, SIGINT, EV_SIGNAL|EV_PERSIST, stop_cb, NULL);
	event_add(cfg.sigint_ev, NULL);
#else
	event_set(&cfg.sigint_ev, SIGINT, EV_SIGNAL|EV_PERSIST, stop_cb, NULL);
	event_add(&cfg.sigint_ev, NULL);
#endif

#if HAVE_LIBEVENT2
	cfg.sigterm_ev = event_new(cfg.eb, SIGTERM, EV_SIGNAL|EV_PERSIST, stop_cb, NULL);
	event_add(cfg.sigterm_ev, NULL);
#else
	event_set(&cfg.sigterm_ev, SIGTERM, EV_SIGNAL|EV_PERSIST, stop_cb, NULL);
	event_add(&cfg.sigterm_ev, NULL);
#endif

#if HAVE_LIBEVENT2
	cfg.sighup_ev = event_new(cfg.eb, SIGHUP, EV_SIGNAL|EV_PERSIST, reload_cb, NULL);
	event_add(cfg.sighup_ev, NULL);
#else
	event_set(&cfg.sighup_ev, SIGHUP, EV_SIGNAL|EV_PERSIST, reload_cb, NULL);
	event_add(&cfg.sighup_ev, NULL);
#endif
}

void libevent_close()
{
#if HAVE_LIBEVENT2
	event_free(cfg.sigint_ev);
	event_free(cfg.sigterm_ev);
	event_free(cfg.sighup_ev);

	event_base_free(cfg.eb);
#endif

}

void save_pid()
{
	FILE	*f;

	if (!cfg.pid_file)
		return;

	f = fopen(cfg.pid_file, "w");
	if(!f)
	{
		log_msg(LOG_ERR, "Unable to open pid file %s", cfg.pid_file);
		return;
	}
	fprintf(f, "%d\n", getpid());
	fclose(f);
}

void del_pid()
{
	if (!cfg.pid_file)
		return;

	unlink(cfg.pid_file);
}

void daemonize()
{
	pid_t pid, sid;

	if (cfg.daemon_flag) {
		pid = fork();

		if (pid < 0)
			log_msg(LOG_ERR, "Error forking new process");

		if (pid > 0)
			exit(EXIT_SUCCESS);

		umask(0);
		sid = setsid();
		if (sid < 0)
			log_msg(LOG_ERR, "Error starting new session");
	}
	
	fclose(stdin);
	if (cfg.quiet) {
		fclose(stdout);
		fclose(stderr);
	}
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	struct iface_config *ifc;
	int optind;
	int i;


	bzero(&cfg, sizeof(cfg));

	/* Default configuration */
//	cfg.ratelimit = 0;
	cfg.hashsize = 1;
//	cfg.quiet = 0;
	cfg.promisc_flag = 1;
//	cfg.ratelimit = 0;
//	cfg.sqlite_file = NULL;
//	cfg.uname = NULL;
#if HAVE_LIBSQLITE3
	cfg.sqlite_table = PACKAGE;
#endif
#if HAVE_LIBMYSQLCLIENT
//	cfg.mysql_db = NULL;
	cfg.mysql_table = PACKAGE;
#endif

	argp_parse(&argp, argc, argv, 0, &optind, 0);

	if (!cfg.hostname) {
		cfg.hostname_len = sysconf(_SC_HOST_NAME_MAX);
		cfg.hostname = (char *)calloc(cfg.hostname_len, sizeof(char));
		gethostname(cfg.hostname, cfg.hostname_len);
	}

	daemonize();
	save_pid();

	log_open();
	libevent_init();


	if (cfg.ratelimit > 0)
		log_msg(LOG_DEBUG, "Ratelimiting duplicate entries to 1 per %d seconds", cfg.ratelimit);
	else if (cfg.ratelimit == -1)
		log_msg(LOG_DEBUG, "Duplicate entries supressed indefinitely");
	else
		log_msg(LOG_DEBUG, "Duplicate entries ratelimiting disabled");

	if (cfg.promisc_flag)
		log_msg(LOG_DEBUG, "PROMISC mode enabled");
	else
		log_msg(LOG_DEBUG, "PROMISC mode disabled");

	if (argc > optind) {
		for (i = optind; i < argc; i++)
			add_iface(argv[i]);
	} else {
		dev = pcap_lookupdev(errbuf);
		if (dev != NULL)
			add_iface(dev);
	}

	if (!cfg.interfaces)
		log_msg(LOG_ERR, "No suitable interfaces found!");

	if (cfg.uname)
		drop_root(cfg.uname);

	output_flatfile_init();
	output_sqlite_init();
	output_mysql_init();

	/* main loop */
#if HAVE_LIBEVENT2
	event_base_dispatch(cfg.eb);
#else
	event_dispatch();
#endif

	output_mysql_close();
	output_sqlite_close();
	output_flatfile_close();

	for (ifc = cfg.interfaces; ifc != NULL; ifc = del_iface(ifc));


	libevent_close();
	log_close();

	del_pid();
	blacklist_free();

	free(cfg.hostname);

	return 0;
}
