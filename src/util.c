#include "addrwatch.h"
#include "util.h"

#include <stdlib.h>
#include <stdarg.h>

#include <syslog.h>

const char *log_level[] = {
	"EMERG",
	"ALERT",
	"CRIT",
	"ERR",
	"WARNING",
	"NOTICE",
	"INFO",
	"DEBUG",
};

void log_open()
{
	int flags = 0;

	openlog(PACKAGE_NAME, flags, LOG_DAEMON);
}

void log_msg(int priority, const char *format, ...)
{
	va_list     pvar;
	char	buffer[BUFSIZ];

	//LOG_ERR
	//LOG_WARNING
	//LOG_NOTICE
	//LOG_INFO
	//LOG_DEBUG

	if (priority < LOG_CRIT || priority > LOG_DEBUG)
		return;

	if (priority == LOG_DEBUG && !cfg.verbose_flag)
		return;

	va_start (pvar, format);
	vsnprintf(buffer, sizeof(buffer), format, pvar);
	va_end (pvar);

	syslog(priority, "%s: %s", log_level[priority], buffer);

	if (priority != LOG_INFO && !cfg.quiet)
		fprintf(stderr, "%s: %s: %s\n", PACKAGE_NAME, log_level[priority], buffer);

	if (priority == LOG_ERR) {
		log_close();
		exit(EXIT_FAILURE);
	}
}

void log_close()
{
	closelog();
}
