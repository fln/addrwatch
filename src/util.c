#include "addrwatch.h"
#include "util.h"

#include <stdlib.h>
#include <stdarg.h>

#include <syslog.h>

struct log_ctx_s {
	int syslog_only;
	int max_priority;
	char *ident;
};

static struct log_ctx_s _ctx;

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

void log_open(char *ident)
{
	int flags = 0;

	memset(&_ctx, 0, sizeof(_ctx));
	_ctx.ident = ident;
	_ctx.max_priority = LOG_NOTICE;

	openlog(ident, flags, LOG_DAEMON);
}

void log_max_priority(int priority)
{
	_ctx.max_priority = priority;
}

void log_syslog_only(int flag)
{
	_ctx.syslog_only = flag;
}

void log_msg(int priority, const char *format, ...)
{
	va_list pvar;
	char buffer[BUFSIZ];

	//LOG_ERR
	//LOG_WARNING
	//LOG_NOTICE
	//LOG_INFO
	//LOG_DEBUG

	if (priority < LOG_EMERG || priority > LOG_DEBUG)
		return;

	if (priority > _ctx.max_priority)
		return;

	va_start(pvar, format);
	vsnprintf(buffer, sizeof(buffer), format, pvar);
	va_end(pvar);

	syslog(priority, "%s: %s", log_level[priority], buffer);

	if (!_ctx.syslog_only)
		fprintf(stderr, "%s: %s: %s\n", _ctx.ident, log_level[priority], buffer);

	if (priority <= LOG_ERR) {
		log_close();
		exit(EXIT_FAILURE);
	}
}

void log_close()
{
	closelog();
}
