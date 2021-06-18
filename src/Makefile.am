AM_CFLAGS = -Wall -Wextra -Wno-unused-parameter
EXTRA_PROGRAMS = addrwatch_mysql
bin_PROGRAMS = addrwatch addrwatch_stdout addrwatch_syslog $(optional_modules)

noinst_HEADERS = shm.h common.h

addrwatch_SOURCES = addrwatch.c addrwatch.h util.c util.h parse.c parse.h check.c check.h process.c process.h base64.c base64.h storage.c storage.h mcache.c mcache.h output_flatfile.c output_flatfile.h output_sqlite.c output_sqlite.h output_shm.c output_shm.h
addrwatch_stdout_SOURCES = addrwatch_stdout.c shm_client.c shm_client.h
addrwatch_syslog_SOURCES = addrwatch_syslog.c shm_client.c shm_client.h
addrwatch_mysql_SOURCES = addrwatch_mysql.c shm_client.c shm_client.h util.c util.h

addrwatch_LDADD = @LIBEVENT_LIBS@ -lpcap
addrwatch_mysql_LDADD = -lmysqlclient

