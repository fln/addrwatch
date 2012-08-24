bin_PROGRAMS = addrwatch
addrwatch_SOURCES = addrwatch.c util.c parse.c check.c process.c base64.c storage.c mcache.c output_flatfile.c output_sqlite.c output_mysql.c
noinst_HEADERS = addrwatch.h util.h parse.h check.h process.h base64.h storage.h mcache.h output_flatfile.h output_sqlite.h output_mysql.h

AM_CFLAGS = @LIBEVENT_CFLAGS@
LDADD = @LIBEVENT_LIBS@

