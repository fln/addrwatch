AC_PREREQ([2.68])
AC_INIT([addrwatch], [0.8], [julius.kriukas@gmail.com])
AM_INIT_AUTOMAKE([-Wall foreign check-news silent-rules -Werror])
AC_CONFIG_SRCDIR([src/addrwatch.c])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL


# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live], , [
	AC_MSG_ERROR([Please install libpcap and libpcap development files])
])

PKG_CHECK_MODULES(LIBEVENT, [libevent >= 1.4], , [
	AC_CHECK_LIB([event], [event_dispatch], , [
		AC_MSG_ERROR([Please install libevent-1.4 or libevent-2.0])
	])
])

PKG_CHECK_MODULES(LIBEVENT2, [libevent >= 2.0], [
	AC_DEFINE([HAVE_LIBEVENT2], 1, [Define to 1 if you have libevent2])
], [ ])


AC_SEARCH_LIBS([argp_parse], [argp], , [
	AC_MSG_ERROR([Your libc is missing argp_parse funcion. If you \
are not using GNU libc you can use argp-standalone package. Specify argp \
library search path in LDFLAGS variable with -L option. Example: ./configure \
LDFLAGS="-L/usr/local/lib"])
])
AC_CHECK_HEADERS([argp.h], , [
	AC_MSG_ERROR([Unable to find argp.h header. If you are using \
argp-standalone package specify argp include search path in CPPFLAGS \
variable with -I option. Example: ./configure CPPFLAGS="-I/usr/local/include"])
])

AC_ARG_ENABLE([sqlite3],
    AS_HELP_STRING([--enable-sqlite3], [Enable sqlite3 database output]),
    AC_CHECK_LIB([sqlite3], [sqlite3_open], , [
    	AC_MSG_ERROR([Unable to find libsqlite3.])
    ])
)
AC_ARG_ENABLE([mysql],
    AS_HELP_STRING([--enable-mysql], [Enable MySQL database output]),
    AC_CHECK_LIB([mysqlclient], [mysql_real_connect], , [
    	AC_MSG_ERROR([Unable to find libmysqlclient.])
    ])
)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_CHECK_DECLS([sys_siglist], [], [
	AC_MSG_ERROR([Unable to find sys_siglist declaration.])
], [[#include <signal.h>]])
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([bzero])



AC_CONFIG_FILES([Makefile
                 src/Makefile
		 doc/Makefile])
AC_OUTPUT
