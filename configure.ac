AC_PREREQ([2.68])
AC_INIT([addrwatch], [0.3], [julius.kriukas@gmail.com])
AC_CONFIG_AUX_DIR([config])
AM_CONFIG_HEADER([src/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live])
#AC_CHECK_LIB([event], [event_base_dispatch])
AC_CHECK_LIB([event], [event_new], [
	LIBS="$LIBS -levent"
	AC_DEFINE([HAVE_LIBEVENT], 1, [Define to 1 if you have the event library (-levent).])
	AC_DEFINE([HAVE_LIBEVENT2], 1, [Define to 1 if you have libevent2])
], [
	AC_CHECK_LIB([event], [event_dispatch],[
		LIBS="$LIBS -levent"
		AC_DEFINE([HAVE_LIBEVENT], 1, [Define to 1 if you have the event library (-levent).])
	],[
		AC_MSG_ERROR([Please install libevent-1.4 or libevent-2.0])
	])
])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h stdint.h stdlib.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([bzero])


AC_ARG_ENABLE([sqlite3],
    AS_HELP_STRING([--enable-sqlite3], [Enable sqlite3 database output]))

AS_IF([test "x$enable_sqlite3" = "xyes"], [
	AC_CHECK_LIB([sqlite3], [sqlite3_open])
])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_FILES([Makefile
                 src/Makefile
		 doc/Makefile])
AC_OUTPUT
