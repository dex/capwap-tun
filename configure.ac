#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([capwap-tun], [0.0.1], [dex.chen@cipherium.com.tw])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/capwap-tun-server.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
has_iwlib=no
AC_SEARCH_LIBS([event_init],[event],[have_event=yes])

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h string.h sys/socket.h unistd.h])

if test "x${have_event}" = xyes; then
	AC_CHECK_HEADERS([event.h],[],[have_event=no])
fi

if test "x${have_event}" = xno; then
	AC_MSG_ERROR([No event support])
fi

AC_ARG_ENABLE([capwap-header],
	    [AS_HELP_STRING([--disable-capwap-header],
			    [Remove CAPWAP header])],
	    [],[AC_DEFINE([ENABLE_CAPWAP_HDR], 1, [Enable CAPWAP header])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([memset socket])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
