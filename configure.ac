AC_PREREQ([2.69])
ACLOCAL_AMFLAGS=-I m4
AC_INIT([freezer], [0.0.1], [jangho@jangho.io])
AM_INIT_AUTOMAKE([foreign -Wall -Werror no-dist-gzip dist-xz])

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile m4/Makefile])

AC_DEFINE([DEFAULT_CHUNK_SIZE], [268435456], [Default chunk size. Must be aligned to 1MiB, and 1MiB multiplied by a power of 2])
AC_DEFINE([CURL_WRITE_BUFFER_SIZE], [4096], [curl write buffer size.])
AC_DEFINE([NUM_RETRY], [5], [The number of re-trials for each request.])

PKG_CHECK_MODULES([UTF8PROC], [libutf8proc])
PKG_CHECK_MODULES([CURL], [libcurl])
PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([LIBXML2], [libxml-2.0])

AC_PATH_PROG([CFORMAT], [clang-format], [])
AS_IF([test "x$CFORMAT" = x], [AC_MSG_WARN([clang-format not found. Format will not be available.])])

AC_OUTPUT
