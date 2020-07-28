AC_INIT([libstirshaken], [1.0.0], [stirshaken@dataandsignal.com, bugs: add_url], [libstirshaken], [dataandsignal.com])
AM_PROG_AR
LT_INIT
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign])
AC_PROG_CC

AC_CANONICAL_HOST

case "$host" in
    *darwin*)
        # Common Apple Darwin settings
        CPPFLAGS="$CPPFLAGS -I/usr/local/opt/openssl/include"
	LDFLAGS="$LDFLAGS -L/usr/local/opt/openssl/lib"
    ;;
esac

SAC_OPENSSL

if test x$HAVE_OPENSSL = x1; then
	openssl_CFLAGS="$openssl_CFLAGS -DHAVE_OPENSSL";
else
	AC_MSG_ERROR([OpenSSL >= 1.0.1e and associated developement headers required])
fi

PKG_CHECK_MODULES([CURL], [libcurl >= 7.19], [have_curl=true], [have_curl=false])
PKG_CHECK_MODULES([CJSON], [libcjson], [have_cjson=true], [have_cjson=false])
PKG_CHECK_MODULES([JWT], [libjwt], [have_jwt=true], [have_jwt=false])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
