AC_INIT([libstirshaken], [1.0.0], [stirshaken@dataandsignal.com, bugs: add_url], [libstirshaken], [dataandsignal.com])

AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign])

AC_CONFIG_MACRO_DIRS([build/m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_PROG_CC_C_O

AM_PROG_AR

AC_PROG_LIBTOOL

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

PKG_CHECK_MODULES([CURL], [libcurl >= 7.19])
PKG_CHECK_MODULES([JWT], [libjwt >= 1.12])
PKG_CHECK_MODULES([KS], [libks >= 1.1.0])

#  Enable clang address sanitizer bit build
AC_ARG_ENABLE(address_sanitizer,
  [AC_HELP_STRING([--enable-address-sanitizer],[build with address sanitizer])],
  [enable_address_sanitizer="$enable_address_sanitizer"],
  [enable_address_sanitizer="no"])
if test "${enable_address_sanitizer}" = "yes"; then
  CFLAGS="$CFLAGS -fsanitize=address -fno-omit-frame-pointer -fstack-protector-strong"
  CXXFLAGS="$CXXFLAGS -fsanitize=address -fno-omit-frame-pointer -fstack-protector-strong"
  LDFLAGS="$LDFLAGS -fsanitize=address"
fi

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
