ACLOCAL_AMFLAGS = -I build/m4
AM_CFLAGS    = -I./src -Iinclude -I$(srcdir)/include $(KS_CFLAGS) $(CURL_CFLAGS) $(JWT_CFLAGS) $(openssl_CFLAGS)

lib_LTLIBRARIES = libstirshaken.la
libstirshaken_la_SOURCES = src/stir_shaken.c src/stir_shaken_service.c src/stir_shaken_passport.c src/stir_shaken_verify.c src/stir_shaken_ssl.c src/stir_shaken_acme.c src/stir_shaken_sp.c
include_HEADERS = include/stir_shaken.h
libstirshaken_la_LDFLAGS = -version-info 1:0:0 -Wl,--wrap=stir_shaken_make_http_req

pkgconfigdir   = @pkgconfigdir@
pkgconfig_DATA = build/stirshaken.pc

check_PROGRAMS = stir_shaken_test_1 stir_shaken_test_2 stir_shaken_test_3 stir_shaken_test_4 stir_shaken_test_5 stir_shaken_test_6 stir_shaken_test_7 stir_shaken_test_8 stir_shaken_test_9 stir_shaken_test_10 stir_shaken_test_11 stir_shaken_test_12 stir_shaken_test_14
TESTS = $(check_PROGRAMS)

bin_PROGRAMS = stirshaken
stirshaken_SOURCES = util/src/stir_shaken_tool_command.c util/src/stir_shaken_tool.c util/src/stir_shaken_ca.c util/src/mongoose.c
stirshaken_CFLAGS = -Iinclude -Iutil/include -DMG_ENABLE_SSL
stirshaken_LDADD = libstirshaken.la $(KS_LIBS)

LIBS += $(KS_LIBS) $(CURL_LIBS) $(JWT_LIBS) -pthread

stir_shaken_test_1_SOURCES = test/stir_shaken_test_1.c
stir_shaken_test_1_CFLAGS = -Iinclude
stir_shaken_test_1_LDADD = libstirshaken.la

stir_shaken_test_2_SOURCES = test/stir_shaken_test_2.c
stir_shaken_test_2_CFLAGS = -Iinclude
stir_shaken_test_2_LDADD = libstirshaken.la

stir_shaken_test_3_SOURCES = test/stir_shaken_test_3.c
stir_shaken_test_3_CFLAGS = -Iinclude
stir_shaken_test_3_LDADD = libstirshaken.la

stir_shaken_test_4_SOURCES = test/stir_shaken_test_4.c
stir_shaken_test_4_CFLAGS = -Iinclude
stir_shaken_test_4_LDADD = libstirshaken.la

stir_shaken_test_5_SOURCES = test/stir_shaken_test_5.c
stir_shaken_test_5_CFLAGS = -Iinclude
stir_shaken_test_5_LDADD = libstirshaken.la

stir_shaken_test_6_SOURCES = test/stir_shaken_test_6.c
stir_shaken_test_6_CFLAGS = -Iinclude
stir_shaken_test_6_LDADD = libstirshaken.la

stir_shaken_test_7_SOURCES = test/stir_shaken_test_7.c
stir_shaken_test_7_CFLAGS = -Iinclude
stir_shaken_test_7_LDADD = libstirshaken.la

stir_shaken_test_8_SOURCES = test/stir_shaken_test_8.c
stir_shaken_test_8_CFLAGS = -Iinclude
stir_shaken_test_8_LDADD = libstirshaken.la

stir_shaken_test_9_SOURCES = test/stir_shaken_test_9.c
stir_shaken_test_9_CFLAGS = -Iinclude
stir_shaken_test_9_LDADD = libstirshaken.la

stir_shaken_test_10_SOURCES = test/stir_shaken_test_10.c
stir_shaken_test_10_CFLAGS = -Iinclude
stir_shaken_test_10_LDADD = libstirshaken.la

stir_shaken_test_11_SOURCES = test/stir_shaken_test_11.c
stir_shaken_test_11_CFLAGS = -Iinclude
stir_shaken_test_11_LDADD = libstirshaken.la

stir_shaken_test_12_SOURCES = test/stir_shaken_test_12.c
stir_shaken_test_12_CFLAGS = -Iinclude
stir_shaken_test_12_LDADD = libstirshaken.la

stir_shaken_test_14_SOURCES = test/stir_shaken_test_14.c
stir_shaken_test_14_CFLAGS = -Iinclude
stir_shaken_test_14_LDADD = libstirshaken.la
