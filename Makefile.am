dist_doc_DATA = README.txt

AM_CFLAGS    = -I./src -Iinclude -I$(srcdir)/include
lib_LTLIBRARIES = libstirshaken.la
libstirshaken_la_SOURCES = src/stir_shaken.c src/stir_shaken_service.c src/stir_shaken_passport.c src/stir_shaken_authorize.c src/stir_shaken_verify.c src/stir_shaken_ssl.c
include_HEADERS = include/stir_shaken.h
libstirshaken_la_LDFLAGS = -version-info 1:0:0

check_PROGRAMS = stir_shaken_test_1 stir_shaken_test_2 stir_shaken_test_3 stir_shaken_test_4 stir_shaken_test_5 stir_shaken_test_6 stir_shaken_test_7 stir_shaken_test_8 stir_shaken_test_9 stir_shaken_test_10 stir_shaken_test_11 stir_shaken_test_12
TESTS = $(check_PROGRAMS)

LIBS += -lcjson -lcurl -lcrypto -lssl -ljwt -pthread

stir_shaken_test_1_SOURCES = test/stir_shaken_test_1.c
stir_shaken_test_1_CFLAGS = -Iinclude
stir_shaken_test_1_LDFLAGS = -lstirshaken

stir_shaken_test_2_SOURCES = test/stir_shaken_test_2.c
stir_shaken_test_2_CFLAGS = -Iinclude
stir_shaken_test_2_LDFLAGS = -lstirshaken

stir_shaken_test_3_SOURCES = test/stir_shaken_test_3.c
stir_shaken_test_3_CFLAGS = -Iinclude
stir_shaken_test_3_LDFLAGS = -lstirshaken

stir_shaken_test_4_SOURCES = test/stir_shaken_test_4.c
stir_shaken_test_4_CFLAGS = -Iinclude
stir_shaken_test_4_LDFLAGS = -lstirshaken

stir_shaken_test_5_SOURCES = test/stir_shaken_test_5.c
stir_shaken_test_5_CFLAGS = -Iinclude
stir_shaken_test_5_LDFLAGS = -lstirshaken

stir_shaken_test_6_SOURCES = test/stir_shaken_test_6.c
stir_shaken_test_6_CFLAGS = -Iinclude
stir_shaken_test_6_LDFLAGS = -lstirshaken

stir_shaken_test_7_SOURCES = test/stir_shaken_test_7.c
stir_shaken_test_7_CFLAGS = -Iinclude
stir_shaken_test_7_LDFLAGS = -lstirshaken

stir_shaken_test_8_SOURCES = test/stir_shaken_test_8.c
stir_shaken_test_8_CFLAGS = -Iinclude
stir_shaken_test_8_LDFLAGS = -lcurl -lstirshaken

stir_shaken_test_9_SOURCES = test/stir_shaken_test_9.c
stir_shaken_test_9_CFLAGS = -Iinclude
stir_shaken_test_9_LDFLAGS = -lcurl -lstirshaken

stir_shaken_test_10_SOURCES = test/stir_shaken_test_10.c
stir_shaken_test_10_CFLAGS = -Iinclude
stir_shaken_test_10_LDFLAGS = -lcurl -lstirshaken

stir_shaken_test_11_SOURCES = test/stir_shaken_test_11.c
stir_shaken_test_11_CFLAGS = -Iinclude
stir_shaken_test_11_LDFLAGS = -lcurl -lstirshaken

stir_shaken_test_12_SOURCES = test/stir_shaken_test_12.c
stir_shaken_test_12_CFLAGS = -Iinclude
stir_shaken_test_12_LDFLAGS = -lcurl -lstirshaken
