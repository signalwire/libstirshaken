dist_doc_DATA = README.txt

AM_CFLAGS    = -I./src -Iinclude -I$(srcdir)/include
lib_LTLIBRARIES = libstirshaken.la
libstirshaken_la_SOURCES = src/stir_shaken.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_verify.c src/stir_shaken_ssl.c
include_HEADERS = include/stir_shaken.h
libstirshaken_la_LDFLAGS = -version-info 1:0:0

check_PROGRAMS = stir_shaken_test_1 stir_shaken_test_2 stir_shaken_test_3 stir_shaken_test_4 stir_shaken_test_5 stir_shaken_test_6 stir_shaken_test_7 stir_shaken_test_8 stir_shaken_test_9
TESTS = $(check_PROGRAMS)

LIBS += -lcjson -lssl -lcrypto -pthread

stir_shaken_test_1_SOURCES = test/stir_shaken_test_1.c src/stir_shaken_service.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_1_CFLAGS = -Iinclude
stir_shaken_test_1_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_2_SOURCES = test/stir_shaken_test_2.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_2_CFLAGS = -Iinclude
stir_shaken_test_2_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_3_SOURCES = test/stir_shaken_test_3.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_3_CFLAGS = -Iinclude
stir_shaken_test_3_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_4_SOURCES = test/stir_shaken_test_4.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_4_CFLAGS = -Iinclude
stir_shaken_test_4_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_5_SOURCES = test/stir_shaken_test_5.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_5_CFLAGS = -Iinclude
stir_shaken_test_5_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_6_SOURCES = test/stir_shaken_test_6.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_6_CFLAGS = -Iinclude
stir_shaken_test_6_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_7_SOURCES = test/stir_shaken_test_7.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_7_CFLAGS = -Iinclude
stir_shaken_test_7_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_8_SOURCES = test/stir_shaken_test_8.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_verify.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_8_CFLAGS = -Iinclude
stir_shaken_test_8_LDFLAGS = -lssl -lcrypto -lm

stir_shaken_test_9_SOURCES = test/stir_shaken_test_9.c src/stir_shaken_service.c src/stir_shaken_authorize.c src/stir_shaken_verify.c src/stir_shaken_ssl.c src/stir_shaken.c
stir_shaken_test_9_CFLAGS = -Iinclude
stir_shaken_test_9_LDFLAGS = -lssl -lcrypto -lm
