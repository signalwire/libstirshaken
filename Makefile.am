dist_doc_DATA = README.txt

AM_CFLAGS    = -I./src -Iinclude -I$(srcdir)/include
lib_LTLIBRARIES = libstirshaken.la
libstirshaken_la_SOURCES = src/stir_shaken.c src/stir_shaken_service.c src/stir_shaken_ssl.c
include_HEADERS = include/stir_shaken.h
libstirshaken_la_LDFLAGS = -version-info 1:0:0

check_PROGRAMS = stir_shaken_test_1
TESTS = $(check_PROGRAMS)

LIBS += -lssl -lcrypto -pthread

stir_shaken_test_1_SOURCES = test/stir_shaken_test_1.c src/stir_shaken_service.c src/stir_shaken_ssl.c src/stir_shaken.c include/stir_shaken.h
stir_shaken_test_1_CFLAGS = -Iinclude
stir_shaken_test_1_LDFLAGS = -lssl -lcrypto -lm
