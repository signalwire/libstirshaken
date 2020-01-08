dist_doc_DATA = README.txt

AM_CFLAGS    = -I./src -Iinclude -I$(srcdir)/include
lib_LTLIBRARIES = libstirshaken.la
libstirshaken_la_SOURCES = src/stir_shaken.c src/stir_shaken_service.c src/stir_shaken_passport.c src/stir_shaken_authorize.c src/stir_shaken_verify.c src/stir_shaken_ssl.c
include_HEADERS = include/stir_shaken.h
libstirshaken_la_LDFLAGS = -version-info 1:0:0

check_PROGRAMS = stir_shaken_test_1 stir_shaken_test_11 stir_shaken_test_12
TESTS = $(check_PROGRAMS)

LIBS += -lcjson -lcurl -lcrypto -lssl -ljwt -pthread

stir_shaken_test_1_SOURCES = test/stir_shaken_test_1.c
stir_shaken_test_1_CFLAGS = -Iinclude
stir_shaken_test_1_LDFLAGS = -lstirshaken

stir_shaken_test_11_SOURCES = test/stir_shaken_test_11.c
stir_shaken_test_11_CFLAGS = -Iinclude
stir_shaken_test_11_LDFLAGS = -lcurl -lstirshaken

stir_shaken_test_12_SOURCES = test/stir_shaken_test_12.c
stir_shaken_test_12_CFLAGS = -Iinclude
stir_shaken_test_12_LDFLAGS = -lcurl -lstirshaken
