COMPILATION
============

Dependencies (must be compiled and installed):

LIBS += -lcjson -lcurl -lcrypto -lssl -ljwt -pthread
cJSON: https://github.com/DaveGamble/cJSON
CURL: https://github.com/curl/curl
OpenSSL: https://github.com/openssl/openssl
LibJWT: https://github.com/benmcollins/libjwt


May need to export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib if CJSON is in folder that is not currently in LD_LIBRARY_PATH.

Please run ./install.sh or perform these manual steps:

autoreconf -i
automake --add-missing
libtoolize
autoreconf
configure
make
sudo make install

TEST
====
make check
