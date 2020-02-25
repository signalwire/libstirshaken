COMPILATION
============

If you just want to get on with it, then please run
./do_install.sh
This will install dependencies as well as tools needed to make build, and will build and install it.

Dependencies:

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


stirshaken commandline tool
===========================

./stirshaken csr --privkey priv.key --pubkey pub.key --spc 12 --subject_c US --subject_cn "New SP" -f csr.pem
./stirshaken keys --privkey priv.key --pubkey pub.key
./stirshaken cert --type CA --privkey priv.key --pubkey pub.key --issuer_c "US" --issuer_cn "New Service Provider" -f certificate.pem

