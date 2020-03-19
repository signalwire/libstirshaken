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

openssl req -in csr.pem -text -noout
openssl x509 -in sp.pem -text -noout

./stirshaken keys --privkey priv.key --pubkey pub.key
./stirshaken csr --privkey priv.key --pubkey pub.key --spc 12 --subject_c US --subject_cn "New SP" -f csr.pem
sudo ./stirshaken ca
sudo ./stirshaken ca --v
./stirshaken ca --port 8650
./stirshaken sp-cert-req --url http://localhost/sti-ca/acme/cert --privkey priv.key --pubkey pub.key --csr csr.pem --spc 12 --spc_token SPCT --v
./stirshaken cert --type CA --privkey priv.key --pubkey pub.key --issuer_c US --issuer_cn "New CA" -f ca.pem
./stirshaken cert --type SP --privkey priv.key --pubkey pub.key --issuer_c US --issuer_cn "Trusted CA" --serial 3 --expiry 2 --ca_cert ca.pem --csr csr.pem --uri "http://ca.com/api" -f sp.pem
./stirshaken spc-token --privkey pa_priv.pem --url http://pa.com --spc 7889 --issuer_cn "SignalWire STI-PA" -f spc_token.txt --vvv
