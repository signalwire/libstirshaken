COMPILATION
============

If you just want to get on with it, then please run
./do_install.sh
This will install dependencies as well as tools needed to make build, and will build and install it.

Dependencies:

LIBS += -lcjson -lcurl -lcrypto -lssl -ljwt -luuid -pthread
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
openssl x509 -hash -noout -in ca.pem

openssl pkey -in priv.pem -pubout -outform pem | sha256sum
openssl x509 -in cert.pem -pubkey -noout -outform pem | sha256sum
openssl req -in csr.pem -pubkey -noout -outform pem | sha256sum
openssl verify -verbose -CAfile test/ref/ca/ca.pem sp.pem

./stirshaken keys --privkey priv.key --pubkey pub.key
./stirshaken csr --privkey priv.key --pubkey pub.key --spc 12 --subject_c US --subject_cn "New SP" -f csr.pem
sudo ./stirshaken ca --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 --ca_cert test/ref/ca/ca.pem --uri http://ca.shaken.signalwire.com/sti-ca/authority-over-the-number-check --vvv
./stirshaken ca --port 8756 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 1000 --ca_cert test/ref/ca/ca.pem --uri http://190.102.98.199/api --v
nohup sudo ./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 --ca_cert test/ref/ca/ca.pem --uri http://190.102.98.199/sti-ca/authority-over-the-number-check/1 --vvv 2> /var/log/ca.err > /var/log/ca.log &
./stirshaken sp-cert-req --url http://localhost/sti-ca/acme/cert --privkey priv.key --pubkey pub.key --csr csr.pem --spc 12 --spc_token SPCT --v
./stirshaken cert --type CA --privkey test/ref/ca/ca.priv --pubkey test/ref/ca/ca.pub --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 -f test/ref/ca/ca.pem -v
./stirshaken cert --type SP --privkey priv.key --pubkey pub.key --issuer_c US --issuer_cn "Trusted CA" --serial 3 --expiry 2 --ca_cert ca.pem --csr csr.pem --uri "http://ca.com/api" -f sp.pem
./stirshaken cert --type PA --privkey test/ref/pa/pa.priv --pubkey test/ref/pa/pa.pub --issuer_c US --issuer_cn "SignalWire STI-PA" --serial 1 --expiry 1000 -f test/ref/pa/pa.pem
./stirshaken spc-token --privkey pa_priv.pem --url http://pa.com --spc 7889 --issuer_cn "SignalWire STI-PA" -f spc_token.txt --vvv
./stirshaken spc-token --privkey test/ref/pa/pa.priv --url https://jazzchat.pl/pa.pem --spc 1 --issuer_cn "SignalWire STI-PA" -f spc_token_1.txt --vvv
./stirshaken jwt-check --jwt "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL2phenpjaGF0LnBsL3BhLnBlbSJ9.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMTAxIiwidHlwZSI6InNwYy10b2tlbiJ9.PGNPGieDuNIhxtpLFUPwS0qyy61_iW4hNqyio-jeSn8o8d7zgLW1SsQ6JFNB4txR8cW-99mKO1fO7qmSrbOAOw" --pubkey tsst/ref/pa/pa.pub --vvv
./stirshaken jwt-dump --jwt "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL2phenpjaGF0LnBsL3BhLnBlbSJ9.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMTAxIiwidHlwZSI6InNwYy10b2tlbiJ9.PGNPGieDuNIhxtpLFUPwS0qyy61_iW4hNqyio-jeSn8o8d7zgLW1SsQ6JFNB4txR8cW-99mKO1fO7qmSrbOAOw" --vvv
