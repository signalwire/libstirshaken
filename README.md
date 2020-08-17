## Overview

STIR-Shaken is a technology for making secure calls by use of SSL certificates and JSON Web Tokens.
For a general overview of the framwork please search web for: ATIS, "Signature-based Handling of Asserted Information using Tokens (SHAKEN). Governance Model and Certificate Management",
(no link provided because spec is actively worked on and updated frequently).
This library provides building blocks for implementing STIR-Shaken authentication and verification services, (STI-SP/AS, STI-SP/VS),
as well as elements of STI-CA and STI-PA.
You can find a list of specs relevant to Shaken at the bottom of this document.


## Folders

```
/ - main folder
	README.txt	- this file
	src/		- library sources
	include/	- library headers
	util/		- helper programs (stirshaken tool for running multiple commands, see below)
	test/		- unit tests
```

## Compilation

### Dependencies

CURL: https://github.com/curl/curl

OpenSSL: https://github.com/openssl/openssl version 1.1 or later

LibJWT: https://github.com/benmcollins/libjwt version 1.12 or later

LibKS: https://github.com/signalwire/libks

Packages for latest libks and libjwt which are required are available in the freeswitch package repositories:

Debian 10:
```
apt-get update && apt-get install -y gnupg2 wget lsb-release
wget -O - https://files.freeswitch.org/repo/deb/debian-release/fsstretch-archive-keyring.asc | apt-key add -
echo "deb http://files.freeswitch.org/repo/deb/debian-release/ `lsb_release -sc` main" > /etc/apt/sources.list.d/freeswitch.list
echo "deb-src http://files.freeswitch.org/repo/deb/debian-release/ `lsb_release -sc` main" >> /etc/apt/sources.list.d/freeswitch.list
apt-get update && apt-get install -y automake autoconf libtool libcurl4-openssl-dev libjwt-dev libks
```

### Build

If you just want to get on with it, then please run
```
./do_install.sh
```
This will install dependencies as well as tools needed to make build, and will build and install it on debian buster.
If there are problems with dependencies, then install them manually and rerun `./do_install.sh`.
This will build all Shaken targets if packages are installed.

Please run `./do_install.sh` (debian specific) or perform these manual steps:

```
./bootstrap.sh
./configure
make
sudo make install
```

### Test

```
make check
make -f Makefile.unit (this will execute comprehensive test that tests it all)
```

## stirshaken Tool

```
make stirshaken

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
./stirshaken ca --port 8756 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 1000 --ca_cert test/ref/ca/ca.pem --uri http://ca.shaken.signalwire.com/api --v
./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 9999 --ca_cert test/ref/ca/ca.pem --uri "TNAuthList(URI)" --vvv
nohup sudo ./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 --ca_cert test/ref/ca/ca.pem --uri http://190.102.98.199/sti-ca/authority-over-the-number-check/1 --vvv 2> /var/log/ca.err > /var/log/ca.log &
./stirshaken sp-cert-req --url http://localhost/sti-ca/acme/cert --privkey priv.key --pubkey pub.key --csr csr.pem --spc 12 --spc_token SPCT --v
./stirshaken cert --type CA --privkey test/ref/ca/ca.priv --pubkey test/ref/ca/ca.pub --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 -f test/ref/ca/ca.pem -v
./stirshaken cert --type SP --privkey priv.key --pubkey pub.key --issuer_c US --issuer_cn "Trusted CA" --serial 3 --expiry 2 --ca_cert ca.pem --csr csr.pem --uri "http://ca.com/api" -f sp.pem
./stirshaken cert --type PA --privkey test/ref/pa/pa.priv --pubkey test/ref/pa/pa.pub --issuer_c US --issuer_cn "SignalWire STI-PA" --serial 1 --expiry 1000 -f test/ref/pa/pa.pem
./stirshaken spc-token --privkey pa_priv.pem --url http://pa.com --spc 7889 --issuer_cn "SignalWire STI-PA" -f spc_token.txt --vvv
./stirshaken spc-token --privkey test/ref/pa/pa.priv --url http://pa.shaken.signalwire.com/pa.pem --spc 1 --issuer_cn "SignalWire STI-PA" -f spc_token_1.txt --vvv
./stirshaken jwt-check --jwt "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL2phenpjaGF0LnBsL3BhLnBlbSJ9.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMTAxIiwidHlwZSI6InNwYy10b2tlbiJ9.PGNPGieDuNIhxtpLFUPwS0qyy61_iW4hNqyio-jeSn8o8d7zgLW1SsQ6JFNB4txR8cW-99mKO1fO7qmSrbOAOw" --pubkey tsst/ref/pa/pa.pub --vvv
./stirshaken jwt-dump --jwt "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL2phenpjaGF0LnBsL3BhLnBlbSJ9.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMTAxIiwidHlwZSI6InNwYy10b2tlbiJ9.PGNPGieDuNIhxtpLFUPwS0qyy61_iW4hNqyio-jeSn8o8d7zgLW1SsQ6JFNB4txR8cW-99mKO1fO7qmSrbOAOw" --vvv
./stirshaken sp-cert-req --url http://localhost/sti-ca/acme/cert --privkey priv.key --pubkey pub.key --csr csr.pem --spc 12 --spc_token SPCT --v
./stirshaken sp-cert-req --url 190.102.98.199/sti-ca/acme/cert --privkey priv.pem --pubkey pub.pem  --csr csr.pem --spc 1 -f sp.pem --vvv --port 8082 --spc_token eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIiwidHlwIjoiSldUIiwieDV1IjoiaHR0cDovLzMuMTcuMTc3LjE3NC9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.SXvxvFWE68aSQgo9BVrw4bH_GVAtIjPyd8llvHGMzfQctwKi7k2mM0Lb2fzHNL-Z_CldLq-iiBhcgNHiZnv-1A
```


## Specs

* ATIS-1000074, Signature-based Handling of Asserted Information using Tokens (SHAKEN).
* ATIS-1000080, Signature-based Handling of Asserted Information using Tokens (SHAKEN). Governance Model and Certificate Management
* ATIS-0300251, Codes for Identification of Service Providers for Information Exchange.
* ATIS-1000054, ATIS Technical Report on Next Generation Network Certificate Management.
* ATIS-0300116, Interoperability Standards between Next Generation Networks (NGN) for Signature-Based Handling of Asserted Information Using Tokens (SHAKEN)
draft-barnes-acme-service-provider, ACME Identifiers and Challenges for VoIP Service Providers.
* RFC 2986, PKCS #10: Certification Request Syntax Specification Version 1.7.
* RFC 3261, SIP: Session Initiation Protocol.
* RFC 3966, The tel URI for Telephone Numbers.																		https://tools.ietf.org/html/rfc3966
* RFC 4949, Internet Security Glossary, Version 2.
* RFC 5246, The Transport Layer Security (TLS) Protocol Version 1.2.
* IETF RFC 5280, Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile.  https://www.ietf.org/rfc/rfc5280.txt
* RFC 5958, Asymmetric Key Package.
* RFC 6749, The OAuth 2.0 Authorization Framework.
* RFC 6960, Online Certificate Status Protocol (OSCP).
* RFC 7159, The JavaScript Object Notation (JSON).
* RFC 7515, JSON Web Signature (JWS)                                                                                  https://tools.ietf.org/html/rfc7515
* RFC 7516, JSON Web Algorithms (JWA).
* RFC 7517, JSON Web Key (JWK).
* RFC 7518, JSON Web Algorithms (JWA)                                                                                 https://tools.ietf.org/html/rfc7518         ES256
* RFC 7519, JSON Web Token (JWT).
* RFC 7231, Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content.
* RFC 7375, Secure Telephone Identity Threat Model.                                                                   https://tools.ietf.org/html/rfc7375
* draft-ietf-stir-rfc4474bis, Authenticated Identity Management in the Session Initiation Protocol.                   https://tools.ietf.org/html/rfc8224
* draft-ietf-stir-passport, Personal Assertion Token (PASSporT).                                                      https://tools.ietf.org/html/rfc8225
* draft-ietf-stir-certificates, Secure Telephone Identity Credentials: Certificates4                                  https://tools.ietf.org/html/rfc8226
* draft-ietf-acme-acme, Automatic Certificate Management Environment (ACME)                                           https://tools.ietf.org/html/rfc8555
* draft-ietf-stir-passport-rcd
* draft-ietf-stir-rph-emergency-services
* draft-ietf-stir-passport-divert
* draft-ietf-stir-cert-delegation
* draft-ietf-stir-oob
* draft-ietf-acme-authority-token-tnauthlist

