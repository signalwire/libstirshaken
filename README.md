## Overview

STIR-Shaken is a technology for making secure calls by use of SSL certificates and JSON Web Tokens.
For a general overview of the framwork please search web for: ATIS, "Signature-based Handling of Asserted Information using Tokens (SHAKEN). Governance Model and Certificate Management",

This library implements STIR (Secure Telephony Identity Revisited) and SHAKEN (Signature-based Handling of Asserted information using toKENs) (RFC8224, RFC8588), with X509 certificate path check (ATIS "Signature-based Handling of Asserted information using toKENs (SHAKEN)", RFC5280 "6. Certification Path Validation").

You can find a comprehensive list of specs relevant to Shaken at the bottom of this document.

## libstirshaken

This library provides building blocks for implementing STIR-Shaken authentication and verification services, (STI-SP/AS, STI-SP/VS),
as well as elements of STI-CA and STI-PA.

## Interoperability

libstirshaken was tested for interoperability with other leading Shaken implementations (e.g. TransNexus).

## Basic usage

# Authentication

Create PASSporT using Authentication Service interface

```
stir_shaken_context_t ss = { 0 };
stir_shaken_passport_params_t params = {
	.x5u = "https://shaken.signalwire.cloud/sp.pem"",
	.attest = "B",
	.desttn_key = "tn",
	.desttn_val = "01256700800",
	.iat = time(NULL),
	.origtn_key = "tn",
	.origtn_val = "01256500600",
	.origid = "e32f4189-cb86-460f-bb92-bd3acb89f29c"
};
stir_shaken_passport_t *passport = NULL;
char *s = NULL, *sih = NULL;
stir_shaken_as_t *as = NULL;

stir_shaken_init(&ss, STIR_SHAKEN_LOGLEVEL_NOTHING);
as = stir_shaken_as_create(&ss);
stir_shaken_as_load_private_key(&ss, as, "sp.priv"); 
encoded = stir_shaken_as_authenticate_to_passport(&ss, as, &params, &passport);
```

Print PASSporT in encoded form
 
```
printf("\n1. PASSporT encoded:\n%s\n", encoded);
```
```
1. PASSporT encoded:
eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyIwMTI1NjcwMDgwMCJdfSwiaWF0IjoxNjE2NDQyNTIzLCJvcmlnIjp7InRuIjoiMDEyNTY1MDA2MDAifSwib3JpZ2lkIjoiZTMyZjQxODktY2I4Ni00NjBmLWJiOTItYmQzYWNiODlmMjljIn0.VT_KOQtrCS3WctNBFT7PKcUowTqHI1cZU3XhBaYEji8eH07XE5rYxomns1EnnePpw96zUF7cr-mBBro-wP65jg
```
Print PASSporT in decoded (plain) form
```
s = stir_shaken_passport_dump_str(&ss, passport, 1);
printf("\n2. PASSporT decoded:\n%s\n", s);
```
```
2. PASSporT decoded:

{
    "alg": "ES256",
    "ppt": "shaken",
    "typ": "passport",
    "x5u": "https://shaken.signalwire.cloud/sp.pem"
}
.
{
    "attest": "B",
    "dest": {
        "tn": [
            "01256700800"
        ]
    },
    "iat": 1616442523,
    "orig": {
        "tn": "01256500600"
    },
    "origid": "e32f4189-cb86-460f-bb92-bd3acb89f29c"
}

```
Create and print SIP Identity Header
```
sih = stir_shaken_as_authenticate_to_sih(&ss, as, &params, &passport);
printf("\n3. SIP Identity Header:\n%s\n", sih);
```
```
3. SIP Identity Header:
eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyIwMTI1NjcwMDgwMCJdfSwiaWF0IjoxNjE2NDQyNTIzLCJvcmlnIjp7InRuIjoiMDEyNTY1MDA2MDAifSwib3JpZ2lkIjoiZTMyZjQxODktY2I4Ni00NjBmLWJiOTItYmQzYWNiODlmMjljIn0.rN3n-2qjP9eVPMViBbK6sVUmN3tMRbI-8ffVs1M7J9KL0q0hMKtdZNBWj_TS5RkvakiDUoSErkDsahh2nRGD8Q;info=<https://shaken.signalwire.cloud/sp.pem>;alg=ES256;ppt=shaken
```

# Verification

```

char *passport_encoded = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyIwMTI1NjcwMDgwMCJdfSwiaWF0IjoxNjE2NDQyNTIzLCJvcmlnIjp7InRuIjoiMDEyNTY1MDA2MDAifSwib3JpZ2lkIjoiZTMyZjQxODktY2I4Ni00NjBmLWJiOTItYmQzYWNiODlmMjljIn0.VT_KOQtrCS3WctNBFT7PKcUowTqHI1cZU3XhBaYEji8eH07XE5rYxomns1EnnePpw96zUF7cr-mBBro-wP65jg";
char *sip_identity_header = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyIwMTI1NjcwMDgwMCJdfSwiaWF0IjoxNjE2NDQyNTIzLCJvcmlnIjp7InRuIjoiMDEyNTY1MDA2MDAifSwib3JpZ2lkIjoiZTMyZjQxODktY2I4Ni00NjBmLWJiOTItYmQzYWNiODlmMjljIn0.rN3n-2qjP9eVPMViBbK6sVUmN3tMRbI-8ffVs1M7J9KL0q0hMKtdZNBWj_TS5RkvakiDUoSErkDsahh2nRGD8Q;info=<https://shaken.signalwire.cloud/sp.pem>;alg=ES256;ppt=shaken";
stir_shaken_passport_t *passport_out = NULL;
stir_shaken_cert_t *cert_out = NULL;
int iat_freshness_seconds = 60;
unsigned long connect_timeout_s = 5;
stir_shaken_vs_t *vs = NULL;

stir_shaken_init(&ss, STIR_SHAKEN_LOGLEVEL_NOTHING);

vs = stir_shaken_vs_create(&ss);
```

Optionally turn on X509 certificate path verification (and configure CA dir containing trusted CA root certificates)
```
stir_shaken_vs_set_x509_cert_path_check(&ss, vs, 1);
stir_shaken_vs_load_ca_dir(&ss, vs, "path/to/ca/dir");
```

Optionally set your own callback to supply certificates from cache
```
stir_shaken_vs_set_callback(&ss, vs, cache_callback);
```

Optionally set timeout on connect (default is 2 seconds)
```
stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s);
```

Verify PASSporT's signature (involves certificate downloading or fetching from cache, and X509 cert path check if turned on), input is PASSporT encoded, output is status and optionally certificate and PASSporT used during verification
``` 
status = stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out);
if (STIR_SHAKEN_STATUS_OK != status) {
	printf("PASSporT failed verification");
} else {
	printf("PASSporT Verified");
}
```

Same as before, but input is PASSporT wrapped into SIP Identity Header
```
status = stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out);
if (STIR_SHAKEN_STATUS_OK != status) {
	printf("SIP Identity Header failed verification");
} else {
	printf("SIP Identity Header verified");
}
```

Check that PASSporT applies to the current moment in time
```
if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_validate_iat_against_freshness(&ss, passport_out, iat_freshness_seconds)) {
	error_description = stir_shaken_get_error(&ss, &error_code);
	if (error_code == STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_FUTURE) {
		printf("PASSporT not valid yet\n");
	} else if (error_code == STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_EXPIRED) {
		printf("PASSporT expired\n");
	} else if (error_code == STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT) {
		printf("PASSporT is missing @iat grant\n");
	} else {
		printf("You called this method with NULL PASSporT\n");
	}
	printf("PASSporT doesn't apply to the current moment in time\n");
	printf("Error description is:\n%s\n", error_description);
}
```

Print PASSporT
```
passport_decoded = stir_shaken_passport_dump_str(&ss, passport, 1);
if (passport_decoded) {
	printf("PASSporT is:\n%s\n", passport_decoded);
	stir_shaken_free_jwt_str(passport_decoded);
	passport_decoded = NULL;
}
```

```
PASSporT Verified

PASSporT is:

{
    "alg": "ES256",
    "ppt": "shaken",
    "typ": "passport",
    "x5u": "https://shaken.signalwire.cloud/sp.pem"
}
.
{
    "attest": "B",
    "dest": {
        "tn": [
            "01256700800"
        ]
    },
    "iat": 1616442523,
    "orig": {
        "tn": "01256500600"
    },
    "origid": "e32f4189-cb86-460f-bb92-bd3acb89f29c"
}

```

Print the certificate
```
if (STIR_SHAKEN_STATUS_OK == stir_shaken_read_cert_fields(&ss, cert)) {
	printf("Certificate is:\n");
	stir_shaken_print_cert_fields(stdout, cert);
}
```

```
Certificate is:
STIR-Shaken: STI Cert: Serial number: 01 1
STIR-Shaken: STI Cert: Issuer: /C=US/CN=SignalWire STI-CA Test
STIR-Shaken: STI Cert: Subject: /C=US/CN=SignalWire STI-SP Test
STIR-Shaken: STI Cert: Valid from: Aug  1 00:37:19 2020 GMT
STIR-Shaken: STI Cert: Valid to: Dec 17 00:37:19 2047 GMT
STIR-Shaken: STI Cert: Version: 3
```


## Folders

```
/ - main folder
	README.txt	- this file
	src/		- library sources
	include/	- library headers
	util/		- helper programs (stirshaken tool for running multiple commands, see below)
	test/		- unit tests
	examples/	- examples:
						stir_shaken_as_basic.c - shows how Authentication Service may be constructed from the basic blocks
						stir_shaken_as_easy.c - shows how to use default Authentication Service interface
						stir_shaken_vs_basic.c - shows how Verification Service may be constructed from the basic blocks
						stir_shaken_vs_easy.c - shows how to use default Verification Service interface
						stir_shaken_ca.c - shows how Certificate Authority may be constructed from the basic blocks
						stir_shaken_cert_req.c - shows how certificate may be requested and downloaded from CA
```

## Compilation

### Dependencies

CURL: https://github.com/curl/curl

OpenSSL: https://github.com/openssl/openssl version 1.1 or later

LibJWT: https://github.com/benmcollins/libjwt version 1.12 or later

LibKS: https://github.com/signalwire/libks

Signalwire Personal Access Token: https://freeswitch.org/confluence/display/FREESWITCH/HOWTO+Create+a+SignalWire+Personal+Access+Token

Packages for latest libks and libjwt which are required are available in the freeswitch package repositories:

Debian 10:
```
TOKEN=YOURSIGNALWIRETOKEN
apt-get update && apt-get install -y gnupg2 wget lsb-release
wget --http-user=signalwire --http-password=$TOKEN -O /usr/share/keyrings/signalwire-freeswitch-repo.gpg https://freeswitch.signalwire.com/repo/deb/debian-release/signalwire-freeswitch-repo.gpg
 
echo "machine freeswitch.signalwire.com login signalwire password $TOKEN" > /etc/apt/auth.conf
echo "deb [signed-by=/usr/share/keyrings/signalwire-freeswitch-repo.gpg] https://freeswitch.signalwire.com/repo/deb/debian-release/ `lsb_release -sc` main" > /etc/apt/sources.list.d/freeswitch.list
echo "deb-src [signed-by=/usr/share/keyrings/signalwire-freeswitch-repo.gpg] https://freeswitch.signalwire.com/repo/deb/debian-release/ `lsb_release -sc` main" >> /etc/apt/sources.list.d/freeswitch.list
apt-get update && apt-get install -y automake autoconf libtool pkg-config libcurl4-openssl-dev libjwt-dev libks
```

Mac:
```
brew install automake autoconf libtool pkg-config curl libjwt
brew install signalwire/signalwire/libks
```

### Build from source

Example Dockerfiles to build FreeSWITCH and dependencies from source:
  * https://github.com/signalwire/libstirshaken/tree/master/docker/examples

### Build

```
./bootstrap.sh
./configure
make
```


### Install

```
sudo make install
```

In case of troubles with build see Troubleshooting.


### Test

Test suite can be executed with

```
make check
```

command in main folder. There is one special test (13) which tests it all,

it runs the complete process of SP obtaining STI cert from CA. By default this test will mock CA process and HTTP transfers,

but it can also be tested with real CA running and HTTP transfers executed, for this run test with 'nomock' argument.

It will download STI cert from CA, given you run it somewhere with reference data, e.g:

	./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA Test" --serial 1 --expiry 9999 --ca_cert test/ref/ca/ca.pem --uri "https://ca.shaken.signalwire.cloud/sti-ca/acme/TNAuthList" --pa_cert test/ref/pa/pa.pem --vvv

	CA can be configured with SSL:
		./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 9999 --ca_cert test/ref/ca/ca.pem --uri "TNAuthList(URI)" --pa_cert test/ref/pa/pa.pem --ssl --ssl_cert fullchain.cer --ssl_key key.pem --vvv


### Examples

You can find very compressed and useful examples of library usages in 'examples' folder. If you would like to learn more, probably 'util' folder with 'stirshaken' program would be very helpful as most of this library's functionalities are exposed through it.
Simply run ./stirshaken to start:

```
root@deb9:~/projects/libstirshaken# ./stirshaken

usage:	 /root/projects/libstirshaken/.libs/stirshaken command



Where command is one of:

		 keys --pubkey pub.pem --privkey priv.pem
		 csr --privkey key --pubkey key --subject_c C --subject_cn CN --spc CODE -f csrName
		 cert --type CA --privkey key --pubkey key --issuer_c C --issuer_cn CN --serial SERIAL --expiry EXPIRY -f certName
		 cert --type SP --privkey key --pubkey key --issuer_c C --issuer_cn CN --serial SERIAL --expiry EXPIRY --ca_cert ca.pem --csr csr.pem --uri TNAuthList(URI) -f certName
		 hash -f certName
		 spc-token --privkey key --url x5u_URL --spc CODE --issuer_cn CN -f spc_token_file_name
		 jwt-key-check --jwt token --pubkey key
		 jwt-check --jwt token [--cert_path_check --ca_dir ca_dir] [--timeout timeout_in_seconds]
		 jwt-dump --jwt token
		 ca --port 80 --privkey key --issuer_c C --issuer_cn CN --serial SERIAL --expiry EXPIRY --ca_cert ca.pem --uri TNAuthList(URI) --pa_cert pa.pem --pa_dir padir
		 pa --port 80
		 sp-spc-req --url URL --port port
		 sp-cert-req --url URL --port port --privkey key --pubkey key --csr csr.pem --spc CODE --spc_token SPC_TOKEN -f CERT_NAME
		 passport-create --privkey key --url x5u_URL --attest attestation_level --origtn origtn --desttn desttn --origid origid -f passport_file_name
		 version

		 Each command accepts setting print/logging verbosity level:
		 --v		basic logging
		 --vv		medium logging
		 --vvv		high logging

		 CA can be configured with HTTPS by setting up SSL cert and key with:
			 --ssl --ssl_cert cert.pem --ssl_key key.pem

		 SSL/HTTPS is supported, simply use 'https://' instead of 'http://' whenever you need encryption (default port for HTTPS is 443)

		 keys			: generate key pair
		 csr			: generate X509 certificate request for SP identified by SP Code given to --spc
		 cert			: generate X509 certificate (end entity for --type SP and self-signed for --type CA)
		 hash			: save CA certificate under hashed name (in this form it can be put into CA dir)
		 spc-token		: generate SPC token for SP identified by SP Code given to --spc (set token's PA issuer to name given as --issuer_cn, and token's x5u URL of the PA certificate to URL given as --url)
		 jwt-key-check		: decode JWT and verify signature using public key given to --pubkey
		 jwt-check		: decode JWT and verify signature using certificate referenced in 'x5u' header (involves HTTP(S) GET request), optionally execute X509 certificate path check against trusted root CA certificates
		 jwt-dump		: decode JWT and print it (do not verify signature)
		 ca			: run CA service on port given to --port and accepting tokens issued by trusted PAs (trusted PAs are ones that match public key embedded in cert given to --pa_cert or those whose certificate can be linked to trusted PA roots by X509 cert path check procedure using certs from the folder given to --pa_dir, options --pa_cert and --pa_dir are independent). Use "--ssl --ssl_cert cert.pem --ssl_key key.pem" for HTTPS
		 pa			: run PA service on port given to --port
		 sp-spc-req		: request SP Code token from PA at url given to --url
		 sp-cert-req		: request SP certificate for Service Provider identified by number given to --spc from CA at url given to --url on port given to --port
		 passport-create	: generate PASSporT with x5u pointing to given URL, with given attestation level, origination and destination telephone numbers and with given reference, and sign it using specified private key
		 version		: print the library version (git hash of the most recent commit)
```

### Helpful commands from SSL

```
openssl req -in csr.pem -text -noout
openssl x509 -in sp.pem -text -noout
openssl x509 -hash -noout -in ca.pem

openssl pkey -in priv.pem -pubout -outform pem | sha256sum
openssl x509 -in cert.pem -pubkey -noout -outform pem | sha256sum
openssl req -in csr.pem -pubkey -noout -outform pem | sha256sum
openssl verify -verbose -CAfile test/ref/ca/ca.pem sp.pem
```

### Some commands to get you started

./stirshaken keys --privkey priv.key --pubkey pub.key

./stirshaken csr --privkey priv.key --pubkey pub.key --spc 12 --subject_c US --subject_cn "New SP" -f csr.pem

sudo ./stirshaken ca --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 --ca_cert test/ref/ca/ca.pem --uri https://ca.shaken.signalwire.cloud/sti-ca/authority-over-the-number-check --vvv

./stirshaken ca --port 8756 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 1000 --ca_cert test/ref/ca/ca.pem --uri https://ca.shaken.signalwire.cloud/api --v

./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 9999 --ca_cert test/ref/ca/ca.pem --uri "TNAuthList(URI)" --pa_cert test/ref/pa/pa.pem --vvv

./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 9999 --ca_cert test/ref/ca/ca.pem --uri "TNAuthList(URI)" --pa_cert test/ref/pa/pa.pem --ssl -ssl_cert cert.pem --ssl_key key.pem --vvv

./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 9999 --ca_cert test/ref/ca/ca.pem --uri "TNAuthList(URI)" --pa_cert test/ref/pa/pa.pem --pa_dir rootpax509 --ssl --ssl_cert fullchain.cer --ssl_key key.pem --vvv

./stirshaken passport-create --privkey test/ref/pa/pa.priv --url https://sp.shaken.signalwire.cloud/sp.pem -attest B --origtn +48599800700 --desttn +447267888999 --origid REF200500 -f passport_ssl.txt

nohup sudo ./stirshaken ca --port 8082 --privkey test/ref/ca/ca.priv --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 --ca_cert test/ref/ca/ca.pem --uri https://190.102.98.199/sti-ca/authority-over-the-number-check/1 --vvv 2> /var/log/ca.err > /var/log/ca.log &

./stirshaken sp-cert-req --url https://localhost/sti-ca/acme/cert --privkey priv.key --pubkey pub.key --csr csr.pem --spc 12 --spc_token SPCT --v

./stirshaken cert --type CA --privkey test/ref/ca/ca.priv --pubkey test/ref/ca/ca.pub --issuer_c US --issuer_cn "SignalWire STI-CA" --serial 1 --expiry 10000 -f test/ref/ca/ca.pem -v

./stirshaken cert --type SP --privkey priv.key --pubkey pub.key --issuer_c US --issuer_cn "Trusted CA" --serial 3 --expiry 2 --ca_cert ca.pem --csr csr.pem --uri "https://ca.com/api" -f sp.pem

./stirshaken cert --type PA --privkey test/ref/pa/pa.priv --pubkey test/ref/pa/pa.pub --issuer_c US --issuer_cn "SignalWire STI-PA" --serial 1 --expiry 1000 -f test/ref/pa/pa.pem

./stirshaken spc-token --privkey pa_priv.pem --url https://pa.com --spc 7889 --issuer_cn "SignalWire STI-PA" -f spc_token.txt --vvv

./stirshaken spc-token --privkey test/ref/pa/pa.priv --url https://pa.shaken.signalwire.cloud/pa.pem --spc 1 --issuer_cn "SignalWire STI-PA" -f spc_token_1.txt --vvv

./stirshaken jwt-check --jwt eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyJBbGljZSJdfSwiaWF0IjoxNjE1OTM2MjQ1LCJvcmlnIjp7InRuIjoiQm9iIn0sIm9yaWdpZCI6ImUzMmY0MTg5LWNiODYtNDYwZi1iYjkyLWJkM2FjYjg5ZjI5YyJ9.jJSEUTpKlBuSGT_eoyWB6ngHl5J5OA0yAbDPMq8mjO1SkHaXxh8aL1oJ2Gl2qmqmMJNXMQeeA6KKZphensxljg --ca_dir test/ref/ca --vvv

Verify PASSporT without X509 cert path check:

./stirshaken jwt-check --jwt eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyJBbGljZSJdfSwiaWF0IjoxNjE1OTM2MjQ1LCJvcmlnIjp7InRuIjoiQm9iIn0sIm9yaWdpZCI6ImUzMmY0MTg5LWNiODYtNDYwZi1iYjkyLWJkM2FjYjg5ZjI5YyJ9.jJSEUTpKlBuSGT_eoyWB6ngHl5J5OA0yAbDPMq8mjO1SkHaXxh8aL1oJ2Gl2qmqmMJNXMQeeA6KKZphensxljg --vvv

Verify PASSporT with X509 cert path check:

./stirshaken jwt-check --jwt eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyJBbGljZSJdfSwiaWF0IjoxNjE1OTM2MjQ1LCJvcmlnIjp7InRuIjoiQm9iIn0sIm9yaWdpZCI6ImUzMmY0MTg5LWNiODYtNDYwZi1iYjkyLWJkM2FjYjg5ZjI5YyJ9.jJSEUTpKlBuSGT_eoyWB6ngHl5J5OA0yAbDPMq8mjO1SkHaXxh8aL1oJ2Gl2qmqmMJNXMQeeA6KKZphensxljg --cert_path_check --ca_dir test/ref/ca --vvv

Verify PASSporT with X509 cert path check and put 1 second timeout on HTTPS connection to be established:

./stirshaken jwt-check --jwt eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9zcC5wZW0ifQ.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0biI6WyJBbGljZSJdfSwiaWF0IjoxNjE1OTM2MjQ1LCJvcmlnIjp7InRuIjoiQm9iIn0sIm9yaWdpZCI6ImUzMmY0MTg5LWNiODYtNDYwZi1iYjkyLWJkM2FjYjg5ZjI5YyJ9.jJSEUTpKlBuSGT_eoyWB6ngHl5J5OA0yAbDPMq8mjO1SkHaXxh8aL1oJ2Gl2qmqmMJNXMQeeA6KKZphensxljg --cert_path_check --ca_dir test/ref/ca --timeout 1 --vvv

./stirshaken jwt-key-check --jwt "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL2phenpjaGF0LnBsL3BhLnBlbSJ9.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMTAxIiwidHlwZSI6InNwYy10b2tlbiJ9.PGNPGieDuNIhxtpLFUPwS0qyy61_iW4hNqyio-jeSn8o8d7zgLW1SsQ6JFNB4txR8cW-99mKO1fO7qmSrbOAOw" --pubkey test/ref/pa/pa.pub --vvv

./stirshaken jwt-dump --jwt "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL2phenpjaGF0LnBsL3BhLnBlbSJ9.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMTAxIiwidHlwZSI6InNwYy10b2tlbiJ9.PGNPGieDuNIhxtpLFUPwS0qyy61_iW4hNqyio-jeSn8o8d7zgLW1SsQ6JFNB4txR8cW-99mKO1fO7qmSrbOAOw" --vvv

./stirshaken sp-cert-req --url https://localhost/sti-ca/acme/cert --privkey priv.key --pubkey pub.key --csr csr.pem --spc 12 --spc_token SPCT --v

./stirshaken sp-cert-req --url https://ca.shaken.signalwire.cloud/sti-ca/acme/cert --port 8082 --privkey test/ref/sp/sp.priv --pubkey test/ref/sp/sp.pub --csr test/ref/sp/csr.pem --spc 1 --spc_token eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIFRlc3QiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL3BhLnNoYWtlbi5zaWduYWx3aXJlLmNvbS9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.Q2_oc3Ssd_Nz1Ex_B2nm8C8iiN9OzgxBRsljuEqkFdiEh5wkAHhqnQd54bITs2k4M6p9ePfRV5-8qtsXVkUp-Q -f sptest.pem --vvv


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


### Help

Any questions? Please let us know at: https://signalwire.community/
