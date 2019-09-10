#include "stir_shaken.h"

#define BUFSIZE 1024*8


static int stir_shaken_verify_data_with_cert(const char *data, size_t datalen, const unsigned char *signature, size_t siglen, stir_shaken_cert_t *cert)
{
    EVP_PKEY *pkey = NULL;

    // Get EVP_PKEY public key from cert
    if (!cert || !cert->x || !(pkey = X509_get_pubkey(cert->x))) {
        return -1;
    }

    return stir_shaken_do_verify_data(data, datalen, signature, siglen, pkey);
}


stir_shaken_status_t stir_shaken_verify_with_cert(const char *identity_header, stir_shaken_cert_t *cert)
{
    char *challenge = NULL;
    unsigned char signature[BUFSIZE] = {0};
    char *b = NULL, *e = NULL, *se = NULL, *sig = NULL;
    int len = 0, challenge_len = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

    if (!identity_header || !cert) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    
    // Identity header is in the form header_base64.payload_base64.signature_base64
    // (TODO docs do not say signature is Base64 encoded, but I do that)
    // Data (challenge) to verify signature is "header_base64.payload_base64"

    b = strchr(identity_header, '.');
    if (!b || (b + 1 == strchr(identity_header, '\0'))) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    e = strchr(b + 1, '.');
    if (!e || (e + 1 == strchr(identity_header, '\0'))) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    se = strchr(e + 1, ';');
    if (!se || (se + 1 == strchr(identity_header, '\0'))) {
        return STIR_SHAKEN_STATUS_FALSE;
    }

    len = e - identity_header;
    challenge_len = len;
    challenge = malloc(challenge_len);
    if (!challenge) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    memcpy(challenge, identity_header, challenge_len);
    
    len = se - e;
    sig = malloc(len);
    if (!sig) {
		goto fail;
    }
    memcpy(sig, e + 1, len);
    sig[len - 1] = '\0';

    len = stir_shaken_b64_decode(sig, (char*)signature, BUFSIZE); // decode signature from SIP Identity Header (cause we encode it Base64, TODO confirm, they don't Base 64 cause ES256 would produce ASCII maybe while our current signature is not printable and of different length, something is not right with our signature, oh dear),
    // alternatively we would do signature = stir_shaken_core_strdup(stir_shaken_globals.pool, e + 1);
    
    if (stir_shaken_verify_data_with_cert(challenge, challenge_len, signature, len - 1, cert) != 0) { // len - 1 cause _b64_decode appends '\0' and counts it
        goto fail;
    }

    status = STIR_SHAKEN_STATUS_OK;

fail:
	if (challenge) {
		free(challenge);
		challenge = NULL;
	}
	if (sig) {
		free(sig);
		sig = NULL;
	}
	return status;
}
