#include "stir_shaken.h"

#undef BUFSIZE
#define BUFSIZE 1024*8


stir_shaken_status_t stir_shaken_stisp_verify_stica_against_list(stir_shaken_context_t *ss, stir_shaken_cert_t *cert)
{
	if (!cert) return STIR_SHAKEN_STATUS_FALSE;
	return STIR_SHAKEN_STATUS_OK;
}

int stir_shaken_do_verify_data_file(stir_shaken_context_t *ss, const char *data_filename, const char *signature_filename, EVP_PKEY *public_key)
{
    BIO *in = NULL, *inp = NULL, *bmd = NULL, *sigbio = NULL, *bio_err = NULL;
    const EVP_MD    *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int r = -1, sanity = 5000;
    int siglen = 0, res = -1;
    unsigned char *buf = NULL;
    unsigned char *sigbuf = NULL;
    EVP_MD_CTX *ctx = NULL;

    const char      *digest_name = "sha256";
    int             i = 0;
	char			err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

	
	stir_shaken_clear_error(ss);

    if (!data_filename || !signature_filename || !public_key) {
        goto err;
    }

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    buf = malloc(BUFSIZE);
    if (!buf) {
        goto err;
    }
    memset(buf, 0, BUFSIZE);
    
    md = EVP_get_digestbyname(digest_name);
    if (!md) {
        
		sprintf(err_buf, "Cannot get %s digest", digest_name);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        goto err;
    }
    
    in = BIO_new(BIO_s_file());
    bmd = BIO_new(BIO_f_md());
    if ((in == NULL) || (bmd == NULL)) {
        
		sprintf(err_buf, "Cannot get SSL'e BIOs...");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        goto err;
    }

    if (!BIO_get_md_ctx(bmd, &mctx)) {
        
		sprintf(err_buf, "Error getting message digest context");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        goto err;
    }

    r = EVP_DigestVerifyInit(mctx, &pctx, md, NULL, public_key);
    if (!r) {
        
		sprintf(err_buf, "Error setting context");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        goto err;
    }
    
    sigbio = BIO_new_file(signature_filename, "rb");
    if (sigbio == NULL) {
        
		sprintf(err_buf, "Error opening signature file");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        goto err;
    }
    siglen = EVP_PKEY_size(public_key);
    sigbuf = malloc(siglen);
    siglen = BIO_read(sigbio, sigbuf, siglen);
    BIO_free(sigbio);
    if (siglen <= 0) {
        
		sprintf(err_buf, "Error reading signature");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        //ERR_print_errors(bio_err);
        goto err;
    }

    inp = BIO_push(bmd, in);
    
    if (BIO_read_filename(in, data_filename) <= 0) {
        
		// TODO remove
		sprintf(err_buf, "Error reading data file");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        //ERR_print_errors(bio_err);
        goto err;
    }

    // Do fp

    for (;sanity--;) {
        i = BIO_read(inp, (char *)buf, BUFSIZE);
        if (i < 0) {
            
			// TODO remove
			sprintf(err_buf, "Read Error");
			stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
            //ERR_print_errors(bio_err);
            goto err;
        }
        if (i == 0) {
            break;
        }
    }
    BIO_get_md_ctx(inp, &ctx);
    i = EVP_DigestVerifyFinal(ctx, sigbuf, (unsigned int)siglen);
    if (i > 0) {
		
		// OK
        res = 0;

    } else if (i == 0) {
		
        sprintf(err_buf, "Signature/data-key failed verification (signature doesn't match the data-key pair)");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER); 
        res = 1;

    } else {
		
        sprintf(err_buf, "Unknown error while verifying data");
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL); 
        res = 2;
        //ERR_print_errors(bio_err);

    }

    if (buf) {
        free(buf);
    }
    if (sigbuf) {
        free(sigbuf);
    }
    if (bio_err) {
        BIO_free(bio_err);
    }
    if (in) {
        BIO_free(in);
    }
    if (bmd) {
        BIO_free(bmd);
    }
    return res;

err:
    if (sigbuf) {
        free(sigbuf);
    }
    if (buf) {
        free(buf);
    }
    if (bio_err) {
        BIO_free(bio_err);
    }
    if (in) {
        BIO_free(in);
    }
    if (bmd) {
        BIO_free(bmd);
    }
    return -1;
}


static int stir_shaken_verify_data_with_cert(stir_shaken_context_t *ss, const char *data, size_t datalen, const unsigned char *signature, size_t siglen, stir_shaken_cert_t *cert)
{
    EVP_PKEY *pkey = NULL;
	int ret = -1;


	stir_shaken_clear_error(ss);

    // Get EVP_PKEY public key from cert
    if (!cert || !cert->x || !(pkey = X509_get_pubkey(cert->x))) {
		stir_shaken_set_error(ss, "Verify data with cert: Bad params", STIR_SHAKEN_ERROR_GENERAL);
        return -1;
    }

    ret = stir_shaken_do_verify_data(ss, data, datalen, signature, siglen, pkey);
	EVP_PKEY_free(pkey);
	return ret;
}


stir_shaken_status_t stir_shaken_verify_with_cert(stir_shaken_context_t *ss, const char *identity_header, stir_shaken_cert_t *cert)
{
    char *challenge = NULL;
    unsigned char signature[BUFSIZE] = {0};
    char *b = NULL, *e = NULL, *se = NULL, *sig = NULL;
    int len = 0, challenge_len = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_ERR;


	stir_shaken_clear_error(ss);

    if (!identity_header || !cert) {
		
		stir_shaken_set_error(ss, "Verify with cert: Bad params", STIR_SHAKEN_ERROR_GENERAL);
        return status;
    }
    
    // Identity header is in the form header_base64.payload_base64.signature_base64
    // (TODO docs do not say signature is Base64 encoded, but I do that)
    // Data (challenge) to verify signature is "header_base64.payload_base64"

    b = strchr(identity_header, '.');
    if (!b || (b + 1 == strchr(identity_header, '\0'))) {
		
		stir_shaken_set_error(ss, "Verify with cert: Invalid SIP Identity Header: Missing dot separating header/payload", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		return STIR_SHAKEN_STATUS_FALSE;
    }

    e = strchr(b + 1, '.');
    if (!e || (e + 1 == strchr(identity_header, '\0'))) {
		
		stir_shaken_set_error(ss, "Verify with cert: Invalid SIP Identity Header: Missing dot separating payload/signature", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		return STIR_SHAKEN_STATUS_FALSE;
    }

    se = strchr(b + 1, ';');
    if (!se || e > se || (se + 1 == strchr(identity_header, '\0'))) {
		
		stir_shaken_set_error(ss, "Verify with cert: Invalid SIP Identity Header: Missing dot separating header/payload or no colon terminating signature", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		return STIR_SHAKEN_STATUS_FALSE;
    }

    len = e - identity_header;
    challenge_len = len;
    challenge = malloc(challenge_len);
    if (!challenge) {
		
		stir_shaken_set_error(ss, "Verify with cert: Out of memory", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_ERR;
    }
    memcpy(challenge, identity_header, challenge_len);
    
    len = se - e;
    sig = malloc(len);
    if (!sig) {
		
		stir_shaken_set_error(ss, "Verify with cert: Out of memory", STIR_SHAKEN_ERROR_GENERAL);
		status = STIR_SHAKEN_STATUS_ERR;
		goto fail;
    }
    memcpy(sig, e + 1, len);
    sig[len - 1] = '\0';

    len = stir_shaken_b64_decode(sig, (char*)signature, BUFSIZE); // decode signature from SIP Identity Header (cause we encode it Base64, TODO confirm, they don't Base 64 cause ES256 would produce ASCII maybe while our current signature is not printable and of different length, something is not right with our signature, oh dear),
    // alternatively we would do signature = stir_shaken_core_strdup(stir_shaken_globals.pool, e + 1);
    
    if (stir_shaken_verify_data_with_cert(ss, challenge, challenge_len, signature, len - 1, cert) != 0) { // len - 1 cause _b64_decode appends '\0' and counts it
		
		stir_shaken_set_error_if_clear(ss, "Verify with cert: SIP Identity Header is spoofed", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		status = STIR_SHAKEN_STATUS_FALSE;
    
	} else {
		
		status = STIR_SHAKEN_STATUS_OK;
	}

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

/*
 * @jwt_encoded - (out) buffer for encoded JWT
 * @jwt_encoded_len - (in) buffer length
 */
static stir_shaken_status_t stir_shaken_jwt_sih_to_jwt_encoded(stir_shaken_context_t *ss, const char *identity_header, unsigned char *jwt_encoded, int jwt_encoded_len)
{
	char *p = NULL;
	int len = 0;


	if (!identity_header) return STIR_SHAKEN_STATUS_TERM;
    
	p = strchr(identity_header, ';');
	if (!p) {

		stir_shaken_set_error(ss, "Sih to jwt: Invalid PASSporT token, ';' not found", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	len = p - identity_header + 1;

	if (len > jwt_encoded_len) {

		stir_shaken_set_error(ss, "Sih to jwt: buffer for encoded JWT too short", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	memcpy(jwt_encoded, identity_header, len);
	jwt_encoded[len - 1] = '\0';

	return STIR_SHAKEN_STATUS_OK;
}

/*
 * PASSporT veerification.
 *
 * @passport - (in/out) should point to memory prepared for new PASSporT,
 *				on exit retrieved and verified PASSporT JWT is moved into that @passport
 * @stica_array - if not NULL then validate the root of the digital signature in the STI certificate
 *				by determining whether the STI-CA that issued the STI certificate is in the list of approved STI-CAs
 */ 
stir_shaken_status_t stir_shaken_jwt_verify_with_cert(stir_shaken_context_t *ss, const char *identity_header, stir_shaken_cert_t *cert, stir_shaken_jwt_passport_t *passport, cJSON *stica_array)
{
	unsigned char key[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	unsigned char jwt_encoded[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int key_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;
	jwt_t *jwt = NULL;

	if (!identity_header || !cert) return STIR_SHAKEN_STATUS_TERM;

	if (stir_shaken_jwt_sih_to_jwt_encoded(ss, identity_header, &jwt_encoded[0], STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN) != STIR_SHAKEN_STATUS_OK) {

		stir_shaken_set_error_if_clear(ss, "Failed to parse encoded PASSporT (SIP Identity Header) into encoded JWT", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stica_array) {

		// Validate the root of the digital signature in the STI certificate
		// by determining whether the STI-CA that issued the STI certificate is in the list of approved STI-CAs
		if (stir_shaken_stisp_verify_stica(ss, cert, stica_array) != STIR_SHAKEN_STATUS_OK) {

			stir_shaken_set_error(ss, "STI-CA is not in a trusted list of approved STI-CAs", STIR_SHAKEN_ERROR_STICA_NOT_APPROVED);
			return STIR_SHAKEN_STATUS_FALSE;
		}
	}

	// Get raw public key from cert
	if (stir_shaken_get_pubkey_raw_from_cert(ss, cert, key, &key_len) != STIR_SHAKEN_STATUS_OK) {

		stir_shaken_set_error_if_clear(ss, "Failed to get public key in raw format from remote STI-SP certificate", STIR_SHAKEN_ERROR_SSL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (jwt_decode(&jwt, jwt_encoded, key, key_len)) {

		stir_shaken_set_error_if_clear(ss, "JWT did not pass verification", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		jwt_free(jwt);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	stir_shaken_jwt_move_to_passport(jwt, passport);

	// Validate headers and grants in PASSporT
	return stir_shaken_jwt_passport_validate(ss, passport);
}

static size_t curl_callback(void *contents, size_t size, size_t nmemb, void *p)
{
	char *m = NULL;
	size_t realsize = size * nmemb;
	mem_chunk_t *mem = (mem_chunk_t *) p;

	
	stir_shaken_clear_error(mem->ss);

	// TODO remove
	printf("STIR-Shaken: CURL: Download progress: got %zu bytes (%zu total)\n", realsize, realsize + mem->size);

	m = realloc(mem->mem, mem->size + realsize + 1);
	if(!m) {
		stir_shaken_set_error(mem->ss, "realloc returned NULL", STIR_SHAKEN_ERROR_GENERAL);
		return 0;
	}

	mem->mem = m;
	memcpy(&(mem->mem[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->mem[mem->size] = 0;

	return realsize;
}

stir_shaken_status_t stir_shaken_download_cert(stir_shaken_context_t *ss, const char *url, mem_chunk_t *chunk)
{
	CURL *curl_handle = NULL;
	CURLcode res = 0;
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	char			err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	
	
	stir_shaken_clear_error(ss);

	chunk->mem = malloc(1);
	chunk->size = 0;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)chunk);

	// Some pple say, some servers don't like requests that are made without a user-agent field, so we provide one.
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "freeswitch-stir-shaken/1.0");

	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK) {
		
		sprintf(err_buf, "Download: Error in CURL: %s", curl_easy_strerror(res));
		
		if (res == CURLE_COULDNT_RESOLVE_HOST || res == CURLE_COULDNT_RESOLVE_PROXY || res == CURLE_COULDNT_CONNECT || res != CURLE_REMOTE_ACCESS_DENIED) {
			
			// Cannot access
			stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);

		} else {

			// All other erros
			stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_CURL);
		}
	
		// Only curl_easy_cleanup in case of error, cause otherwise (if also curl_global_cleanup) SSL starts to mulfunction ???? (EVP_get_digestbyname("sha256") in stir_shaken_do_verify_data returns NULL)
		curl_easy_cleanup(curl_handle);
        return STIR_SHAKEN_STATUS_FALSE;

	} else {

		// TODO remove
		printf("Download: Got %zu bytes\n", chunk->size);
        status = STIR_SHAKEN_STATUS_OK;
	}

	curl_easy_cleanup(curl_handle);
	curl_global_cleanup();

	return status;
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

stir_shaken_status_t stir_shaken_download_cert_to_file(const char *url, const char *file)
{
	CURL *curl;
	FILE *fp;
	CURLcode res = CURLE_FAILED_INIT;
	curl = curl_easy_init();
	if (curl) {
		fp = fopen(file,"wb");
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		res = curl_easy_perform(curl);
		/* always cleanup */
		curl_easy_cleanup(curl);
		fclose(fp);
	}

	if (res != CURLE_OK) {
		return STIR_SHAKEN_STATUS_FALSE;
	}
	return STIR_SHAKEN_STATUS_OK;
}

// 5.3.1 PASSporT & Identity Header Verification
// The certificate referenced in the info parameter of the Identity header field shall be validated by performing the
// following:
// - Check the certificate's validity using the Basic Path Validation algorithm defined in the X.509
// certificate standard (RFC 5280).
// - Check that the certificate is not revoked using CRLs and/or OCSP.
// The verifier validates that the PASSporT token provided in the Identity header of the INVITE includes all of the
// baseline claims, as well as the SHAKEN extension claims. The verifier shall also follow the draft-ietf-stir-
// rfc4474bis-defined verification procedures to check the corresponding date, originating identity (i.e., the
// originating telephone number) and destination identities (i.e., the terminating telephone numbers).
// The orig claim and dest claim shall be of type tn.
//
// The orig claim tn value validation shall be performed as follows:
// - The P-Asserted-Identity header field value shall be checked as the telephone identity to be validated if
// present, otherwise the From header field value shall also be checked.
// - If there are two P-Asserted-Identity values, the verification service shall check each of them until it finds
// one that is valid.
// NOTE: As discussed in draft-ietf-stir-rfc4474bis, call features such as call forwarding can cause calls to reach a
// destination different from the number in the To header field. The problem of determining whether or not these call
// features or other B2BUA functions have been used legitimately is out of scope of STIR. It is expected that future
// SHAKEN documents will address these use cases.
//
//
// ERRORS
// ======
// There are five main procedural errors defined in draft-ietf-stir-rfc4474bis that can identify issues with the validation
// of the Identity header field. The error conditions and their associated response codes and reason phrases are as
// follows:
// 403 Stale Date - Sent when the verification service receives a request with a Date header field value
// that is older than the local policy 3 for freshness permits. The same response may be used when the "iat"
// has a value older than the local policy for freshness permits.
// 428 'Use Identity Header' is not recommended for SHAKEN until a point where all calls on the VoIP
// network are mandated to be signed either by local or global policy.
// 436 'Bad-Identity-Info' - The URI in the info parameter cannot be dereferenced (i.e., the request times
// out or receives a 4xx or 5xx error).
// 437 'Unsupported credential' - This error occurs when a credential is supplied by the info parameter
// but the verifier doesntt support it or it doesn't contain the proper certificate chain in order to trust the
// credentials.
// 438 Invalid Identity Header -  This occurs if the signature verification fails.
// If any of the above error conditions are detected, the terminating network shall convey the response code and
// reason phrase back to the originating network, indicating which one of the five error scenarios has occurred. How
// this error information is signaled to the originating network depends on the disposition of the call as a result of the
// error. If local policy dictates that the call should not proceed due to the error, then the terminating network shall
// include the error response code and reason phrase in the status line of a final 4xx error response sent to the
// originating network. On the other hand, if local policy dictates that the call should continue, then the terminating
// network shall include the error response code and reason phrase in a Reason header field (defined in [RFC
// 3326]) in the next provisional or final response sent to the originating network as a result of normal terminating
// call processing.
// Example of Reason header field:
// Reason: SIP ;cause=436 ;text="Bad Identity Info"
// In addition, if any of the base claims or SHAKEN extension claims are missing from the PASSporT token claims,
// the verification service shall treat this as a 438 Invalid Identity Header error and proceed as defined above.

stir_shaken_status_t stir_shaken_verify(stir_shaken_context_t *ss, const char *sih, const char *cert_url, stir_shaken_jwt_passport_t *passport, cJSON *stica_array, stir_shaken_cert_t **cert_out)
{
	stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_FALSE;
	char					err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	stir_shaken_http_req_t	http_req = { 0 };
	long					res = CURLE_OK;
	stir_shaken_cert_t		*cert = NULL;
	
	stir_shaken_clear_error(ss);
	
	if (!sih) {
		stir_shaken_set_error(ss, "Verify: SIP Identity Header not set", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		goto fail;
	}
	
	if (!cert_url) {
		stir_shaken_set_error(ss, "Verify: Cert URL not set", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
		goto fail;
	}

	if (!passport) {
		stir_shaken_set_error(ss, "Verify: PASSporT not set", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	if (!cert_out) {
		stir_shaken_set_error(ss, "Verify: Cert (out) not set", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	cert = malloc(sizeof(stir_shaken_cert_t));
	if (!cert) {
		goto fail;
	}

	memset(cert, 0, sizeof(stir_shaken_cert_t));

	// TODO remove
	printf("STIR-Shaken: Verify: cert URL is: %s\n", cert_url);

	// Download cert

	// TODO remove
	printf("STIR-Shaken: Verify: downloading cert...\n");

	memset(&http_req, 0, sizeof(http_req));

	// Download cert of the STI-SP claiming to athenticate this call
	if (stir_shaken_make_http_get_req(ss, &http_req, cert_url) != STIR_SHAKEN_STATUS_OK) {

		sprintf(err_buf, "Verify: Failed to download certificate using URL: %s", cert_url);

		// On fail, http_req->response.code is CURLcode
		res = http_req.response.code;
		
		if (res == CURLE_COULDNT_RESOLVE_HOST || res == CURLE_COULDNT_RESOLVE_PROXY || res == CURLE_COULDNT_CONNECT || res != CURLE_REMOTE_ACCESS_DENIED) {
			
			// Cannot access
			sprintf(err_buf, "Verify: Cannot connect to URL: %s", cert_url);
			stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);

		} else if (res == CURLE_REMOTE_ACCESS_DENIED) {

			// Access denied
			sprintf(err_buf, "Verify: Access denied for URL: %s", cert_url);
			stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_CURL);

		} else {

			// All other erros
			sprintf(err_buf, "Verify: Failed to download certificate using URL: %s", cert_url);
			stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_CURL);
		}

		goto fail;

	} else {

		// On success, http_req->response.code is HTTP response code (200, 403, 404, etc...)
		res = http_req.response.code;

		// TODO remove
		printf("Download: Got %zu bytes\n", http_req.response.mem.size);
		printf("Got response to download cert request:\ncode:\t%ld\ndata:\t%s\n", http_req.response.code, http_req.response.mem.mem);

		switch (res) {

			case 200:

				// TODO remove
				printf("HTTP 200 OK\n");
				break;

			case 403:
				stir_shaken_set_error(ss, "HTTP 403 Forbidden", STIR_SHAKEN_ERROR_HTTP_403_FORBIDDEN);
				goto fail;

			case 404:
			default:
				stir_shaken_set_error(ss, "HTTP 404 Invalid request", STIR_SHAKEN_ERROR_HTTP_404_INVALID);
				goto fail;
		}
	}

	// Load into X509

	// TODO remove
	printf("STIR-Shaken: Verify: loading cert from memory into X509...\n");

    if (stir_shaken_load_cert_from_mem(ss, &cert->x, http_req.response.mem.mem, http_req.response.mem.size) != STIR_SHAKEN_STATUS_OK) {
	
		stir_shaken_set_error_if_clear(ss, "Verify: error while loading cert from memory", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
    }

	// TODO copy cert into cert.body
	cert->body = malloc(http_req.response.mem.size);
	if (!cert->body) {
	
		stir_shaken_set_error(ss, "Verify: out of memory", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	memcpy(cert->body, http_req.response.mem.mem, http_req.response.mem.size);
	cert->len = http_req.response.mem.size;

	// Parse X509 representation of cert into char/int variables
	if (stir_shaken_read_cert_fields(ss, cert) != STIR_SHAKEN_STATUS_OK) {

		goto fail;
	}

	// Verify root of certificate
	if (stir_shaken_verify_cert_root(ss, cert) != STIR_SHAKEN_STATUS_OK) {

		goto fail;
	}

	// TODO Handle STIR_SHAKEN_ERROR_SIP_403_STALE_DATE
	
	// TODO remove
	printf("STIR-Shaken: Verify: checking SIH signature with cert...\n");

	ss_status = stir_shaken_jwt_verify_with_cert(ss, sih, cert, passport, stica_array);
	
	switch (ss_status) {
	   
		case STIR_SHAKEN_STATUS_OK:

			// Passed
			break;

		case STIR_SHAKEN_STATUS_FALSE:
			
			// Didn't pass
			// Cannot download referenced certificate or caller didn't pass verification
			// Bad Identity Headers also end up here
			//
			// Error code will be set to one of:
			// STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER			- bad Identity Header, missing fields, malformed content, didn't pass the signature check, etc.
			// STIR_SHAKEN_ERROR_PASSPORT_INVALID							- bad Identity Header, specifically: PASSporT is missing some mandatory fields
			// STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO					- cannot download referenced certificate
			stir_shaken_set_error_if_clear(ss, "Verify: SIP Identity Header is spoofed", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
			goto fail;

		case STIR_SHAKEN_STATUS_ERR:
		default:
			
			// Error while verifying
			stir_shaken_set_error_if_clear(ss, "Verify: Error while processing request", STIR_SHAKEN_ERROR_GENERAL);
			goto fail;
	}

	// TODO remove
	printf("STIR-Shaken: Verify: PASS\n");
    
fail:

	// Release all memory used by http_req
	stir_shaken_destroy_http_request(&http_req);

	if (cert_out) {
	
		// Note, cert must be destroyed by caller
		*cert_out = cert;

	} else {

		stir_shaken_destroy_cert(cert);
		free(cert);
		cert = NULL;
	}

	return ss_status;
}
