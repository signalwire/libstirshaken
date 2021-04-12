#include "stir_shaken.h"
#include <curl/curl.h>

#undef BUFSIZE
#define BUFSIZE 1024*8


stir_shaken_status_t stir_shaken_basic_cert_check(stir_shaken_context_t *ss, stir_shaken_cert_t *cert)
{
	int version = -1;
	int res = 0;
	char					err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

	if (!cert) return STIR_SHAKEN_STATUS_TERM;

	version = stir_shaken_cert_get_version(cert);
	if (version < 1) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "Invalid STI cert: wrong version: %d", version);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_CERT_VERSION);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	res = X509_cmp_current_time(cert->notBefore_ASN1);
	if (res == 0) {
		stir_shaken_set_error(ss, "Error validating STI Cert's notBefore timestamp", STIR_SHAKEN_ERROR_SSL_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (res > 0) {
		stir_shaken_set_error(ss, "Invalid STI Certificate: (Not valid yet) notBefore timestamp ahead of now", STIR_SHAKEN_ERROR_CERT_NOT_VALID_YET);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	res = X509_cmp_current_time(cert->notAfter_ASN1);
	if (res == 0) {
		stir_shaken_set_error(ss, "Error validating STI Cert's notAfter timestamp", STIR_SHAKEN_ERROR_SSL_2);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (res < 0) {
		stir_shaken_set_error(ss, "Invalid STI Certificate: (Expired) notAfter timestamp has already passed", STIR_SHAKEN_ERROR_CERT_EXPIRED);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_vs_verify_stica_against_list(stir_shaken_context_t *ss, stir_shaken_cert_t *cert)
{
	if (!cert) return STIR_SHAKEN_STATUS_FALSE;
	return STIR_SHAKEN_STATUS_OK;
}

#if 0
static int stir_shaken_verify_data_with_cert(stir_shaken_context_t *ss, const char *data, size_t datalen, const unsigned char *signature, size_t siglen, stir_shaken_cert_t *cert)
{
	EVP_PKEY *pkey = NULL;
	int ret = -1;


	stir_shaken_clear_error(ss);

	// Get EVP_PKEY public key from cert
	if (!cert || !cert->x) {
		stir_shaken_set_error(ss, "Verify data with cert: Bad params", STIR_SHAKEN_ERROR_CERT_NOT_SET);
		return -1;
	}

	if (!(pkey = X509_get_pubkey(cert->x))) {
		stir_shaken_set_error(ss, "Verify data with cert: Bad params", STIR_SHAKEN_ERROR_PUBKEY_GET);
		return -1;
	}

	ret = stir_shaken_do_verify_data(ss, data, datalen, signature, siglen, pkey);
	EVP_PKEY_free(pkey);
	return ret;
}
#endif

/*
 * @jwt_encoded - (out) buffer for encoded JWT
 * @jwt_encoded_len - (in) buffer length
 */
static stir_shaken_status_t stir_shaken_jwt_sih_to_jwt_encoded(stir_shaken_context_t *ss, const char *identity_header, unsigned char *jwt_encoded, int jwt_encoded_len)
{
	char *p = NULL;
	int len = 0;


	if (!identity_header) {
		stir_shaken_set_error(ss, "Sih to jwt: PASSporT missing", STIR_SHAKEN_ERROR_PASSPORT_MISSING_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	p = strchr(identity_header, ';');
	if (!p) {
		stir_shaken_set_error(ss, "Sih to jwt: PASSporT malformed, ';' not found", STIR_SHAKEN_ERROR_PASSPORT_MALFORMED);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	len = p - identity_header + 1;

	if (len > jwt_encoded_len) {
		stir_shaken_set_error(ss, "Sih to jwt: buffer for encoded JWT too short", STIR_SHAKEN_ERROR_BUFFER_2);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	memcpy(jwt_encoded, identity_header, len);
	jwt_encoded[len - 1] = '\0';

	return STIR_SHAKEN_STATUS_OK;
}

#if 0
static size_t curl_callback(void *contents, size_t size, size_t nmemb, void *p)
{
	char *m = NULL;
	size_t realsize = size * nmemb;
	mem_chunk_t *mem = (mem_chunk_t *) p;


	fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "STIR-Shaken: CURL: Download progress: got %zu bytes (%zu total)\n", realsize, realsize + mem->size);

	m = realloc(mem->mem, mem->size + realsize + 1);
	if(!m) {
		stir_shaken_set_error(mem->ss, "Realloc returned NULL", STIR_SHAKEN_ERROR_MEM_REALLOC);
		return 0;
	}

	mem->mem = m;
	memcpy(&(mem->mem[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->mem[mem->size] = 0;

	return realsize;
}
#endif

stir_shaken_status_t stir_shaken_download_cert(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	if (!http_req) {
		stir_shaken_set_error(ss, "HTTP Req not set", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL not set. Set URL on HTTP request?", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_make_http_get_req(ss, http_req)) {
		stir_shaken_set_error(ss, "Cannot connect to URL", STIR_SHAKEN_ERROR_HTTP_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (http_req->response.code != 200 && http_req->response.code != 201) {
		stir_shaken_set_error(ss, "HTTP request rejected", STIR_SHAKEN_ERROR_HTTP_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_jwt_fetch_or_download_cert(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out, unsigned long connect_timeout_s)
{
	stir_shaken_status_t ss_status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_http_req_t http_req = { 0 };
	stir_shaken_cert_t *cert = NULL;
	const char *cert_url = NULL;
	jwt_t *jwt = NULL;

	if (!ss) {
		stir_shaken_set_error(ss, "Bad params: context missing", STIR_SHAKEN_ERROR_BAD_PARAMS_25);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (!token) {
		stir_shaken_set_error(ss, "Bad params: JWT token is missing", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO_2);
		goto fail;
	}

	if (!cert_out) {
		stir_shaken_set_error(ss, "Bad params: Pointer to result cert is NULL", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO_3);
		goto fail;
	}

	if (0 != jwt_decode(&jwt, token, NULL, 0)) {
		stir_shaken_set_error(ss, "Not a valid JWT (cannot be parsed into JSON)", STIR_SHAKEN_ERROR_JWT_INVALID_1);
		goto fail;
	}

	cert_url = jwt_get_header(jwt, "x5u");
	if (stir_shaken_zstr(cert_url)) {
		stir_shaken_set_error(ss, "SPC token is missing x5u, cannot download certificate", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
		goto fail;
	}

	cert = stir_shaken_cert_create();
	if (!cert) {
		stir_shaken_set_error(ss, "Cannot allocate cert", STIR_SHAKEN_ERROR_CERT_CREATE);
		goto fail;
	}

	// In order to get the certificate we execute the callback checking if caller wants to perform this verification with local cert,
	// because for instance, it could have been cached earlier. If the caller doesn't supply cert then we perform standard download over HTTP(S).

	if (!ss->callback) {
		ss->callback = stir_shaken_default_callback;
	}

	ss->callback_arg.action = STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY;
	strncpy(ss->callback_arg.cert.public_url, cert_url, STIR_SHAKEN_BUFLEN - 1);
	ss->callback_arg.cert.public_url[STIR_SHAKEN_BUFLEN - 2] = '\0';

	if (STIR_SHAKEN_STATUS_HANDLED == (ss->callback)(&ss->callback_arg)) {

		// Maybe fetched cert supplied by the caller

		if (!ss->callback_arg.cert.x) {
			stir_shaken_set_error(ss, "Caller returned STATUS_HANDLED for callback action STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY but no certificate. "
					"Return STATUS_NOT_HANDLED for callback action STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY if certificate should be downloaded, "
					"or return STATUS_HANDLED and load cert to callback's argument if pre-cached cert should be used", STIR_SHAKEN_ERROR_CALLBACK_ACTION_CERT_FETCH_ENQUIRY);
			goto fail;
		}

		if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_copy(ss, cert, &ss->callback_arg.cert)) {
			stir_shaken_set_error(ss, "Cannot copy certificate", STIR_SHAKEN_ERROR_CERT_COPY);
			goto fail;
		}
		stir_shaken_cert_deinit(&ss->callback_arg.cert);
		ss->cert_fetched_from_cache = 1;

	} else {

		// Download cert if it has not been supplied by the caller
		http_req.url = strdup(cert_url);
		http_req.connect_timeout_s = connect_timeout_s;

		jwt_free(jwt);
		jwt = NULL;

		ss_status = stir_shaken_download_cert(ss, &http_req);
		if (STIR_SHAKEN_STATUS_OK != ss_status) {
			stir_shaken_set_error(ss, "Cannot download certificate", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO_4);
			goto fail;
		}

		ss_status = stir_shaken_load_x509_from_mem(ss, &cert->x, &cert->xchain, http_req.response.mem.mem);
		if (STIR_SHAKEN_STATUS_OK != ss_status) {
			stir_shaken_set_error(ss, "Error while loading cert from memory", STIR_SHAKEN_ERROR_GENERAL);
			goto fail;
		}
	}

	// Note, cert must be destroyed by caller
	*cert_out = cert;

	if (jwt_out) {
		*jwt_out = jwt;
	} else {
		jwt_free(jwt);
		jwt = NULL;
	}

	stir_shaken_destroy_http_request(&http_req);

	return STIR_SHAKEN_STATUS_OK;

fail:

	stir_shaken_set_error_if_clear(ss, "Unknown error while verifying JWT", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);

	stir_shaken_cert_destroy(&cert);
	if (jwt) jwt_free(jwt);
	stir_shaken_destroy_http_request(&http_req);

	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_sih_verify_with_key(stir_shaken_context_t *ss, const char *identity_header, unsigned char *key, int key_len, stir_shaken_passport_t **passport_out)
{
	unsigned char jwt_encoded[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	jwt_t *jwt = NULL;

	if (!identity_header) {
		stir_shaken_set_error(ss, "Bad params (SIH missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_27);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (!key || !key_len) {
		stir_shaken_set_error(ss, "Bad params (key missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_28);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_jwt_sih_to_jwt_encoded(ss, identity_header, &jwt_encoded[0], STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "Failed to parse SIP Identity Header into encoded JWT", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO_5);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (jwt_decode(&jwt, (const char*) jwt_encoded, key, key_len)) {
		stir_shaken_set_error(ss, "JWT did not pass signature check", STIR_SHAKEN_ERROR_JWT_DECODE_3);
		jwt_free(jwt);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (passport_out) {

		stir_shaken_passport_t *passport = stir_shaken_passport_create(ss, NULL, NULL, 0);
		if (!passport) {
			stir_shaken_set_error(ss, "Failed to create PASSporT", STIR_SHAKEN_ERROR_PASSPORT_CREATE_2);
			return STIR_SHAKEN_STATUS_TERM;
		}

		if (!stir_shaken_jwt_move_to_passport(ss, jwt, passport)) {
			stir_shaken_set_error(ss, "Failed to assign JWT to PASSporT", STIR_SHAKEN_ERROR_SIH_JWT_MOVE_TO_PASSPORT_1);
			jwt_free(jwt);
			stir_shaken_passport_destroy(&passport);
			return STIR_SHAKEN_STATUS_FALSE;
		}

		*passport_out = passport;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_sih_verify_with_cert(stir_shaken_context_t *ss, const char *identity_header, stir_shaken_cert_t *cert, stir_shaken_passport_t **passport_out)
{
	unsigned char key[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int key_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;

	if (!cert) {
		stir_shaken_set_error(ss, "Bad params (cert missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_29);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_get_pubkey_raw_from_cert(ss, cert, key, &key_len) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error_if_clear(ss, "Failed to get public key in raw format from remote STI-SP certificate", STIR_SHAKEN_ERROR_GET_PUBKEY_RAW_FROM_CERT);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return stir_shaken_sih_verify_with_key(ss, identity_header, key, key_len, passport_out);
}

stir_shaken_status_t stir_shaken_jwt_check_signature(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out, unsigned long connect_timeout_s)
{
	stir_shaken_status_t ss_status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_cert_t *cert = NULL;
	jwt_t *jwt = NULL;
	unsigned char key[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int key_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;

	if (!ss) {
		stir_shaken_set_error(ss, "Bad params: context missing", STIR_SHAKEN_ERROR_BAD_PARAMS_26);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (!token) {
		stir_shaken_set_error(ss, "Bad params: JWT token is missing", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO_6);
		goto fail;
	}

	ss_status = stir_shaken_jwt_fetch_or_download_cert(ss, token, &cert, NULL, connect_timeout_s);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Failed to fetch or download certificate", STIR_SHAKEN_ERROR_CERT_FETCH_OR_DOWNLOAD);
		goto fail;
	}

	if (stir_shaken_get_pubkey_raw_from_cert(ss, cert, key, &key_len) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "Failed to get public key in raw format from certificate", STIR_SHAKEN_ERROR_SSL_4);
		goto fail;
	}

	if (jwt_decode(&jwt, token, key, key_len)) {
		stir_shaken_set_error(ss, "JWT did not pass signature check", STIR_SHAKEN_ERROR_JWT_DECODE_4);
		goto fail;
	}

	if (cert_out) {
		*cert_out = cert;
	} else {
		stir_shaken_cert_destroy(&cert);
	}

	if (jwt_out) {
		*jwt_out = jwt;
	} else {
		jwt_free(jwt);
	}

	return STIR_SHAKEN_STATUS_OK;

fail:

	stir_shaken_set_error_if_clear(ss, "Unknown error while verifying JWT", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);

	stir_shaken_cert_destroy(&cert);
	if (jwt) jwt_free(jwt);

	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_jwt_verify_ex(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out, X509_STORE *store, uint8_t check_x509_cert_path, unsigned long connect_timeout_s)
{
	stir_shaken_status_t ss_status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_cert_t *cert = NULL;
	jwt_t *jwt = NULL;
	stir_shaken_context_t ss_local = { 0 };

	if (!ss) ss = &ss_local;

	if (!token) {
		stir_shaken_set_error(ss, "Bad params: JWT token is missing", STIR_SHAKEN_ERROR_BAD_PARAMS_20);
		goto fail;
	}

	ss_status = stir_shaken_jwt_check_signature(ss, token, &cert, &jwt, connect_timeout_s);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "JWT did not pass verification", STIR_SHAKEN_ERROR_JWT_CHECK_SIGNATURE);
		ss->verification_status = STIR_SHAKEN_VERIFICATION_STATUS_BAD_PASSPORT;
		goto fail;
	}

	if (check_x509_cert_path) {

		if (ss) {
			ss->x509_cert_path_checked = 1;
		}

		ss_status = stir_shaken_read_cert_fields(ss, cert);
		if (STIR_SHAKEN_STATUS_OK != ss_status) {
			stir_shaken_set_error(ss, "Error parsing certificate", STIR_SHAKEN_ERROR_JWT_CERT_MALFORMED_1);
			goto fail_x509_cert_path_check;
		}

		ss_status = stir_shaken_basic_cert_check(ss, cert);
		if (STIR_SHAKEN_STATUS_OK != ss_status) {
			stir_shaken_set_error(ss, "Cert did not pass basic check (wrong version or expired)", STIR_SHAKEN_ERROR_JWT_CERT_INVALID_1);
			goto fail_x509_cert_path_check;
		}

		ss_status = stir_shaken_verify_cert_path(ss, cert, store);
		if (STIR_SHAKEN_STATUS_OK != ss_status) {
			stir_shaken_set_error(ss, "Cert did not pass X509 path validation", STIR_SHAKEN_ERROR_JWT_CERT_X509_PATH_INVALID_1);
			goto fail_x509_cert_path_check;
		}
	}

	if (jwt_out) {
		*jwt_out = jwt;
	} else {
		jwt_free(jwt);
		jwt = NULL;
	}

	if (cert_out) {
		// Note, cert must be destroyed by caller
		*cert_out = cert;
	} else {
		stir_shaken_cert_destroy(&cert);
	}

	return STIR_SHAKEN_STATUS_OK;

fail_x509_cert_path_check:

	ss->verification_status = STIR_SHAKEN_VERIFICATION_STATUS_BAD_CERTIFICATE;

fail:

	stir_shaken_cert_destroy(&cert);
	if (jwt) jwt_free(jwt);

	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_jwt_verify(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out, unsigned long connect_timeout_s)
{
	return stir_shaken_jwt_verify_ex(ss, token, cert_out, jwt_out, stir_shaken_globals.store, 1, connect_timeout_s);
}

stir_shaken_status_t stir_shaken_passport_verify_ex(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, stir_shaken_passport_t **passport_out, X509_STORE *store, uint8_t check_x509_cert_path, unsigned long connect_timeout_s)
{
	jwt_t	*jwt = NULL;
	stir_shaken_passport_t *passport = NULL;
	stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_FALSE;

	ss_status = stir_shaken_jwt_verify_ex(ss, token, cert_out, &jwt, store, check_x509_cert_path, connect_timeout_s);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "JWT failed verification with X509 cert path check", STIR_SHAKEN_ERROR_JWT_VERIFY_AND_CHECK_X509_CERT_PATH_3);
		goto end;
	}

	if (passport_out) {

		passport = stir_shaken_passport_create(ss, NULL, NULL, 0);
		if (!passport) {
			stir_shaken_set_error(ss, "Failed to create PASSporT", STIR_SHAKEN_ERROR_PASSPORT_CREATE_6);
			goto end;
		}

		if (!stir_shaken_jwt_move_to_passport(ss, jwt, passport)) {
			stir_shaken_set_error(ss, "Failed to assign JWT to PASSporT", STIR_SHAKEN_ERROR_SIH_JWT_MOVE_TO_PASSPORT_5);
			jwt_free(jwt);
			stir_shaken_passport_destroy(&passport);
			goto end;
		}
		jwt = NULL;

		*passport_out = passport;
	}

	return ss_status;

end:
	if (jwt) jwt_free(jwt);

	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_passport_verify(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, stir_shaken_passport_t **passport_out, unsigned long connect_timeout_s)
{
	return stir_shaken_passport_verify_ex(ss, token, cert_out, passport_out, stir_shaken_globals.store, 1, connect_timeout_s);
}

stir_shaken_status_t stir_shaken_check_authority_over_number(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, stir_shaken_passport_t *passport)
{
	char *origin_identity = NULL;
	char authority_check_url[STIR_SHAKEN_BUFLEN] = { 0 };
	int is_tn = 0;

	if (!cert || !cert->x || !passport) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if ((STIR_SHAKEN_STATUS_OK != stir_shaken_cert_to_authority_check_url(ss, cert, authority_check_url, STIR_SHAKEN_BUFLEN)) || stir_shaken_zstr(authority_check_url)) {
		stir_shaken_set_error(ss, "Cannot get SPC from certificate", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	origin_identity = stir_shaken_passport_get_identity(ss, passport, &is_tn);
	if (stir_shaken_zstr(origin_identity)) {
		stir_shaken_set_error(ss, "PASSporT has no identity claim", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_make_authority_over_number_check_req(ss, authority_check_url, origin_identity)) {
		stir_shaken_set_error(ss, "Caller has no authority over the number", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_sih_verify_ex(stir_shaken_context_t *ss, const char *sih, stir_shaken_cert_t **cert_out, stir_shaken_passport_t **passport_out, X509_STORE *store, uint8_t check_x509_cert_path, unsigned long connect_timeout_s)
{
	stir_shaken_status_t ss_status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_cert_t *cert = NULL;
	jwt_t *jwt = NULL;
	stir_shaken_passport_t *passport = NULL;
	unsigned char jwt_encoded[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };

	stir_shaken_clear_error(ss);

	if (!sih) {
		stir_shaken_set_error(ss, "SIP Identity Header not set", STIR_SHAKEN_ERROR_BAD_PARAMS_23);
		ss->verification_status = STIR_SHAKEN_VERIFICATION_STATUS_BAD_IDENTITY_HDR;
		goto end;
	}

	ss_status = stir_shaken_jwt_sih_to_jwt_encoded(ss, sih, &jwt_encoded[0], STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN);
	if (ss_status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "Failed to parse encoded PASSporT (SIP Identity Header) into encoded JWT", STIR_SHAKEN_ERROR_SIH_TO_JWT_2);
		ss->verification_status = STIR_SHAKEN_VERIFICATION_STATUS_BAD_IDENTITY_HDR;
		goto end;
	}

	ss_status = stir_shaken_jwt_verify_ex(ss, (char *) jwt_encoded, &cert, &jwt, store, check_x509_cert_path, connect_timeout_s);
	if (ss_status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "JWT failed verification", STIR_SHAKEN_ERROR_JWT_VERIFY_AND_CHECK_X509_CERT_PATH_2);
		goto end;
	}

	passport = stir_shaken_passport_create(ss, NULL, NULL, 0);
	if (!passport) {
		stir_shaken_set_error(ss, "Failed to create PASSporT", STIR_SHAKEN_ERROR_PASSPORT_CREATE_3);
		goto end;
	}

	if (!stir_shaken_jwt_move_to_passport(ss, jwt, passport)) {
		stir_shaken_set_error(ss, "Failed to assign JWT to PASSporT", STIR_SHAKEN_ERROR_SIH_JWT_MOVE_TO_PASSPORT_3);
		jwt_free(jwt);
		stir_shaken_passport_destroy(&passport);
		goto end;
	}


	// TODO move it outside as an optional check
#if STIR_SHAKEN_CHECK_AUTHORITY_OVER_NUMBER

	ss_status = stir_shaken_check_authority_over_number(ss, cert, passport);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Caller has no authority over the call origin", STIR_SHAKEN_ERROR_AUTHORITY_CHECK_4);
		goto end;
	}

#endif

end:

	if (cert_out) {
		// Note, cert must be destroyed by caller
		*cert_out = cert;
	} else {
		stir_shaken_cert_destroy(&cert);
	}

	if (passport_out) {
		// Note, PASSporT must be destroyed by caller
		*passport_out = passport;
	} else {
		stir_shaken_passport_destroy(&passport);
	}

	return ss_status;
}

stir_shaken_status_t stir_shaken_sih_verify(stir_shaken_context_t *ss, const char *sih, stir_shaken_cert_t **cert_out, stir_shaken_passport_t **passport_out, unsigned long connect_timeout_s)
{
	return stir_shaken_sih_verify_ex(ss, sih, cert_out, passport_out, stir_shaken_globals.store, 1, connect_timeout_s);
}

stir_shaken_status_t stir_shaken_passport_validate(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, uint32_t iat_freshness)
{
	stir_shaken_status_t ss_status = STIR_SHAKEN_STATUS_OK;


	if (!passport) {
		stir_shaken_set_error(ss, "PASSporT not set", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}

	ss_status = stir_shaken_passport_validate_headers_and_grants(ss, passport);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "PASSporT invalid", STIR_SHAKEN_ERROR_PASSPORT_INVALID_3);
		return ss_status;
	}

	ss_status = stir_shaken_passport_validate_iat_against_freshness(ss, passport, iat_freshness);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "PASSporT expired", STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_2);
		return ss_status;
	}

	return STIR_SHAKEN_STATUS_OK;
}
