#include "stir_shaken.h"

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
		stir_shaken_set_error(ss, "Error validating STI Cert's notBefore timestamp", STIR_SHAKEN_ERROR_SSL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (res > 0) {
		stir_shaken_set_error(ss, "Invalid STI Certificate: (Not valid yet) notBefore timestamp ahead of now", STIR_SHAKEN_ERROR_CERT_NOT_VALID_YET);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	res = X509_cmp_current_time(cert->notAfter_ASN1);
	if (res == 0) {
		stir_shaken_set_error(ss, "Error validating STI Cert's notAfter timestamp", STIR_SHAKEN_ERROR_SSL);
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
 * PASSporT verification.
 *
 * @passport - (in/out) should point to memory prepared for new PASSporT,
 *				on exit retrieved and verified PASSporT JWT is moved into that @passport
 */ 
stir_shaken_status_t stir_shaken_jwt_verify_with_cert(stir_shaken_context_t *ss, const char *identity_header, stir_shaken_cert_t *cert, stir_shaken_passport_t *passport)
{
	unsigned char key[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	unsigned char jwt_encoded[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int key_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;
	jwt_t *jwt = NULL;

	if (!identity_header || !cert) return STIR_SHAKEN_STATUS_TERM;

	if (stir_shaken_jwt_sih_to_jwt_encoded(ss, identity_header, &jwt_encoded[0], STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN) != STIR_SHAKEN_STATUS_OK) {

		stir_shaken_set_error(ss, "Failed to parse encoded PASSporT (SIP Identity Header) into encoded JWT", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	// Get raw public key from cert
	if (stir_shaken_get_pubkey_raw_from_cert(ss, cert, key, &key_len) != STIR_SHAKEN_STATUS_OK) {

		stir_shaken_set_error_if_clear(ss, "Failed to get public key in raw format from remote STI-SP certificate", STIR_SHAKEN_ERROR_SSL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (jwt_decode(&jwt, jwt_encoded, key, key_len)) {

		stir_shaken_set_error(ss, "JWT did not pass verification", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		jwt_free(jwt);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	stir_shaken_jwt_move_to_passport(jwt, passport);

	return STIR_SHAKEN_STATUS_OK;
}

static size_t curl_callback(void *contents, size_t size, size_t nmemb, void *p)
{
	char *m = NULL;
	size_t realsize = size * nmemb;
	mem_chunk_t *mem = (mem_chunk_t *) p;

	
	stir_shaken_clear_error(mem->ss);

	fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "STIR-Shaken: CURL: Download progress: got %zu bytes (%zu total)\n", realsize, realsize + mem->size);

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

stir_shaken_status_t stir_shaken_download_cert(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	stir_shaken_status_t ss_status = STIR_SHAKEN_STATUS_FALSE;

	if (!http_req) {
		stir_shaken_set_error(ss, "HTTP Req not set", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL not set. Set URL on HTTP request?", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
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

stir_shaken_status_t stir_shaken_jwt_verify(stir_shaken_context_t *ss, const char *token)
{
	stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_http_req_t	http_req = { 0 };
	long					res = CURLE_OK;
	stir_shaken_cert_t		cert = { 0 };
	const char				*cert_url = NULL;
	jwt_t					*jwt = NULL;
	unsigned char key[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int key_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;
	
	stir_shaken_clear_error(ss);
	memset(&http_req, 0, sizeof(http_req));

	if (!token) {
		stir_shaken_set_error(ss, "Bad params: JWT token is missing", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
		goto fail;
	}

	if (jwt_new(&jwt) != 0) {
		stir_shaken_set_error(ss, "Cannot create JWT for the token", STIR_SHAKEN_ERROR_JWT);
		goto fail;
	}

	if (0 != jwt_decode(&jwt, token, NULL, 0)) {
		stir_shaken_set_error(ss, "Token is not JWT", STIR_SHAKEN_ERROR_JWT);
		goto fail;
	}

	cert_url = jwt_get_header(jwt, "x5u");
	if (stir_shaken_zstr(cert_url)) {
		stir_shaken_set_error(ss, "SPC token is missing x5u, cannot download certificate", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
		goto fail;
	}
	http_req.url = strdup(cert_url);

	jwt_free(jwt);
	jwt = NULL;

	ss_status = stir_shaken_download_cert(ss, &http_req);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Cannot download certificate", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
		goto fail;
	}

	ss_status = stir_shaken_load_x509_from_mem(ss, &cert.x, &cert.xchain, http_req.response.mem.mem);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Error while loading cert from memory", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	cert.len = http_req.response.mem.size;

	if (stir_shaken_get_pubkey_raw_from_cert(ss, &cert, key, &key_len) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "Failed to get public key in raw format from certificate", STIR_SHAKEN_ERROR_SSL);
		goto fail;
	}

	if (jwt_decode(&jwt, token, key, key_len)) {
		stir_shaken_set_error(ss, "JWT did not pass verification", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		jwt_free(jwt);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	stir_shaken_destroy_cert(&cert);
	if (jwt) jwt_free(jwt);
	return STIR_SHAKEN_STATUS_OK;

fail:

	stir_shaken_set_error_if_clear(ss, "Unknown error while verifying JWT", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);

	stir_shaken_destroy_cert(&cert);
	stir_shaken_destroy_http_request(&http_req);
	if (jwt) jwt_free(jwt);
	return STIR_SHAKEN_STATUS_FALSE;
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
// 
//
// Errors:
//
// STIR_SHAKEN_ERROR_CERT_INIT									- Cannot instantiate verification context (CA list / Revocation list wrong or missing)
// STIR_SHAKEN_ERROR_CERT_INVALID								- Certificate did not pass X509 path validation against CA list and CRL
// STIR_SHAKEN_ERROR_TNAUTHLIST									- TNAuthList extension wrong or missing
// STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER			- Bad Identity Header, missing fields, malformed content, didn't pass the signature check, etc.
// STIR_SHAKEN_ERROR_PASSPORT_INVALID							- Bad Identity Header, specifically: PASSporT is missing some mandatory fields
// STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO					- Cannot download referenced certificate
//
stir_shaken_status_t stir_shaken_verify(stir_shaken_context_t *ss, const char *sih, const char *cert_url, stir_shaken_passport_t *passport, stir_shaken_cert_t **cert_out, time_t iat_freshness)
{
	stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_http_req_t	http_req = { 0 };
	long					res = CURLE_OK;
	stir_shaken_cert_t		*cert = NULL;
	
	stir_shaken_clear_error(ss);
	memset(&http_req, 0, sizeof(http_req));
	
	if (!sih) {
		stir_shaken_set_error(ss, "Verify: SIP Identity Header not set", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		goto fail;
	}
	
	if (!cert_url) {
		stir_shaken_set_error(ss, "Verify: Cert URL not set", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
		goto fail;
	}
	
	if (stir_shaken_zstr(cert_url)) {
		stir_shaken_set_error(ss, "Verify: Cert URL is empty", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
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

	http_req.url = strdup(cert_url);
	
	ss_status = stir_shaken_download_cert(ss, &http_req);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Cannot download certificate", STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO);
		goto fail;
	}

    ss_status = stir_shaken_load_x509_from_mem(ss, &cert->x, &cert->xchain, http_req.response.mem.mem);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Verify: error while loading cert from memory", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
    }

	cert->body = malloc(http_req.response.mem.size);
	if (!cert->body) {
		stir_shaken_set_error(ss, "Verify: out of memory (will this work?)", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	memcpy(cert->body, http_req.response.mem.mem, http_req.response.mem.size);
	cert->len = http_req.response.mem.size;

	ss_status = stir_shaken_read_cert_fields(ss, cert);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Verify: error parsing certificate", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	ss_status = stir_shaken_basic_cert_check(ss, cert);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Cert did not pass basic check (wrong version or expired)", STIR_SHAKEN_ERROR_CERT_INVALID);
		goto fail;
	}

	ss_status = stir_shaken_verify_cert_path(ss, cert);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Cert did not pass X509 path validation", STIR_SHAKEN_ERROR_CERT_INVALID);
		goto fail;
	}

	ss_status = stir_shaken_jwt_verify_with_cert(ss, sih, cert, passport);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Cert does not match the PASSporT", STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER);
		goto fail;
	}

	ss_status = stir_shaken_passport_validate_headers_and_grants(ss, passport);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "PASSporT invalid", STIR_SHAKEN_ERROR_PASSPORT_INVALID);
		goto fail;
	}

	ss_status = stir_shaken_passport_validate_iat_against_freshness(ss, passport, iat_freshness);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "PASSporT expired", STIR_SHAKEN_ERROR_SIP_403_STALE_DATE);
		goto fail;
	}

#if STIR_SHAKEN_CHECK_AUTHORITY_OVER_NUMBER

	ss_status = stir_shaken_check_authority_over_number(ss, cert, passport);
	if (STIR_SHAKEN_STATUS_OK != ss_status) {
		stir_shaken_set_error(ss, "Caller has no authority over the call origin", STIR_SHAKEN_ERROR_AUTHORITY_CHECK);
		goto fail;
	}

#endif

fail:

	stir_shaken_set_error_if_clear(ss, "Unknown error while processing request", STIR_SHAKEN_ERROR_GENERAL);

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
