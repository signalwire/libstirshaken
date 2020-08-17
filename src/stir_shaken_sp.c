#include "stir_shaken.h"


stir_shaken_status_t stir_shaken_sp_cert_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, char *jwt, unsigned char *key, uint32_t keylen, const char *spc, char *spc_token)
{
    stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_FALSE;
	char cert_download_url[STIR_SHAKEN_BUFLEN] = { 0 };
    uint16_t remote_port = STIR_SHAKEN_HTTP_DEFAULT_REMOTE_PORT;

	if (!http_req) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}

    remote_port = http_req->remote_port;

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL missing", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	if (stir_shaken_zstr(spc)) {
		stir_shaken_set_error(ss, "SPC missing", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	snprintf(cert_download_url, STIR_SHAKEN_BUFLEN, "%s/%s", http_req->url, spc);
	
	if (stir_shaken_zstr(jwt)) {
		stir_shaken_set_error(ss, "JWT missing", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	if (!key) {
		stir_shaken_set_error(ss, "Key not set", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	if (keylen < 1) {
		stir_shaken_set_error(ss, "Invalid key. Key length must be > 0", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	if (stir_shaken_zstr(spc_token)) {
		stir_shaken_set_error(ss, "SPC token missing", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	/**
	 * Make cert req.
	 * Performing Step 1 of 6.3.5.2 ACME Based Steps for Application for an STI Certificate [ATIS-1000080].
	 */

    http_req->action = STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_INIT;
	ss_status = stir_shaken_make_http_post_req(ss, http_req, jwt, 0);

	if (ss_status != STIR_SHAKEN_STATUS_OK) {
		goto exit;
	}

	if (http_req->response.code != 200 && http_req->response.code != 201) {
		stir_shaken_set_error(ss, http_req->response.error, STIR_SHAKEN_ERROR_ACME);
		ss_status = STIR_SHAKEN_STATUS_FALSE;
		goto exit;
	}

	/**
	 * Process response to cert req, performing authorization if required by STI-CA.
	 * Authorization is performed by responding to the challenge with the current SP Code Token.
	 * Performing Steps 4, 5, 7 of 6.3.5.2 ACME Based Steps for Application for an STI Certificate [ATIS-1000080].
	 */

	ss_status = stir_shaken_acme_perform_authorization(ss, http_req->response.mem.mem, spc_token, key, keylen, http_req->remote_port);
	if (ss_status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "ACME failed at authorization step", STIR_SHAKEN_ERROR_ACME);
		goto exit;
	}

	/*
	 * Download cert.
	 * Executing 6.3.6 STI Certificate Acquisition [ATIS-1000080].
	 */

	stir_shaken_destroy_http_request(http_req);

	http_req->url = strdup(cert_download_url);
    http_req->remote_port = remote_port;
    http_req->action = STIR_SHAKEN_ACTION_TYPE_SP_CERT_DOWNLOAD;

	ss_status = stir_shaken_download_cert(ss, http_req);
	if (ss_status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "ACME failed to download certificate", STIR_SHAKEN_ERROR_ACME);
		goto exit;
	}

	return STIR_SHAKEN_STATUS_OK;


exit:

	stir_shaken_set_error_if_clear(ss, "ACME failed to download certificate", STIR_SHAKEN_ERROR_ACME);
	stir_shaken_destroy_http_request(http_req);
	return ss_status;
}

stir_shaken_status_t stir_shaken_sp_cert_req_ex(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *kid, const char *nonce, X509_REQ *req, const char *nb, const char *na, const char *spc, unsigned char *key, uint32_t keylen, char **json, char *spc_token)
{
    stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_FALSE;
	char					*jwt_encoded = NULL;
	char					*jwt_decoded = NULL;


	if (!req) {
		stir_shaken_set_error(ss, "X509 REQ missing", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_zstr(nonce)) {
		// Allow for empty nonce for now
		//stir_shaken_set_error(ss, "Nonce missing", STIR_SHAKEN_ERROR_GENERAL);
	}

	if (!key) {
		stir_shaken_set_error(ss, "Key not set", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	if (keylen < 1) {
		stir_shaken_set_error(ss, "Invalid key. Key length must be > 0", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	if (stir_shaken_zstr(spc)) {
		stir_shaken_set_error(ss, "SPC missing", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}
	
	jwt_encoded = stir_shaken_acme_generate_cert_req_payload(ss, kid, nonce, http_req->url, req, nb, na, spc, key, keylen, &jwt_decoded);
	if (!jwt_encoded || !jwt_decoded) {
		stir_shaken_set_error(ss, "Failed to generate JWT payload", STIR_SHAKEN_ERROR_JWT);
		return STIR_SHAKEN_STATUS_TERM;
	}

	ss_status = stir_shaken_sp_cert_req(ss, http_req, jwt_encoded, key, keylen, spc, spc_token);

#if STIR_SHAKEN_MOCK_ACME_CERT_REQ
	// Mock response
	ss_status = STIR_SHAKEN_STATUS_OK;
	stir_shaken_as_acme_mock_cert_req_response(as, &http_req);
#endif

	if (ss_status != STIR_SHAKEN_STATUS_OK) {
		goto exit;
	}

	if (http_req->response.code != 200 && http_req->response.code != 201) {
		stir_shaken_set_error(ss, http_req->response.error, STIR_SHAKEN_ERROR_ACME);
		ss_status = STIR_SHAKEN_STATUS_FALSE;
		goto exit;
	}

	if (stir_shaken_zstr(http_req->response.mem.mem)) {
		stir_shaken_set_error(ss, "Got empty response from CA", STIR_SHAKEN_ERROR_ACME_EMPTY_CA_RESPONSE);
		ss_status = STIR_SHAKEN_STATUS_FALSE;
		goto exit;
	}

	fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Got STI certificate from CA:\n%s\n", http_req->response.mem.mem);

	if (json) {
		*json = jwt_decoded;
	} else {
		stir_shaken_free_jwt_str(jwt_decoded);
	}
	stir_shaken_free_jwt_str(jwt_encoded);
	return STIR_SHAKEN_STATUS_OK;


exit:

	stir_shaken_set_error_if_clear(ss, "ACME failed to download certificate", STIR_SHAKEN_ERROR_ACME);
	stir_shaken_destroy_http_request(http_req);
	if (jwt_encoded) stir_shaken_free_jwt_str(jwt_encoded);
	if (jwt_decoded) stir_shaken_free_jwt_str(jwt_decoded);
	return ss_status;
}

void stir_shaken_sp_destroy(stir_shaken_sp_t *sp)
{
	if (sp) {
		stir_shaken_destroy_csr(&sp->csr);
		stir_shaken_destroy_cert(&sp->cert);
		stir_shaken_destroy_keys(&sp->keys);
		if (sp->kid) free(sp->kid);
		if (sp->nonce) free(sp->nonce);
		if (sp->nb) free(sp->nb);
		if (sp->na) free(sp->na);
		memset(sp, 0, sizeof(*sp));
	}
}
