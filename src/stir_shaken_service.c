#include "stir_shaken.h"


/*
 * JWT:
 *
 * {
 *	"protected": base64url({
 *		"alg": "ES256",
 *		"kid": " https://sti-ca.com/acme/acct/1",
 *		"nonce": "5XJ1L3lEkMG7tR6pA00clA",
 *		"url": " https://sti-ca.com/acme/new-order"
 *		})
 *	"payload": base64url({
 *		"csr": "5jNudRx6Ye4HzKEqT5...FS6aKdZeGsysoCo4H9P",
 *		"notBefore": "2016-01-01T00:00:00Z",
 *		"notAfter": "2016-01-08T00:00:00Z"
 *		}),
 *	"signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
 * }
*/
char* stir_shaken_stisp_acme_generate_cert_req_payload(stir_shaken_context_t *ss, char *kid, char *nonce, char *url, X509_REQ *req, char *nb, char *na, unsigned char *key, uint32_t keylen, char **json)
{
	char	*out = NULL;
	jwt_t	*jwt = NULL;
	unsigned char	csr_raw[1000] = { 0 };
	int				csr_raw_len = 1000;
	char			csr_b64[1500] = { 0 };
	int				csr_b64_len = 1500;

	if (jwt_new(&jwt) != 0) {

		stir_shaken_set_error(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	// Header

	if (key && keylen) {		

		if(jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
			goto exit;
		}
	}

	if (kid) {

		if (jwt_add_header(jwt, "kid", kid) != 0) {
			goto exit;
		}
	}

	if (nonce) {

		if (jwt_add_header(jwt, "nonce", "nonce") != 0) {
			goto exit;
		}
	}

	if (url) {

		if (jwt_add_header(jwt, "url", url) != 0) {
			goto exit;
		}
	}

	// Payload

	if (req) {

		if (stir_shaken_get_csr_raw(ss, req, &csr_raw[0], &csr_raw_len) != STIR_SHAKEN_STATUS_OK) {

			stir_shaken_set_error_if_clear(ss, "Cannot get CSR raw", STIR_SHAKEN_ERROR_SSL);
			goto exit;
		}

		if (stir_shaken_b64_encode(csr_raw, csr_raw_len, csr_b64, csr_b64_len) != STIR_SHAKEN_STATUS_OK) {

			stir_shaken_set_error_if_clear(ss, "Cannot base 64 encode CSR raw", STIR_SHAKEN_ERROR_SSL);
			goto exit;
		}

		if (jwt_add_grant(jwt, "csr", csr_b64) != 0) {
			goto exit;
		}
	}

	if (nb) {

		if (jwt_add_grant(jwt, "notBefore", nb) != 0) {
			goto exit;
		}
	}

	if (na) {

		if (jwt_add_grant(jwt, "notAfter", na) != 0) {
			goto exit;
		}
	}

	if (json) {

		*json = jwt_dump_str(jwt, 1);
		if (!*json) {
			stir_shaken_set_error(ss, "Failed to dump JWT", STIR_SHAKEN_ERROR_GENERAL);
			goto exit;
		}
	}

	out = jwt_encode_str(jwt);
	if (!out) {
		stir_shaken_set_error(ss, "Failed to encode JWT", STIR_SHAKEN_ERROR_GENERAL);
		goto exit;
	}

exit:
	if (jwt) jwt_free(jwt);
	return out;
}

/**
 * JWT:
 *
 * {
 *	"protected": base64url({
 *		"alg": "ES256",
 *		"kid": "https://sti-ca.com/acme/acct/1",
 *		"nonce": "Q_s3MWoqT05TrdkM2MTDcw",
 *		"url": "https://sti-ca.com/acme/authz/1234/0"
 *	}),
 *	"payload": base64url({
 *		"type": "spc-token",
 *		"keyAuthorization": "IlirfxKKXA...vb29HhjjLPSggwiE"
 *	}),
 *	"signature": "9cbg5JO1Gf5YLjjz...SpkUfcdPai9uVYYQ"
 * }
 */
char* stir_shaken_stisp_acme_generate_auth_challenge_token(stir_shaken_context_t *ss, char *kid, char *nonce, char *url, char *sp_code_token, unsigned char *key, uint32_t keylen, char **json)
{
	char	*out = NULL;
	jwt_t	*jwt = NULL;
	unsigned char	csr_raw[1000] = { 0 };
	int				csr_raw_len = 1000;
	char			csr_b64[1500] = { 0 };
	int				csr_b64_len = 1500;

	if (jwt_new(&jwt) != 0) {

		stir_shaken_set_error(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	// Header

	if (key && keylen) {		

		if(jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
			goto exit;
		}
	}

	if (kid) {

		if (jwt_add_header(jwt, "kid", kid) != 0) {
			goto exit;
		}
	}

	if (nonce) {

		if (jwt_add_header(jwt, "nonce", "nonce") != 0) {
			goto exit;
		}
	}

	if (url) {

		if (jwt_add_header(jwt, "url", url) != 0) {
			goto exit;
		}
	}

	// Payload

	if (jwt_add_grant(jwt, "type", "spc-token") != 0) {
		goto exit;
	}

	if (sp_code_token) {

		// TODO Need more details here
		//
		// "This challenge response JWS payload shall include the SHAKEN certificate framework specific challenge type of
		// “spc-token” and the “keyAuthorization” field containing the “token” for the challenge concatenated with the value of
		// the Service Provider Code token."

		if (jwt_add_grant(jwt, "keyAuthorization", sp_code_token) != 0) {
			goto exit;
		}
	}

	if (json) {

		*json = jwt_dump_str(jwt, 1);
		if (!*json) {
			stir_shaken_set_error(ss, "Failed to dump JWT", STIR_SHAKEN_ERROR_GENERAL);
			goto exit;
		}
	}

	out = jwt_encode_str(jwt);
	if (!out) {
		stir_shaken_set_error(ss, "Failed to encode JWT", STIR_SHAKEN_ERROR_GENERAL);
		goto exit;
	}

exit:
	if (jwt) jwt_free(jwt);
	return out;
}

/*
 * JWT:
 *
 * {
 *	"protected": base64url({
 *		"alg": "ES256",
 *		"jwk": {...},
 *		"nonce": "6S8IqOGY7eL2lsGoTZYifg",
 *		"url": "https://sti-ca.com/acme/new-reg"
 *		}),
 *	"payload": base64url({
 *		"contact": [
 *			"mailto:cert-admin-sp-kms01@sp.com",
 *			"tel:+12155551212"
 *			]
 *		}),
 *	"signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
 * }
*/
char* stir_shaken_stisp_acme_generate_new_account_req_payload(stir_shaken_context_t *ss, char *jwk, char *nonce, char *url, char *contact_mail, char *contact_tel, unsigned char *key, uint32_t keylen, char **json)
{
	char	*out = NULL;
	jwt_t	*jwt = NULL;

	if (jwt_new(&jwt) != 0) {

		stir_shaken_set_error(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	// Header

	if (key && keylen) {		

		if(jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
			goto exit;
		}
	}

	if (jwk) {

		if (jwt_add_header(jwt, "jwk", jwk) != 0) {
			goto exit;
		}
	}

	if (nonce) {

		if (jwt_add_header(jwt, "nonce", "nonce") != 0) {
			goto exit;
		}
	}

	if (url) {

		if (jwt_add_header(jwt, "url", url) != 0) {
			goto exit;
		}
	}

	// Payload

	if (contact_mail || contact_tel) {

		cJSON *contact = NULL, *e = NULL;
		char *jstr = NULL;

		contact = cJSON_CreateArray();
		if (!contact) {
			stir_shaken_set_error(ss, "Passport create json: Error in cjson, @contact", STIR_SHAKEN_ERROR_CJSON);
			goto exit;
		}

		if (contact_mail) {

			e = cJSON_CreateString(contact_mail);
			if (!e) {
				stir_shaken_set_error(ss, "Passport create json: Error in cjson, @contact_mail", STIR_SHAKEN_ERROR_CJSON);
				cJSON_Delete(contact);
				goto exit;
			}
			cJSON_AddItemToArray(contact, e);
		}

		if (contact_tel) {

			e = cJSON_CreateString(contact_tel);
			if (!e) {
				stir_shaken_set_error(ss, "Passport create json: Error in cjson, @contact_tel", STIR_SHAKEN_ERROR_CJSON);
				cJSON_Delete(contact);
				goto exit;
			}
			cJSON_AddItemToArray(contact, e);
		}

		jstr = cJSON_PrintUnformatted(contact);
		if (!jstr || (jwt_add_grant(jwt, "contact", jstr) != 0)) {
			cJSON_Delete(contact);
			goto exit;
		}

		cJSON_Delete(contact);
		free(jstr);
	}

	if (json) {

		*json = jwt_dump_str(jwt, 1);
		if (!*json) {
			stir_shaken_set_error(ss, "Failed to dump JWT", STIR_SHAKEN_ERROR_GENERAL);
			goto exit;
		}
	}

	out = jwt_encode_str(jwt);
	if (!out) {
		stir_shaken_set_error(ss, "Failed to encode JWT", STIR_SHAKEN_ERROR_GENERAL);
		goto exit;
	}

exit:
	if (jwt) jwt_free(jwt);
	return out;
}

static size_t stir_shaken_curl_write_callback(void *contents, size_t size, size_t nmemb, void *p)
{
	char *m = NULL;
	size_t realsize = size * nmemb;
	stir_shaken_http_req_t *http_req = (stir_shaken_http_req_t *) p;
	mem_chunk_t *mem = &http_req->response.mem;
	
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

static size_t stir_shaken_curl_header_callback(void *ptr, size_t size, size_t nmemb, void *data)
{
	register unsigned int realsize = (unsigned int) (size * nmemb);
	stir_shaken_http_req_t *http_req = data;
	char *header = NULL;

	header = malloc(realsize + 1);
	if (!header) {
		// TODO panic
		return 0;
	}
	memcpy(header, ptr, realsize);
	header[realsize] = '\0';

	http_req->rx_headers = curl_slist_append(http_req->rx_headers, header);

	return realsize;
}

/*
 * Make HTTP request with CURL.
 *
 * On fail, http_req->response.code is CURLcode explaining the reason (CURLE_COULDNT_RESOLVE_HOST, 
 * CURLE_COULDNT_RESOLVE_PROXY, CURLE_COULDNT_CONNECT, CURLE_REMOTE_ACCESS_DENIED, etc...).
 * On success, http_req->response.code is HTTP response code (200, 403, 404, etc...).
 */
stir_shaken_status_t stir_shaken_make_http_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	CURLcode		res = 0;
	CURL			*curl_handle = NULL;
	char			err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

	if (!http_req || !http_req->url) return STIR_SHAKEN_STATUS_RESTART;

	if (ss) stir_shaken_clear_error(ss);

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	if (!curl_handle) return STIR_SHAKEN_STATUS_TERM;

	curl_easy_setopt(curl_handle, CURLOPT_URL, http_req->url);

	// Shared stuff
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, stir_shaken_curl_write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) http_req);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, stir_shaken_curl_header_callback);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *) http_req);
	
	// Some pple say, some servers don't like requests that are made without a user-agent field, so we provide one.
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "freeswitch-stir-shaken/1.0");

	switch (http_req->type) {

		case STIR_SHAKEN_HTTP_REQ_TYPE_GET:	

			curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1);
			break;

		case STIR_SHAKEN_HTTP_REQ_TYPE_POST:

			if (http_req->data) {
				curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, strlen(http_req->data));
				curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, (void *) http_req->data);
			}

			// Curl will send form urlencoded by default, so for json the Content-Type header must be explicitly set
			switch (http_req->content_type) {

				case STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_JSON:
					
					http_req->tx_headers = curl_slist_append(http_req->tx_headers, "Content-Type: application/json");
					break;

				case STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_URLENCODED:
				default:
					break;
			}

			break;

		case STIR_SHAKEN_HTTP_REQ_TYPE_PUT:
			break;

		case STIR_SHAKEN_HTTP_REQ_TYPE_HEAD:	

			// TODO check if this is necessary to make HEAD req
			//curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "HEAD");

			// Get the resource without a body
			curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);

			break;

		default:
			break;
	}

	if (http_req->tx_headers) {
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, http_req->tx_headers);
	}

	// TODO remove
	if (http_req->data) {
		printf("STIR-Shaken: making HTTP (%d) call:\nurl:\t%s\ndata:\t%s\n", http_req->type, http_req->url, http_req->data);
	} else {
		printf("STIR-Shaken: making HTTP (%d) call:\nurl:\t%s\n", http_req->type, http_req->url);
	}

	res = curl_easy_perform(curl_handle);
	http_req->response.code = res;

	if (res != CURLE_OK) {

		sprintf(err_buf, "Error in CURL: %s", curl_easy_strerror(res));
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_CURL); 

		// Do not curl_global_cleanup in case of error, cause otherwise (if also curl_global_cleanup) SSL starts to mulfunction ???? (EVP_get_digestbyname("sha256") in stir_shaken_do_verify_data returns NULL)
		curl_easy_cleanup(curl_handle);
		
		// On fail, http_req->response.code is CURLcode
        return STIR_SHAKEN_STATUS_FALSE;
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_req->response.code);
	curl_easy_cleanup(curl_handle);
	
	// On success, http_req->response.code is HTTP response code (200, 403, 404, etc...)
	return STIR_SHAKEN_STATUS_OK;
}

void stir_shaken_destroy_http_request(stir_shaken_http_req_t *http_req)
{
	if (!http_req) return;

	if (http_req->url) {
		free((char *) http_req->url);
		http_req->url = NULL;
	}

	if (http_req->data) {
		free((char *) http_req->data);
		http_req->data = NULL;
	}

	if (http_req->response.mem.mem) {
		free(http_req->response.mem.mem);
		http_req->response.mem.mem = NULL;
	}

	if (http_req->tx_headers) {
		curl_slist_free_all(http_req->tx_headers);
		http_req->tx_headers = NULL;
	}

	if (http_req->rx_headers) {
		curl_slist_free_all(http_req->rx_headers);
		http_req->rx_headers = NULL;
	}
}

/**
 * @http_req - (out) will contain HTTP response
 * @url - (in) POST url
 * @fingerprint - POST body, should be fingerprint of the STI-SP's public key certificate
 */
stir_shaken_status_t stir_shaken_stisp_make_code_token_request(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, const char *fingerprint)
{
	if (!http_req || !url || !fingerprint) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_POST;
	http_req->data = strdup(fingerprint); // TODO change to JSON if it is not JSON already
	http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_JSON;
	http_req->url = strdup(url);	// this should be similar to http://my-sti-pa.com/sti-pa/account/:id/token

	return stir_shaken_make_http_req(ss, http_req);
}

/**
 * Verify STI-CA agaist list (array).
 *
 * Validate the root of the digital signature in the STI certificate
 * by determining whether the STI-CA that issued the STI certificate is in the list of approved STI-CAs
 */
stir_shaken_status_t stir_shaken_stisp_verify_stica(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, cJSON *array)
{
	unsigned char key[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int key_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;
	cJSON *iterator = NULL;

	if (!cert || !array) return STIR_SHAKEN_STATUS_TERM;

	if (stir_shaken_get_pubkey_raw(ss, cert, key, &key_len) != STIR_SHAKEN_STATUS_OK) {

		stir_shaken_set_error(ss, "Cannot get public key from cert", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	cJSON_ArrayForEach(iterator, array) {

		if (iterator->type == cJSON_String) {

			// TODO remove
			printf("%s\n", iterator->valuestring);

			if (strcmp(key, iterator->valuestring)) {
				return STIR_SHAKEN_STATUS_OK;
			}
		} else {

			printf("invalid\n");
		}
	}

	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_make_http_get_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url)
{
	if (!http_req || !url) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_GET;
	http_req->url = strdup(url);

	return stir_shaken_make_http_req(ss, http_req);
}

stir_shaken_status_t stir_shaken_make_http_post_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, char *data, uint8_t is_json)
{
	if (!http_req || !url) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_POST;
	if (data) {
		http_req->data = strdup(data);
	}

	// TODO enable TYPE_JSON
	if (is_json) {
		http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_JSON;
	} else {
		http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_URLENCODED;
	}

	http_req->url = strdup(url);

	return stir_shaken_make_http_req(ss, http_req);
}

stir_shaken_status_t stir_shaken_make_http_head_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, char *data)
{
	if (!http_req || !url) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_HEAD;
	if (data) {
		http_req->data = strdup(data);
	}

	// TODO enable TYPE_JSON
	http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_URLENCODED;
	http_req->url = strdup(url);

	return stir_shaken_make_http_req(ss, http_req);
}

void stir_shaken_http_add_header(stir_shaken_http_req_t *http_req, const char *h)
{
	if (!http_req || !h) return;

	/* Add a custom header */
	http_req->tx_headers = curl_slist_append(http_req->tx_headers, h);
}

/**
 * Return header's value if found.
 * Note: pointer is valid as long as http_req's headers are valid.
 */ 
char* stir_shaken_get_http_header(stir_shaken_http_req_t *http_req, char *name)
{
	char *data = NULL, *found = NULL;
	curl_slist_t *header = NULL;

	if (!http_req || !name) return NULL;

	header = http_req->response.headers;

	// Parse header data
	while (header) {
		
		// Remove trailing \r
		if ((data =  strrchr(header->data, '\r'))) {
			*data = '\0';
		}

		if (!header->data || *header->data == '\0') {
			header = header->next;
			continue;
		}

		if ((data = strchr(header->data, ':'))) {

			*data = '\0';
			data++;
			while (*data == ' ' && *data != '\0') {
				data++;
			}

			// TODO remove
			printf("key:\t\t%s\n", header->data);
			printf("value:\t\t%s\n\n", data);

			if (!strcmp(header->data, name)) {

				// found
				found = data;
			}

		} else {

			if (!strncmp("HTTP", header->data, 4)) {

				// TODO remove
				printf("Starts with HTTP: %s\n", header->data);
			} else {

				// TODO remove
				printf("Unparsable header: %s\n", header->data);
			}
		}
		header = header->next;
	}

	return found;
}
