#include "stir_shaken.h"
#include <curl/curl.h>

static size_t stir_shaken_curl_write_callback(void *contents, size_t size, size_t nmemb, void *p)
{
	char *m = NULL;
	size_t realsize = size * nmemb;
	stir_shaken_http_req_t *http_req = (stir_shaken_http_req_t *) p;
	mem_chunk_t *mem = &http_req->response.mem;

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

static size_t stir_shaken_curl_header_callback(void *ptr, size_t size, size_t nmemb, void *data)
{
	register unsigned int realsize = (unsigned int) (size * nmemb);
	stir_shaken_http_req_t *http_req = data;
	char *header = NULL;

	header = malloc(realsize + 1);
	if (!header) {
		fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "STIR-Shaken: CURL: Received empty header... skipping\n");
		return 0;
	}
	memcpy(header, ptr, realsize);
	header[realsize] = '\0';

	http_req->response.headers = curl_slist_append(http_req->response.headers, header);
	free(header);

	return realsize;
}

const char* stir_shaken_http_req_type_2_str(stir_shaken_http_req_type_t type)
{
	switch (type) {

		case STIR_SHAKEN_HTTP_REQ_TYPE_GET:
			return "GET";
		case STIR_SHAKEN_HTTP_REQ_TYPE_POST:
			return "POST";
		case STIR_SHAKEN_HTTP_REQ_TYPE_PUT:
			return "PUT";
		case STIR_SHAKEN_HTTP_REQ_TYPE_HEAD:
			return "HEAD";
		default:
			return "BAD REQUEST";
	}
}

/*
 * Make HTTP request with CURL.
 *
 * On fail, http_req->response.code is CURLcode explaining the reason (CURLE_COULDNT_RESOLVE_HOST, 
 * CURLE_COULDNT_RESOLVE_PROXY, CURLE_COULDNT_CONNECT, CURLE_REMOTE_ACCESS_DENIED, etc...).
 * On success, http_req->response.code is HTTP response code (200, 403, 404, etc...).
 *
 * Note.
 *
 * When running this function, "still reachable" memory leak may be reported by valgrind. Example:
 *
 * ==18899==
 * ==18899== HEAP SUMMARY:
 * ==18899==     in use at exit: 192 bytes in 12 blocks
 * ==18899==   total heap usage: 7,484 allocs, 7,472 frees, 526,015 bytes allocated
 * ==18899==
 * ==18899== 48 bytes in 6 blocks are still reachable in loss record 1 of 2
 * ==18899==    at 0x483577F: malloc (vg_replace_malloc.c:299)
 * ==18899==    by 0x5959A93: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595B07B: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F3A4: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F3F8: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F42D: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x59599D9: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595A8CE: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5956788: gcry_control (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5102793: libssh2_init (in /usr/lib/x86_64-linux-gnu/libssh2.so.1.0.1)
 * ==18899==    by 0x48AEA87: ??? (in /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4.5.0)
 * ==18899==    by 0x486813E: stir_shaken_make_http_req (stir_shaken_service.c:410)
 * ==18899==
 * ==18899== 144 bytes in 6 blocks are still reachable in loss record 2 of 2
 * ==18899==    at 0x483577F: malloc (vg_replace_malloc.c:299)
 * ==18899==    by 0x5959A93: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595B07B: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F3C1: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F42D: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x59599D9: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595A8CE: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5956788: gcry_control (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5102793: libssh2_init (in /usr/lib/x86_64-linux-gnu/libssh2.so.1.0.1)
 * ==18899==    by 0x48AEA87: ??? (in /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4.5.0)
 * ==18899==    by 0x486813E: stir_shaken_make_http_req (stir_shaken_service.c:410)
 * ==18899==    by 0x486AE03: stir_shaken_verify (stir_shaken_verify.c:578)
 *
 * ==18899== LEAK SUMMARY:
 * ==18899==    definitely lost: 0 bytes in 0 blocks
 * ==18899==    indirectly lost: 0 bytes in 0 blocks
 * ==18899==      possibly lost: 0 bytes in 0 blocks
 * ==18899==    still reachable: 192 bytes in 12 blocks
 * ==18899==         suppressed: 0 bytes in 0 blocks
 *
 * This is not really a leak, as the memory is freed on process exit. It is shown because some libs are missing
 * curl_global_cleanup and therefore are not freeing up the memory used by curl.
 *
 * Explanation from StackOverflow (https://stackoverflow.com/questions/51503838/why-libcurl-still-leaves-reachable-blocks-after-cleanup-calls):
 * 
 * "libcurl links against many libraries, and some of them do not have a function like curl_global_cleanup which reverts initialization and frees all memory.
 * This happens when libcurl is linked against NSS for TLS support, and also with libssh2 and its use of libgcrypt.
 * GNUTLS as the TLS implementation is somewhat cleaner in this regard.
 *
 * In general, this is not a problem because these secondary libraries are only used on operating systems where memory is freed on process termination,
 * so an explicit cleanup is not needed (and would even slow down process termination). Only with certain memory debuggers, the effect of missing cleanup routines is visible,
 * and valgrind deals with this situation by differentiating between actual leaks (memory to which no pointers are left) and memory which is still reachable at process termination
 * (so that it could have been used again if the process had not terminated)."
 */
stir_shaken_status_t stir_shaken_make_http_req_real(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	uint8_t			use_https = 0;
	CURLcode		res = 0;
	CURL			*curl_handle = NULL;
	char			err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	char			user_agent[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

	if (!http_req) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	if (ss) stir_shaken_clear_error(ss);

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	if (!curl_handle) {
		stir_shaken_set_error(ss, "Curl init failed", STIR_SHAKEN_ERROR_CERT_INIT);
		return STIR_SHAKEN_STATUS_TERM;
	}

	curl_easy_setopt(curl_handle, CURLOPT_URL, http_req->url);

#if STIR_SHAKEN_HTTPS_SKIP_PEER_VERIFICATION
	/*
	 * If you want to connect to a site who isn't using a certificate that is
	 * signed by one of the certs in the CA bundle you have, you can skip the
	 * verification of the server's certificate. This makes the connection
	 * A LOT LESS SECURE.
	 *
	 * If you have a CA cert for the server stored someplace else than in the
	 * default bundle, then the CURLOPT_CAPATH option might come handy for
	 * you.
	 */ 
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#if STIR_SHAKEN_HTTPS_SKIP_HOSTNAME_VERIFICATION
	/*
	 * If the site you're connecting to uses a different host name that what
	 * they have mentioned in their server certificate's commonName (or
	 * subjectAltName) fields, libcurl will refuse to connect. You can skip
	 * this check, but this will make the connection less secure.
	 */ 
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	// Shared stuff
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, stir_shaken_curl_write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) http_req);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, stir_shaken_curl_header_callback);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *) http_req);

	if (http_req->response.mem.mem) {
		free(http_req->response.mem.mem);
		http_req->response.mem.mem = NULL;
		http_req->response.mem.size = 0;
	}

	if (strlen(http_req->url) > 5 && (!strncmp(http_req->url, "https", 5) || !strncmp(http_req->url, "HTTPS", 5))) {
		use_https = 1;
	}

	if (http_req->remote_port == 0) {
		if (use_https) {
			http_req->remote_port = STIR_SHAKEN_HTTP_DEFAULT_REMOTE_PORT_HTTPS;
			fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "STIR-Shaken: changing remote port to DEFAULT_HTTPS %u cause port not set\n", http_req->remote_port);
		} else {
			http_req->remote_port = STIR_SHAKEN_HTTP_DEFAULT_REMOTE_PORT;
			fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "STIR-Shaken: changing remote port to DEFAULT %u cause port not set\n", http_req->remote_port);
		}
	}

	curl_easy_setopt(curl_handle, CURLOPT_PORT, http_req->remote_port);

	// Some pple say, some servers don't like requests that are made without a user-agent field, so we provide one.
	snprintf(user_agent, STIR_SHAKEN_ERROR_BUF_LEN, "freeswitch-stir-shaken/%s", STIR_SHAKEN_VERSION);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, user_agent);

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
			stir_shaken_set_error(ss, "Unknown request type", STIR_SHAKEN_ERROR_HTTP_GENERAL);
			return STIR_SHAKEN_STATUS_FALSE;
	}

	if (http_req->tx_headers) {
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, http_req->tx_headers);
	}

	// TODO remove
	if (http_req->data) {
		fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "STIR-Shaken: making %s (%s) call:\nurl:\t%s\nport:\t%u\ndata:\t%s\n", use_https ? "HTTPS" : "HTTP", stir_shaken_http_req_type_2_str(http_req->type), http_req->url, http_req->remote_port, http_req->data);
	} else {
		fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "STIR-Shaken: making %s (%s) call:\nurl:\t%s\nport:\t%u\n", use_https ? "HTTPS" : "HTTP", stir_shaken_http_req_type_2_str(http_req->type), http_req->url, http_req->remote_port);
	}

	res = curl_easy_perform(curl_handle);
	http_req->response.code = res;

	if (res != CURLE_OK) {

		sprintf(err_buf, "Error in CURL: %s", curl_easy_strerror(res));
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_CURL); 

		// Do not curl_global_cleanup in case of error, cause otherwise (if also curl_global_cleanup) SSL starts to mulfunction ???? (EVP_get_digestbyname("sha256") in stir_shaken_do_verify_data returns NULL)
		curl_easy_cleanup(curl_handle);
		curl_global_cleanup();

		return STIR_SHAKEN_STATUS_FALSE;
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_req->response.code);
	if (http_req->response.code != 200 && http_req->response.code != 201) {
		sprintf(http_req->response.error, "%s response code: %ld (%s%s), HTTP response phrase: %s", use_https ? "HTTPS" : "HTTP", http_req->response.code, curl_easy_strerror(http_req->response.code), (http_req->response.code == 400 || http_req->response.code == 404) ? " [Bad URL or API call not handled?]" : "", http_req->response.headers && http_req->response.headers->data ? http_req->response.headers->data : "");
	}
	curl_easy_cleanup(curl_handle);
	curl_global_cleanup();

	// fprintf(stdout, "\n//////////////// HTTP GOT:\n%s\n///////////////////////\n", http_req->response.mem.mem);	

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

	if (http_req->response.headers) {
		curl_slist_free_all(http_req->response.headers);
		http_req->response.headers = NULL;
	}
	memset(http_req, 0, sizeof(*http_req));
}

/**
 * @http_req - (out) will contain HTTP response
 * @url - (in) POST url
 * @fingerprint - POST body, should be fingerprint of the STI-SP's public key certificate
 */
stir_shaken_status_t stir_shaken_stisp_make_code_token_request(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, const char *fingerprint)
{
	if (!http_req) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stir_shaken_zstr(fingerprint)) {
		stir_shaken_set_error(ss, "Fingerprint missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_POST;
	http_req->data = strdup(fingerprint); // TODO change to JSON if it is not JSON already
	http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_JSON;

	return stir_shaken_make_http_req(ss, http_req);
}

/**
 * Verify STI-CA agaist list (array).
 *
 * Validate the root of the digital signature in the STI certificate
 * by determining whether the STI-CA that issued the STI certificate is in the list of approved STI-CAs
 */
stir_shaken_status_t stir_shaken_vs_verify_stica(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, ks_json_t *array)
{
	unsigned char key[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int key_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;
	ks_json_t *iterator = NULL;

	if (!cert || !array) return STIR_SHAKEN_STATUS_TERM;

	if (stir_shaken_get_pubkey_raw_from_cert(ss, cert, key, &key_len) != STIR_SHAKEN_STATUS_OK) {

		stir_shaken_set_error(ss, "Cannot get public key from cert", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	KS_JSON_ARRAY_FOREACH(iterator, array) {

		if (ks_json_type_get(iterator) == KS_JSON_TYPE_STRING) {
			const char *valuestring = ks_json_value_string(iterator);
			// TODO remove
			fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "%s\n", valuestring);

			if (strcmp((const char *)key, valuestring)) {
				return STIR_SHAKEN_STATUS_OK;
			}
		} else {

			fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "invalid\n");
		}
	}

	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_make_authority_over_number_check_req(stir_shaken_context_t *ss, const char *url, const char *origin_identity)
{
	stir_shaken_http_req_t http_req = { 0 };
	char req_url[STIR_SHAKEN_BUFLEN] = { 0 };
	stir_shaken_status_t result = STIR_SHAKEN_STATUS_FALSE;
	ks_json_t *json = NULL, *authority_check_result = NULL;
	char *valuestring = NULL;

	if (stir_shaken_zstr(url)) {
		stir_shaken_set_error(ss, "URL missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_zstr(origin_identity)) {
		stir_shaken_set_error(ss, "Origin identity missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_TERM;
	}

	snprintf(req_url, STIR_SHAKEN_BUFLEN, "%s/%s", url, origin_identity); 
	http_req.url = strdup(req_url);

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_make_http_get_req(ss, &http_req)) {
		stir_shaken_set_error(ss, "HTTP request for authority over number check failed", STIR_SHAKEN_ERROR_HTTP_GENERAL);
		goto fail;
	}

	json = ks_json_parse(http_req.response.mem.mem);
	if (!json) {
		stir_shaken_set_error(ss, "Error parsing into JSON", STIR_SHAKEN_ERROR_JSON);
		goto fail;
	}

	authority_check_result = ks_json_get_object_item(json, "authority");
	if (!authority_check_result) {
		stir_shaken_set_error(ss, "Bad JSON, no 'authority' field", STIR_SHAKEN_ERROR_JSON);
		goto fail;
	}

	if (ks_json_type_get(authority_check_result) != KS_JSON_TYPE_STRING) {
		stir_shaken_set_error(ss, "Bad JSON, 'authority' field is not a string", STIR_SHAKEN_ERROR_JSON);
		goto fail;
	}

	if (strcmp("true", ks_json_value_string(authority_check_result)) == 0) {
		result = STIR_SHAKEN_STATUS_OK;
	} else {
		result = STIR_SHAKEN_STATUS_FALSE;
	}

	stir_shaken_destroy_http_request(&http_req);
	return result;

fail:
	stir_shaken_destroy_http_request(&http_req);
	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_make_http_get_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	if (!http_req) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_GET;

	return stir_shaken_make_http_req(ss, http_req);
}

stir_shaken_status_t stir_shaken_make_http_post_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, char *data, uint8_t is_json)
{
	if (!http_req) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_POST;
	if (data) {
		if (http_req->response.mem.mem) {
			free(http_req->response.mem.mem);
			http_req->response.mem.mem = NULL;
			http_req->response.mem.size = 0;
		}
		http_req->data = strdup(data);
	}

	if (is_json) {
		http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_JSON;
	} else {
		http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_URLENCODED;
	}

	return stir_shaken_make_http_req(ss, http_req);
}

stir_shaken_status_t stir_shaken_make_http_head_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, char *data, uint8_t is_json)
{
	if (!http_req) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stir_shaken_zstr(http_req->url)) {
		stir_shaken_set_error(ss, "URL missing", STIR_SHAKEN_ERROR_HTTP_PARAMS);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_HEAD;
	if (data) {
		http_req->data = strdup(data);
	}

	if (is_json) {
		http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_JSON;
	} else {
		http_req->content_type = STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_URLENCODED;
	}

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
	int sanity = 10000;

	if (!http_req || !name) return NULL;

	header = http_req->response.headers;

	// Parse header data
	while (header && sanity--) {

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

			fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "key:\t\t%s\n", header->data);
			fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "value:\t\t%s\n\n", data);

			if (!strcmp(header->data, name)) {

				// found
				found = data;
			}

		} else {

			if (!strncmp("HTTP", header->data, 4)) {
				fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "Starts with HTTP: %s\n", header->data);
			} else {
				fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "Unparsable header: %s\n", header->data);
			}
		}
		header = header->next;
	}

	return found;
}

void stir_shaken_error_desc_to_http_error_phrase(const char *error_desc, char *error_phrase, int buflen)
{
	char *p = NULL, *d = NULL;

	if (stir_shaken_zstr(error_desc) || !error_phrase || buflen < 1) {
		return;
	}

	strncpy(error_phrase, error_desc, buflen);
	p = error_phrase;
	while (p && (*p != '\0')) {

		d = p;
		if ((p = strstr(d, "\r\n"))) {
			*p = ';';
			p++;
			*p = ' ';
		} else {
			if ((p = strstr(d, "\n"))) {
				*p = ';';
			} else {
				return;
			}
		}
	}
}

stir_shaken_as_t* stir_shaken_as_create(struct stir_shaken_context_s *ss)
{
	stir_shaken_as_t *as = malloc(sizeof(*as));
	if (!as) {
		stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_AS_MEM);
		return NULL;
	}
	memset(as, 0, sizeof(*as));
	return as;
}

void stir_shaken_as_destroy(stir_shaken_as_t *as)
{
	if (!as) return;
	stir_shaken_destroy_keys(&as->keys);
	stir_shaken_destroy_cert(&as->cert);
}

stir_shaken_status_t stir_shaken_vs_set_ca_dir(struct stir_shaken_context_s *ss, stir_shaken_vs_t *vs, const char *ca_dir)
{
	if (!vs) {
		stir_shaken_set_error(ss, "Verification service missing", STIR_SHAKEN_ERROR_VS_MISSING_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	memset((void*) vs->settings.ca_dir, 0, sizeof(vs->settings.ca_dir));

	if (!stir_shaken_zstr(ca_dir)) {
		strncpy(vs->settings.ca_dir, ca_dir, sizeof(vs->settings.ca_dir) - 1);
		vs->settings.ca_dir[sizeof(vs->settings.ca_dir) - 1] = '\0';
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_as_load_private_key(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, const char *private_key_name)
{
	if (!as) {
		stir_shaken_set_error(ss, "Authentication service missing", STIR_SHAKEN_ERROR_AS_MISSING_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	memset((void*) as->settings.private_key_name, 0, sizeof(as->settings.private_key_name));

	if (!stir_shaken_zstr(private_key_name)) {
		strncpy(as->settings.private_key_name, private_key_name, sizeof(as->settings.private_key_name) - 1);
		as->settings.private_key_name[sizeof(as->settings.private_key_name) - 1] = '\0';
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_file_exists(as->settings.private_key_name)) {
		stir_shaken_set_error(ss, "Private key does not exist", STIR_SHAKEN_ERROR_AS_PRIVKEY_DOES_NOT_EXIST);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	as->keys.priv_raw_len = sizeof(as->keys.priv_raw);
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_key_raw(ss, as->settings.private_key_name, as->keys.priv_raw, &as->keys.priv_raw_len)) {
		stir_shaken_set_error(ss, "Failed to load private key", STIR_SHAKEN_ERROR_AS_LOAD_PRIVKEY);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_as_load_cert(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, const char *cert_name)
{
	if (!as) {
		stir_shaken_set_error(ss, "Authentication service missing", STIR_SHAKEN_ERROR_AS_MISSING_4);
		return STIR_SHAKEN_STATUS_TERM;
	}

	memset((void*) as->settings.cert_name, 0, sizeof(as->settings.cert_name));

	if (!stir_shaken_zstr(cert_name)) {
		strncpy(as->settings.cert_name, cert_name, sizeof(as->settings.cert_name) - 1);
		as->settings.cert_name[sizeof(as->settings.cert_name) - 1] = '\0';
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_file_exists(as->settings.cert_name)) {
		stir_shaken_set_error(ss, "Certificate does not exist", STIR_SHAKEN_ERROR_AS_CERTIFICATE_DOES_NOT_EXIST);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	stir_shaken_destroy_cert(&as->cert);

	as->cert.x = stir_shaken_load_x509_from_file(ss, as->settings.cert_name);
	if (!as->cert.x) {
		stir_shaken_set_error(ss, "Failed to load certificate", STIR_SHAKEN_ERROR_AS_LOAD_CERT);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

char* stir_shaken_as_authenticate_to_passport(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport_out)
{
	stir_shaken_passport_t*	passport = NULL;
	char *encoded = NULL;

	if (!as) {
		stir_shaken_set_error(ss, "Authentication service missing", STIR_SHAKEN_ERROR_AS_MISSING_2);
		return NULL;
	}

	passport = stir_shaken_passport_create(ss, params, as->keys.priv_raw, as->keys.priv_raw_len);
	if (!passport) {
		stir_shaken_set_error(ss, "Failed to create PASSporT", STIR_SHAKEN_ERROR_AS_CREATE_PASSPORT_1);
		return NULL;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_sign(ss, passport, NULL, 0, &encoded)) {
		stir_shaken_set_error(ss, "Failed to sign PASSporT", STIR_SHAKEN_ERROR_AS_SIGN_PASSPORT);
		stir_shaken_passport_destroy(passport);
		free(passport);
		return NULL;
	}

	if (passport_out) {
		*passport_out = passport;
	} else {
		stir_shaken_passport_destroy(passport);
		free(passport);
	}

	return encoded;
}

char* stir_shaken_as_authenticate_to_sih(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport_out)
{
	stir_shaken_passport_t*	passport = NULL;
	char *sih = NULL;

	if (!as) {
		stir_shaken_set_error(ss, "Authentication service missing", STIR_SHAKEN_ERROR_AS_MISSING_3);
		return NULL;
	}

	passport = stir_shaken_passport_create(ss, params, as->keys.priv_raw, as->keys.priv_raw_len);
	if (!passport) {
		stir_shaken_set_error(ss, "Failed to create PASSporT", STIR_SHAKEN_ERROR_AS_CREATE_PASSPORT_2);
		return NULL;
	}

	sih = stir_shaken_jwt_sip_identity_create(ss, passport, as->keys.priv_raw, as->keys.priv_raw_len);
	if (!sih) {
		stir_shaken_set_error(ss, "Failed to create SIP Identity Header", STIR_SHAKEN_ERROR_AS_CREATE_SIH);
		stir_shaken_passport_destroy(passport);
		free(passport);
		return NULL;
	}

	if (passport_out) {
		*passport_out = passport;
	} else {
		stir_shaken_passport_destroy(passport);
		free(passport);
	}

	return sih;
}

stir_shaken_status_t stir_shaken_as_install_cert(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, const char *where)
{
	if (!as) {
		stir_shaken_set_error(ss, "Authentication service missing", STIR_SHAKEN_ERROR_AS_MISSING_5);
		return STIR_SHAKEN_STATUS_TERM;
	}

	return stir_shaken_x509_to_disk(ss, as->cert.x, where);
}
