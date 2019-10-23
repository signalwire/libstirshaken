#include "stir_shaken.h"


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

	http_req->headers = curl_slist_append(http_req->headers, header);

	return realsize;
}

stir_shaken_status_t stir_shaken_make_http_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	CURLcode		res = 0;
	CURL			*curl_handle = NULL;
	curl_slist_t	*headers = NULL;
	char			err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

	if (!http_req || !http_req->url) return STIR_SHAKEN_STATUS_FALSE;

	if (ss) stir_shaken_clear_error(ss);

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	if (!curl_handle) {
		// TODO panic
		return STIR_SHAKEN_STATUS_FALSE;
	}

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
					
					headers = curl_slist_append(headers, "Content-Type: application/json");
					break;

				case STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_URLENCODED:
				default:
					break;
			}

			break;

		case STIR_SHAKEN_HTTP_REQ_TYPE_PUT:
			break;

		default:
			break;
	}
	
	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK) {

		sprintf(err_buf, "Error in CURL: %s", curl_easy_strerror(res));
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_CURL); 

		// Do not curl_global_cleanup in case of error, cause otherwise (if also curl_global_cleanup) SSL starts to mulfunction ???? (EVP_get_digestbyname("sha256") in stir_shaken_do_verify_data returns NULL)
		curl_easy_cleanup(curl_handle);
		
		if (headers) {
			curl_slist_free_all(headers);
		}

        return STIR_SHAKEN_STATUS_FALSE;
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_req->response.code);
	curl_easy_cleanup(curl_handle);
	
	if (headers) {
		curl_slist_free_all(headers);
	}

	return STIR_SHAKEN_STATUS_OK;
}

/**
 * @api - (in) STI-SP's api interface to STI-PA
 * @http_req - (out) will contain HTTP response
 *
 *
 * MOVE to FS
 *
stir_shaken_status_t stir_shaken_stisp_get_code_token(stir_shaken_context_t *ss, EVP_PKEY *public_key, stir_shaken_http_req_t *http_req)
{
    stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;
	char					err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	X509					*x = NULL;
	char					*fingerprint = NULL;
	stir_shaken_stipa_api_t *api = NULL;

	if (!public_key || !http_req) {
		return STIR_SHAKEN_STATUS_FALSE;
	}
	api = &stisp->settings.stipa_interface.api;

	memset(http_req, 0, sizeof(*http_req));

	http_req->type = STIR_SHAKEN_HTTP_REQ_TYPE_POST;
	http_req->data = fingerprint;
	http_req->url = api->url;	// TODO create complete SP Code request from url and sp_code_req

	// Get public key certificate fingerprint
	x = stir_shaken_make_cert_from_public_key(ss, stisp->keys.public_key);

	return stir_shaken_make_http_req(ss, http_req);
}**/
