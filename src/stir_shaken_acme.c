#include "stir_shaken.h"
#include <curl/curl.h>

/**
 * JSON:
 *
 * {
 *	"status": "pending",
 *	"expires": "2025-01-01T14:09:00Z",
 *	"csr": "jcRf4uXra7FGYW5ZMewvV...rhlnznwy8YbpMGqwidEXfE",
 *	"notBefore": "2019-01-01T00:00:00Z",
 *	"notAfter": "2029-01-08T00:00:00Z",
 *	"authorizations": [
 *		"https://sti-ca.com/acme/authz/1234"
 *	]
 * }
 */
char* stir_shaken_acme_generate_auth_challenge(stir_shaken_context_t *ss, char *status, char *expires, char *csr, char *nb, char *na, char *authz_url)
{
    char *printed = NULL;
    ks_json_t *json = NULL, *arr = NULL, *obj = NULL, *s = NULL;

    if (stir_shaken_zstr(status)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'status' is missing", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    if (stir_shaken_zstr(expires)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'expires' is missing", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    if (stir_shaken_zstr(csr)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'csr' is missing", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    if (stir_shaken_zstr(nb)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'nb' (not before date) is missing", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    if (stir_shaken_zstr(na)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'na' (not after date) is missing", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    if (stir_shaken_zstr(authz_url)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'authz_url' (authorization URL) is missing", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    s = ks_json_create_string(authz_url);	
    if (!s) {
        stir_shaken_set_error(ss, "Cannot create JSON object for authorization URL", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    arr = ks_json_create_array();
    if (!arr) {
        ks_json_delete(&s);
        stir_shaken_set_error(ss, "Cannot create JSON array for 'authorizations'", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    json = ks_json_create_object();
    if (!json) {
        ks_json_delete(&arr);
        ks_json_delete(&s);
        stir_shaken_set_error(ss, "Cannot create JSON object", STIR_SHAKEN_ERROR_ACME);
        return NULL;
    }

    ks_json_add_string_to_object(json, "status", "pending");
    ks_json_add_string_to_object(json, "expires", "2015-03-01T14:09:00Z");
    ks_json_add_string_to_object(json, "csr", "jcRf4uXra7FGYW5ZMewvV...rhlnznwy8YbpMGqwidEXfE");
    ks_json_add_string_to_object(json, "notBefore", "2016-01-01T00:00:00Z");
    ks_json_add_string_to_object(json, "notAfter", "2016-01-08T00:00:00Z");
    //ks_json_add_item_to_object(obj, s);
    ks_json_add_item_to_array(arr, s); 
    ks_json_add_item_to_object(json, "authorizations", arr);

    printed = strdup(ks_json_print_unformatted(json));
    ks_json_delete(&json);
    return printed;
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
char* stir_shaken_acme_generate_auth_challenge_response(stir_shaken_context_t *ss, char *kid, char *nonce, char *url, char *spc_token, unsigned char *key, uint32_t keylen, char **json)
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

    if (spc_token) {

        // TODO Need more details here
        //
        // "This challenge response JWS payload shall include the SHAKEN certificate framework specific challenge type of
        // “spc-token” and the “keyAuthorization” field containing the “token” for the challenge concatenated with the value of
        // the Service Provider Code token."

        if (jwt_add_grant(jwt, "keyAuthorization", spc_token) != 0) {
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
char* stir_shaken_acme_generate_new_account_req_payload(stir_shaken_context_t *ss, char *jwk, char *nonce, char *url, char *contact_mail, char *contact_tel, unsigned char *key, uint32_t keylen, char **json)
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

        ks_json_t *contact = NULL, *e = NULL;
        char *jstr = NULL;

        contact = ks_json_create_array();
        if (!contact) {
            stir_shaken_set_error(ss, "Passport create json: Error in ks_json, @contact", STIR_SHAKEN_ERROR_KSJSON);
            goto exit;
        }

        if (contact_mail) {

            e = ks_json_create_string(contact_mail);
            if (!e) {
                stir_shaken_set_error(ss, "Passport create json: Error in ks_json, @contact_mail", STIR_SHAKEN_ERROR_KSJSON);
                ks_json_delete(&contact);
                goto exit;
            }
            ks_json_add_item_to_array(contact, e);
        }

        if (contact_tel) {

            e = ks_json_create_string(contact_tel);
            if (!e) {
                stir_shaken_set_error(ss, "Passport create json: Error in ks_json, @contact_tel", STIR_SHAKEN_ERROR_KSJSON);
                ks_json_delete(&contact);
                goto exit;
            }
            ks_json_add_item_to_array(contact, e);
        }

        jstr = ks_json_print_unformatted(contact);
        if (!jstr || (jwt_add_grant(jwt, "contact", jstr) != 0)) {
            ks_json_delete(&contact);
            goto exit;
        }

        ks_json_delete(&contact);
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

#if STIR_SHAKEN_MOCK_ACME_NONCE_REQ
static void mock_nonce_req_response(stir_shaken_http_req_t *http_req)
{
    if (!http_req) return;

    http_req->response.code = 200;
    free(http_req->response.mem.mem);
    http_req->response.headers = curl_slist_append(http_req->response.headers, "Replay-Nonce: oFvnlFP1wIhRlYS2jTaXbA");
    http_req->response.headers = curl_slist_append(http_req->response.headers, "Cache-Control: no-store");
    http_req->response.headers = curl_slist_append(http_req->response.headers, "Link: <https://example.com/acme/directory>;rel=\"index\"");
}
#endif

stir_shaken_status_t stir_shaken_acme_nonce_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
    return stir_shaken_make_http_head_req(ss, http_req, NULL, 0);
}

/*
 * Mocking auth challenge details to be like:
 * {
 *	"status": "pending",
 *	"identifier": {
 *		"type": "TNAuthList",
 *		"value":[ "1234"]
 *	},
 *	"challenges": [ 
 *		{	"type": "spc-token",
 *			"url": "https://sti-ca.com/authz/1234/0",
 *			"token": "DGyRejmCefe7v4NfDGDKfA"
 *		}
 *	],
 * }
 */
#if STIR_SHAKEN_MOCK_ACME_AUTH_CHALLENGE_DETAILS_REQ
static char* mock_auth_challenge_details(void)
{
    char *printed = NULL;
    ks_json_t *json = ks_json_create_object(), *arr = ks_json_create_array(), *o1 = ks_json_create_object(), *o2 = ks_json_create_object();
    if (!json || !arr || !o1 || !o2) {
        return NULL;
    }

    ks_json_add_string_to_object(json, "status", "pending");
    ks_json_add_string_to_object(o1, "type", "TNAuthList");
    ks_json_add_string_to_object(o1, "value", "1234");
    ks_json_add_string_to_object(o2, "type", "spc-token");
    ks_json_add_string_to_object(o2, "url", "https://sti-ca.com/authz/1234/0");
    ks_json_add_string_to_object(o2, "token", "DGyRejmCefe7v4NfDGDKfA");
    ks_json_add_item_to_array(arr, o2); 
    ks_json_add_item_to_object(json, "identifier", o1);
    ks_json_add_item_to_object(json, "challenges", arr);

    printed = strdup(ks_json_print_unformatted(json));
    ks_json_delete(&json);
    return printed;
}
#endif

char* stir_shaken_acme_generate_auth_challenge_details(stir_shaken_context_t *ss, char *status, const char *spc, const char *token, const char *authz_url)
{
    char *printed = NULL;
    ks_json_t *json = ks_json_create_object(), *arr = ks_json_create_array(), *o1 = ks_json_create_object(), *o2 = ks_json_create_object();
    if (!json || !arr || !o1 || !o2) {
        stir_shaken_set_error(ss, "Cannot create auth challenge details JSON object", STIR_SHAKEN_ERROR_ACME);
        goto fail;
    }

    if (stir_shaken_zstr(status)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'status' is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_CHALLENGE_DETAILS);
        return NULL;
    }

    if (stir_shaken_zstr(spc)) {
        stir_shaken_set_error(ss, "Bad params. Auth challenge details must have: spc, token, authz url: spc is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_CHALLENGE_DETAILS);
        goto fail;
    }
    if (stir_shaken_zstr(token)) {
        stir_shaken_set_error(ss, "Bad params. Auth challenge details must have: spc, token, authz url: token is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_CHALLENGE_DETAILS);
        goto fail;
    }
    if (stir_shaken_zstr(authz_url)) {
        stir_shaken_set_error(ss, "Bad params. Auth challenge details must have: spc, token, authz_url: authz_url is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_CHALLENGE_DETAILS);
        goto fail;
    }

    ks_json_add_string_to_object(json, "status", status);
    ks_json_add_string_to_object(o1, "type", "TNAuthList");
    ks_json_add_string_to_object(o1, "value", spc);
    ks_json_add_string_to_object(o2, "type", "spc-token");
    ks_json_add_string_to_object(o2, "url", authz_url);
    ks_json_add_string_to_object(o2, "token", token);
    ks_json_add_item_to_array(arr, o2); 
    ks_json_add_item_to_object(json, "identifier", o1);
    ks_json_add_item_to_object(json, "challenges", arr);

    printed = strdup(ks_json_print_unformatted(json));
    ks_json_delete(&json);
    return printed;

fail:
    if (json) {
        ks_json_delete(&json);
    } else {
        if (arr) {
            ks_json_delete(&arr);
        }
        if (o1) {
            ks_json_delete(&o1);
        }
        if (o2) {
            ks_json_delete(&o2);
        }
    }
    return NULL;
}

char* stir_shaken_acme_generate_auth_polling_status(stir_shaken_context_t *ss, char *status, char *expires, char *validated, const char *spc, const char *token, const char *authz_url)
{
    char *printed = NULL;
    ks_json_t *json = ks_json_create_object(), *arr = ks_json_create_array(), *o1 = ks_json_create_object(), *o2 = ks_json_create_object();
    if (!json || !arr || !o1 || !o2) {
        stir_shaken_set_error(ss, "Cannot create auth challenge details JSON object", STIR_SHAKEN_ERROR_ACME);
        goto fail;
    }

    if (stir_shaken_zstr(status)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'status' is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_POLLING_STATUS);
        return NULL;
    }

    if (stir_shaken_zstr(expires)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'expires' is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_POLLING_STATUS);
        return NULL;
    }

    if (stir_shaken_zstr(validated)) {
        stir_shaken_set_error(ss, "Cannot create JSON, 'validated' is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_POLLING_STATUS);
        return NULL;
    }

    if (stir_shaken_zstr(spc)) {
        stir_shaken_set_error(ss, "Bad params. Auth polling status must have: spc, token, authz url: spc is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_POLLING_STATUS);
        goto fail;
    }
    if (stir_shaken_zstr(token)) {
        stir_shaken_set_error(ss, "Bad params. Auth polling status must have: spc, token, authz url: token is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_POLLING_STATUS);
        goto fail;
    }
    if (stir_shaken_zstr(authz_url)) {
        stir_shaken_set_error(ss, "Bad params. Auth polling status must have: spc, token, authz_url: authz_url is missing", STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_POLLING_STATUS);
        goto fail;
    }

    ks_json_add_string_to_object(json, "status", status);
    ks_json_add_string_to_object(json, "expires", expires);
    ks_json_add_string_to_object(o1, "type", "TNAuthList");
    ks_json_add_string_to_object(o1, "value", spc);
    ks_json_add_string_to_object(o2, "type", "spc-token");
    ks_json_add_string_to_object(o2, "url", authz_url);
    ks_json_add_string_to_object(o2, "status", status);
    ks_json_add_string_to_object(o2, "validated", validated);
    ks_json_add_string_to_object(o2, "token", token);
    ks_json_add_item_to_array(arr, o2); 
    ks_json_add_item_to_object(json, "identifier", o1);
    ks_json_add_item_to_object(json, "challenges", arr);

    printed = strdup(ks_json_print_unformatted(json));
    ks_json_delete(&json);
    return printed;

fail:
    if (json) {
        ks_json_delete(&json);
    } else {
        if (arr) {
            ks_json_delete(&arr);
        }
        if (o1) {
            ks_json_delete(&o1);
        }
        if (o2) {
            ks_json_delete(&o2);
        }
    }
    return NULL;
}

/*
 * In Step 7 of 6.3.5.2 ACME Based Steps for Application for an STI Certificate [ATIS-1000080]
 * only 'status' field is checked, so even if expecting auth status response to be like:

 * {
 *	"status": "pending",
 *	"identifier": {
 *		"type": "TNAuthList",
 *		"value":[ "1234"]
 *	},
 *	"challenges": [ 
 *		{	"type": "spc-token",
 *			"url": "https://sti-ca.com/authz/1234/0",
 *			"token": "DGyRejmCefe7v4NfDGDKfA"
 *		}
 *	],
 * }
 *
 * it is enough to produce json with only 'status' field.
 */
#if STIR_SHAKEN_MOCK_ACME_POLL_REQ
static char* mock_poll_response(char *status)
{
    char *printed = NULL;
    ks_json_t *json = ks_json_create_object();

    if (!json || !status) {
        return NULL;
    }

    ks_json_add_string_to_object(json, "status", status);
    printed = strdup(ks_json_print_unformatted(json));
    ks_json_delete(&json);
    return printed;
}
#endif

stir_shaken_status_t stir_shaken_acme_retrieve_auth_challenge_details(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
    stir_shaken_status_t ss_status = STIR_SHAKEN_STATUS_FALSE;

    if (!http_req)
        return STIR_SHAKEN_STATUS_TERM;

    ss_status = stir_shaken_make_http_get_req(ss, http_req);

#if STIR_SHAKEN_MOCK_ACME_AUTH_CHALLENGE_DETAILS_REQ
    // Mock response
    ss_status = STIR_SHAKEN_STATUS_OK;
    http_req->response.code = 200;
    free(http_req->response.mem.mem);
    http_req->response.mem.mem = mock_auth_challenge_details();
#endif

    if (http_req->response.code != 200 && http_req->response.code != 201) {
        stir_shaken_set_error(ss, http_req->response.error, STIR_SHAKEN_ERROR_ACME);
        return STIR_SHAKEN_STATUS_FALSE;
    }

    return ss_status;
}

/*
 * Expecting @data to be a response with auth challenge details of the form:
 * {
 *	"status": "pending",
 *	"identifier": {
 *		"type": "TNAuthList",
 *		"value":[ "1234"]
 *	},
 *	"challenges": [ 
 *		{	"type": "spc-token",
 *			"url": "https://sti-ca.com/authz/1234/0",
 *			"token": "DGyRejmCefe7v4NfDGDKfA"
 *		}
 *	],
 * }
 */
stir_shaken_status_t stir_shaken_acme_respond_to_challenge(stir_shaken_context_t *ss, void *data, char *spc_token, unsigned char *key, uint32_t keylen, char **polling_url, uint16_t remote_port)
{
    stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_FALSE;
    const char				*error_description = NULL;
    stir_shaken_error_t		error_code = 0;
    ks_json_t *json = NULL, *auth_status = NULL, *challenges_arr = NULL;
    stir_shaken_http_req_t http_req = { 0 };


    if (!data) {
        stir_shaken_set_error(ss, "Bad params, JWT missing", STIR_SHAKEN_ERROR_ACME);
        return STIR_SHAKEN_STATUS_TERM;
    }

    if (stir_shaken_zstr(spc_token)) {
        stir_shaken_set_error(ss, "SPC token NULL or empty", STIR_SHAKEN_ERROR_GENERAL);
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

    json = ks_json_parse(data);
    if (!json) {
        goto fail;
    }

    auth_status = ks_json_get_object_item(json, "status");
    if (!auth_status) {
        stir_shaken_set_error(ss, "ACME authorization challenge malformed, no 'status' field", STIR_SHAKEN_ERROR_ACME);
        goto fail;
    }

    if (ks_json_type_get(auth_status) != KS_JSON_TYPE_STRING) {
        stir_shaken_set_error(ss, "ACME authorization challenge malformed, 'status' field is not a string", STIR_SHAKEN_ERROR_ACME);
        goto fail;
    }

    if (strcmp("valid", ks_json_value_string(auth_status)) == 0) {

        // Authorization completed

    } else {

        ks_json_t	*challenge_item = NULL;
        ks_json_t	*url_item = NULL;
        const char	*challenge_url = NULL;
        char err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

        char *kid = NULL, *nonce = NULL, *url = NULL;
        char *jwt_encoded = NULL, *jwt_decoded = NULL;

        if (strcmp("pending", ks_json_value_string(auth_status)) != 0) {
            snprintf(err_buf, STIR_SHAKEN_BUFLEN, "ACME authorization challenge malformed, 'status' field is neither 'valid' nor 'pending' (status is: '%s')", ks_json_value_string(auth_status));
            stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        // ACME authorization is still pending
        // Retrieve authorization challenge response URL

        challenges_arr = ks_json_get_object_item(json, "challenges");
        if (!challenges_arr) {
            stir_shaken_set_error(ss, "ACME authorization challenge details do not contain 'challenges' array", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        if (ks_json_type_get(challenges_arr) != KS_JSON_TYPE_ARRAY) {
            stir_shaken_set_error(ss, "ACME authorization challenge details contain 'challenges' which is not an array", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        challenge_item = ks_json_get_array_item(challenges_arr, 0);
        if (!challenge_item) {
            stir_shaken_set_error(ss, "ACME authorization challenge details 'challenges' array is empty", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        if (ks_json_type_get(challenge_item) != KS_JSON_TYPE_OBJECT) {
            stir_shaken_set_error(ss, "ACME authorization challenge item is not a JSON object, expecting compound object", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        url_item = ks_json_get_object_item(challenge_item, "url");
        if (!url_item) {
            stir_shaken_set_error(ss, "ACME authorization challenge details malformed, no 'url' field in 'challenges' array", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        if (ks_json_type_get(url_item) != KS_JSON_TYPE_STRING) {
            stir_shaken_set_error(ss, "ACME authorization challenge details malformed, 'url' field in 'challenges' array is not a string", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        challenge_url = ks_json_value_string(url_item);
        if (polling_url) {
            *polling_url = strdup(challenge_url);
        }

        /**
         * Respond with SP code token.
         * Performing Step 5 of 6.3.5.2 ACME Based Steps for Application for an STI Certificate [ATIS-1000080].
         */

        // TODO
        kid = "https://sti-ca.com/acme/acct/1";			// TODO map to auth challenge details
        nonce = "Q_s3MWoqT05TrdkM2MTDcw";				// TODO map to auth challenge details

        jwt_encoded = stir_shaken_acme_generate_auth_challenge_response(ss, kid, nonce, (char*)challenge_url, spc_token, key, keylen, NULL);
        if (!jwt_encoded) {
            stir_shaken_set_error(ss, "Failed to generate JWT with SP Code token as a response to auth challenge", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        http_req.url = strdup(challenge_url);
        http_req.remote_port = remote_port;

        if (STIR_SHAKEN_STATUS_OK != stir_shaken_make_http_post_req(ss, &http_req, jwt_encoded, 1)) {
            // Mock response
            // TODO ????
            //ss_status = STIR_SHAKEN_STATUS_OK;
            //http_req.response.code = 200;
            // Content is left unspecified in Step 5 of 6.3.5.2 ACME Based Steps for Application for an STI Certificate [ATIS-1000080]
            goto fail;
        }

        if (http_req.response.code != 200 && http_req.response.code != 201) {
            stir_shaken_set_error(ss, http_req.response.error, STIR_SHAKEN_ERROR_ACME);
            return STIR_SHAKEN_STATUS_FALSE;
        }

        stir_shaken_destroy_http_request(&http_req);
    }

    ks_json_delete(&json);
    return STIR_SHAKEN_STATUS_OK;

fail:
    if (json) ks_json_delete(&json);
    stir_shaken_destroy_http_request(&http_req);
    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_acme_poll(stir_shaken_context_t *ss, void *data, const char *url, uint16_t remote_port)
{
    uint8_t					status_is_valid = 0;
    stir_shaken_status_t	ss_status = STIR_SHAKEN_STATUS_OK;
    stir_shaken_http_req_t	http_req = { 0 };
    ks_json_t					*json = NULL, *auth_status = NULL;
    int						t = 0;
    char err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

    if (!url) {
        goto fail;
    }

    http_req.url = strdup(url);
    http_req.remote_port = remote_port;

    // Poll until either status is 'valid' or more than 30s passed
    while (!status_is_valid && t < 30) {

        // Fetch authorization status
        ss_status = stir_shaken_make_http_get_req(ss, &http_req);

#if STIR_SHAKEN_MOCK_ACME_POLL_REQ
        ss_status = STIR_SHAKEN_STATUS_OK;
        http_req.response.code = 200;
        free(http_req.response.mem.mem);

        if (t < 12) {

            // Mock response indicating status 'pending'
            http_req.response.mem.mem = sofia_stir_shaken_as_acme_mock_poll_response("pending");
        } else {

            // After some time, mock response indicating status 'valid'
            http_req.response.mem.mem = sofia_stir_shaken_as_acme_mock_poll_response("valid");
        }
#endif
        if (ss_status != STIR_SHAKEN_STATUS_OK) {
            goto fail;
        }

        if (http_req.response.code != 200 && http_req.response.code != 201) {
            stir_shaken_set_error(ss, http_req.response.error, STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        // Process response
        json = ks_json_parse(http_req.response.mem.mem);
        if (!json) {
            goto fail;
        }

        auth_status = ks_json_get_object_item(json, "status");
        if (!auth_status) {
            stir_shaken_set_error(ss, "ACME auth status malformed, no 'status' field", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        if (ks_json_type_get(auth_status) != KS_JSON_TYPE_STRING) {
            stir_shaken_set_error(ss, "ACME auth status malformed, 'status' field is not a string", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        // Check authorization status
        // If status is "valid" authorization is completed and can proceed to cert acquisition
        if (strcmp("valid", ks_json_value_string(auth_status)) == 0) {

            // Authorization completed
            status_is_valid = 1;
            fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Got 'valid' polling status\n");

        } else {

            if (strcmp("pending", ks_json_value_string(auth_status)) != 0) {

                if (0 == strcmp("failed", ks_json_value_string(auth_status))) {
                    fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Got 'failed' polling status");
                    snprintf(err_buf, STIR_SHAKEN_BUFLEN, "\t-> Got 'failed' polling status (%s): ACME authorization unsuccessful\n", ks_json_value_string(auth_status));
                    stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_ACME_AUTHZ_UNSUCCESSFUL);
                    goto fail;
                }

                fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Got malformed polling status\n");

                snprintf(err_buf, STIR_SHAKEN_BUFLEN, "ACME auth status malformed, 'status' field is neither 'valid' nor 'pending' nor 'failed' (status is: '%s')\n", ks_json_value_string(auth_status));
                stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_ACME);
                goto fail;
            }

            fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Got 'pending' polling status, continue polling...\n");

            // ACME authorization is still pending, poll again after some delay
            // Wait before next HTTP request
            sleep(5);
            t += 5;
        }

        if (json) {
            ks_json_delete(&json);
            json = NULL;
        }
    }

    return status_is_valid ? STIR_SHAKEN_STATUS_OK : STIR_SHAKEN_STATUS_FALSE;

fail:
    if (json) ks_json_delete(&json);
    return STIR_SHAKEN_STATUS_TERM;
}

/*
 * Expecting ACME authorization challenge from STI-CA as a response to STI-SP cert request.
 * Expecting ACME authorization challenge from STI-CA to be of the form:
 *
 * {
 *	"status": "pending",
 *	"expires": "2015-03-01T14:09:00Z",
 *	"csr": "jcRf4uXra7FGYW5ZMewvV...rhlnznwy8YbpMGqwidEXfE",
 *	"notBefore": "2016-01-01T00:00:00Z",
 *	"notAfter": "2016-01-08T00:00:00Z",
 *	"authorizations": [
 *		"https://sti-ca.com/acme/authz/1234"
 *	]
 *	}
 */
stir_shaken_status_t stir_shaken_acme_perform_authorization(stir_shaken_context_t *ss, void *data, char *spc_token, unsigned char *key, uint32_t keylen, uint16_t remote_port)
{
    ks_json_t *json = NULL, *auth_status = NULL, *auth_arr = NULL;
    char err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };


    if (!data) {
        stir_shaken_set_error(ss, "Empty authorization details", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_TERM;
    }

    if (stir_shaken_zstr(spc_token)) {
        stir_shaken_set_error(ss, "SPC token NULL or empty", STIR_SHAKEN_ERROR_GENERAL);
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

    json = ks_json_parse(data);
    if (!json) {
        goto fail;
    }

    auth_status = ks_json_get_object_item(json, "status");
    if (!auth_status) {
        stir_shaken_set_error(ss, "ACME authorization challenge malformed, no 'status' field", STIR_SHAKEN_ERROR_ACME);
        goto fail;
    }

    if (ks_json_type_get(auth_status) != KS_JSON_TYPE_STRING) {
        stir_shaken_set_error(ss, "ACME authorization challenge malformed, 'status' field is not a string", STIR_SHAKEN_ERROR_ACME);
        goto fail;
    }

    fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Processing authorization challenge...\n");

    // If status is "valid" authorization is completed and can proceed to cert acquisition
    if (strcmp("valid", ks_json_value_string(auth_status)) == 0) {

        // Authorization completed
        fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Authorization completed\n");

    } else {

        ks_json_t	*auth_item = NULL;
        const char	*auth_url = NULL;
        stir_shaken_http_req_t http_req = { 0 };

        if (strcmp("pending", ks_json_value_string(auth_status)) != 0) {
            snprintf(err_buf, STIR_SHAKEN_BUFLEN, "ACME authorization challenge malformed, 'status' field is neither 'valid' nor 'pending' (status is: '%s')", ks_json_value_string(auth_status));
            stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        // ACME authorization is pending
        // Retrieve authorization challenge details

        fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Authorization is pending\n");

        auth_arr = ks_json_get_object_item(json, "authorizations");
        if (!auth_arr) {
            stir_shaken_set_error(ss, "ACME authorization challenge does not contain 'authorizations' array", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        if (ks_json_type_get(auth_arr) != KS_JSON_TYPE_ARRAY) {
            stir_shaken_set_error(ss, "ACME authorization challenge contains 'authorizations' which is not an array", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        auth_item = ks_json_get_array_item(auth_arr, 0);
        if (!auth_item) {
            stir_shaken_set_error(ss, "ACME authorization challenge 'authorizations' array is empty", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        if (ks_json_type_get(auth_item) != KS_JSON_TYPE_STRING) {
            stir_shaken_set_error(ss, "ACME 'authorizations' array at item 0  is not a string, expecting string value", STIR_SHAKEN_ERROR_ACME);
            goto fail;
        }

        auth_url = ks_json_value_string(auth_item);

        /*
         * Performing Step 4 of 6.3.5.2 ACME Based Steps for Application for an STI Certificate [ATIS-1000080].
         */

        http_req.url = strdup(auth_url);
        http_req.remote_port = remote_port;

        fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Requesting authorization challenge details...\n");

        if (STIR_SHAKEN_STATUS_OK != stir_shaken_acme_retrieve_auth_challenge_details(ss, &http_req)) {
            stir_shaken_set_error(ss, "Request for ACME authorization challenge details failed. STI-SP cert cannot be downloaded.", STIR_SHAKEN_ERROR_ACME);
            goto fail;

        } else {

            char *polling_url = NULL;

            /*
             * Got authorization challenge details, proceed to Step 5, respond to challenge with SP Code token.
             */

            if (stir_shaken_zstr(http_req.response.mem.mem)) {
                stir_shaken_set_error(ss, "Got empty response from CA", STIR_SHAKEN_ERROR_ACME_EMPTY_CA_AUTH_DETAILS_RESPONSE);
                goto fail;
            }

            fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Got authorization challenge details from CA:\n%s\n", http_req.response.mem.mem);
            fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Sending a response to authorization challenge details...\n");

            if (STIR_SHAKEN_STATUS_OK != stir_shaken_acme_respond_to_challenge(ss, http_req.response.mem.mem, spc_token, key, keylen, &polling_url, remote_port)) {
                stir_shaken_set_error(ss, " ACME failed at authorization challenge response step. STI-SP cert cannot be downloaded.", STIR_SHAKEN_ERROR_ACME);
                free(polling_url);
                goto fail;
            }

            /*
             * Polling.
             */

            fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Polling...\n");

            if (STIR_SHAKEN_STATUS_OK != stir_shaken_acme_poll(ss, http_req.response.mem.mem, polling_url, remote_port)) {
                stir_shaken_set_error(ss, "ACME polling failed. STI-SP cert cannot be downloaded.", STIR_SHAKEN_ERROR_ACME);
                free(polling_url);
                goto fail;
            }

            free(polling_url);
            fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Polling finished...\n");
        }
    }

    ks_json_delete(&json);
    return STIR_SHAKEN_STATUS_OK;

fail:
    if (json) ks_json_delete(&json);
    stir_shaken_set_error_if_clear(ss, "ACME request failed. Cannot obtain STI certificate.", STIR_SHAKEN_ERROR_ACME);
    return STIR_SHAKEN_STATUS_FALSE;
}

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
 *		"notAfter": "2016-01-08T00:00:00Z",
 *		"spc": "1234",
 *		}),
 *	"signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
 * }
 */
char* stir_shaken_acme_generate_cert_req_payload(stir_shaken_context_t *ss, const char *kid, const char *nonce, const char *url, X509_REQ *req, const char *nb, const char *na, const char *spc, unsigned char *key, uint32_t keylen, char **json)
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

        if (stir_shaken_b64_encode(csr_raw, csr_raw_len, (unsigned char*) csr_b64, csr_b64_len) != STIR_SHAKEN_STATUS_OK) {

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

    if (spc) {

        if (jwt_add_grant(jwt, "spc", spc) != 0) {
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

stir_shaken_status_t stir_shaken_acme_api_uri_to_spc(stir_shaken_context_t *ss, const char *uri_request, const char *api_url, char *buf, int buflen, int *uri_has_secret, unsigned long long *secret)
{
    char *p = NULL, *spc = NULL;
    char request[STIR_SHAKEN_BUFLEN] = { 0 };
    int len = 0;

    if (stir_shaken_zstr(uri_request)) {
        stir_shaken_set_error(ss, "Bad AUTHZ request URI", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_TERM;
    }

    if (stir_shaken_zstr(api_url)) {
        stir_shaken_set_error(ss, "Bad params, API URI missing", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_TERM;
    }

    if (!uri_has_secret || !secret) {
        stir_shaken_set_error(ss, "Bad params, 'secret' not set", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_TERM;
    }

    strncpy(request, uri_request, 1 < STIR_SHAKEN_BUFLEN ? STIR_SHAKEN_BUFLEN - 1 : 1);
    p = strchr(request, ' ');
    if (!p) p = strchr(request, '\t');
    if (!p) p = strchr(request, '\r');
    if (!p) p = strchr(request, '\n');
    if (p) *p = '\0';

    p = strstr(request, api_url);
    if (!p) {
        stir_shaken_set_error(ss, "Request doesn't contain API URI", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_RESTART;
    }

    p = p + strlen(api_url);
    if (stir_shaken_zstr(p)) {
        stir_shaken_set_error(ss, "Bad AUTHZ request URI, SPC missing", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_FALSE;
    }

    if (*p != '/') {
        stir_shaken_set_error(ss, "Bad AUTHZ request URI, '/' missing after API URI", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_FALSE;
    }

    p = p + 1;
    if (stir_shaken_zstr(p)) {
        stir_shaken_set_error(ss, "Bad AUTHZ request URI, SPC missing (after API URI and '/')", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_FALSE;
    }

    spc = p;

    if ((p = strchr(p, '/'))) {

        char *pCh = NULL;
        unsigned long long  val;

        // maybe authz details URI, or cert URI

        *p = '\0';

        strncpy(buf, spc, buflen);

        p = p + 1;
        if (strchr(p, '/')) {
            stir_shaken_set_error(ss, "Bad AUTHZ request URI, too many '/'", STIR_SHAKEN_ERROR_ACME_URI);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        val = strtoul(p, &pCh, 10); 
        if (val > 0x10000 - 1) { 
            stir_shaken_set_error(ss, "Bad URI: Attempt number too big", STIR_SHAKEN_ERROR_ACME_SECRET_TOO_BIG);
            return STIR_SHAKEN_STATUS_FALSE;
        }

        if (*pCh != '\0') { 
            stir_shaken_set_error(ss, "Bad URI: Attempt number invalid", STIR_SHAKEN_ERROR_ACME_SECRET_INVALID);
            return STIR_SHAKEN_STATUS_FALSE;
        }

        *uri_has_secret = 1;
        *secret = val;

    } else {

        len = strlen(spc);
        if (len > buflen) {
            stir_shaken_set_error(ss, "Buffer too short for SPC", STIR_SHAKEN_ERROR_ACME_URI);
        }

        strncpy(buf, spc, buflen);
    }

    return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_acme_api_uri_parse(stir_shaken_context_t *ss, const char *uri_request, const char *api_url, char *arg1, int arg1_len, char *arg2, int arg2_len, int *args_n)
{
    char *p = NULL, *args = NULL;
    char request[STIR_SHAKEN_BUFLEN] = { 0 };
    int len = 0;

    if (!args_n) {
        stir_shaken_set_error(ss, "Bad params, args_n missing", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_TERM;
    }

    if (stir_shaken_zstr(uri_request)) {
        stir_shaken_set_error(ss, "Bad request URI", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_TERM;
    }

    if (stir_shaken_zstr(api_url)) {
        stir_shaken_set_error(ss, "Bad params, API URI missing", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_TERM;
    }

    if (!arg1 || !arg2 || !arg1_len || !arg2_len) {
        stir_shaken_set_error(ss, "Bad params, buffers missing or too short", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_TERM;
    }

    strncpy(request, uri_request, 1 < STIR_SHAKEN_BUFLEN ? STIR_SHAKEN_BUFLEN - 1 : 1);
    p = strchr(request, ' ');
    if (!p) p = strchr(request, '\t');
    if (!p) p = strchr(request, '\r');
    if (!p) p = strchr(request, '\n');
    if (p) *p = '\0';

    p = strstr(request, api_url);
    if (!p) {
        stir_shaken_set_error(ss, "Request doesn't contain API URI", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_RESTART;
    }

    p = p + strlen(api_url);
    if (stir_shaken_zstr(p)) {
        *args_n = 0;
        return STIR_SHAKEN_STATUS_OK;
    }

    if (*p != '/') {
        stir_shaken_set_error(ss, "Bad request URI, '/' missing after API URI", STIR_SHAKEN_ERROR_ACME_URI);
        return STIR_SHAKEN_STATUS_FALSE;
    }

    p = p + 1;
    if (stir_shaken_zstr(p)) {
        *args_n = 0;
        return STIR_SHAKEN_STATUS_OK;
    }

    args = p;

    if ((p = strchr(p, '/'))) {

        char *pCh = NULL;
        unsigned long long  val;

        // maybe 2 args

        *p = '\0';

        strncpy(arg1, args, arg1_len);

        p = p + 1;
        if (strchr(p, '/')) {
            stir_shaken_set_error(ss, "Bad request URI, too many '/'", STIR_SHAKEN_ERROR_ACME_URI);
            return STIR_SHAKEN_STATUS_FALSE;
        }

        strncpy(arg2, p, arg2_len);
        *args_n = 2;

    } else {

        len = strlen(args);
        if (len > arg1_len) {
            stir_shaken_set_error(ss, "Buffer too short for first arg", STIR_SHAKEN_ERROR_ACME_URI);
            return STIR_SHAKEN_STATUS_FALSE;
        }

        strncpy(arg1, args, arg1_len);
        *args_n = 1;
    }

    return STIR_SHAKEN_STATUS_OK;
}

char* stir_shaken_acme_generate_spc_token(stir_shaken_context_t *ss, char *issuer, char *url, char *nb, char *na, char *spc, unsigned char *key, uint32_t keylen, char **json)
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

    if (issuer) {

        if (jwt_add_header(jwt, "issuer", issuer) != 0) {
            goto exit;
        }
    }

    if (url) {

        if (jwt_add_header(jwt, "x5u", url) != 0) {
            goto exit;
        }
    }

    // Payload

    if (jwt_add_grant(jwt, "type", "spc-token") != 0) {
        goto exit;
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

    if (spc) {

        if (jwt_add_grant(jwt, "spc", spc) != 0) {
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
