#include "stir_shaken.h"


/* Use this to destroy params struct only if it has been initialized with dynamic strings (not stored in static memory). */
void stir_shaken_passport_params_destroy(stir_shaken_passport_params_t *params)
{
	if (!params) return;
	free((char*)params->x5u);
	free((char*)params->origtn_key);
	free((char*)params->origtn_val);
	free((char*)params->desttn_key);
	free((char*)params->desttn_val);
	free((char*)params->origid);
	free((char*)params->attest);
	memset(params, 0, sizeof(*params));
}

/* Produce JWT.
 *
 * The Personal Assertion Token, PASSporT: https://tools.ietf.org/html/rfc8225.
 *
 * JSON web token (JWT)
 *		JSON JOSE Header (alg, ppt, typ, x5u)
 *			alg      This value indicates the encryption algorithm. Must be 'ES256'.
 *			ppt      This value indicates the extension used. Must be 'shaken'.
 *			typ      This value indicates the token type. Must be 'passport'.
 *			x5u      This value indicates the location of the certificate used to sign the token.
 *		JWS Payload
 *			attest   This value indicates the attestation level. Must be either A, B, or C. (This is Shaken extension to PASSporT)
 *			dest     This value indicates the called number(s) or called Uniform Resource Identifier(s).
 *			iat      This value indicates the timestamp when the token was created. The timestamp is the number of seconds that have passed since the beginning of 00:00:00 UTC 1 January 1970.
 *			orig     This value indicates the calling number or calling Uniform Resource Identifier.
 *			origid   This value indicates the origination identifier. (This is Shaken extension to PASSporT)
 */
stir_shaken_status_t stir_shaken_passport_jwt_init(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	if (!jwt) {
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (params) {

		const char *x5u = params->x5u;
		const char *attest = params->attest;
		const char *desttn_key = params->desttn_key;
		const char *desttn_val = params->desttn_val;
		int iat = params->iat;
		const char *origtn_key = params->origtn_key;
		const char *origtn_val = params->origtn_val;
		const char *origid = params->origid;


		// Header

		if (jwt_add_header(jwt, "ppt", "shaken") != 0) {
			stir_shaken_set_error(ss, "Failed to add @ppt to PASSporT", STIR_SHAKEN_ERROR_JWT_ADD_HDR_PPT);
			return STIR_SHAKEN_STATUS_ERR;
		}

		if (jwt_add_header(jwt, "typ", "passport") != 0) {
			stir_shaken_set_error(ss, "Failed to add @typ to PASSporT", STIR_SHAKEN_ERROR_JWT_ADD_HDR_TYP);
			return STIR_SHAKEN_STATUS_ERR;
		}

		if (jwt_add_header(jwt, "x5u", x5u) != 0) {
			stir_shaken_set_error(ss, "Failed to add @x5u to PASSporT", STIR_SHAKEN_ERROR_JWT_ADD_HDR_X5U);
			return STIR_SHAKEN_STATUS_ERR;
		}

		if (key && keylen) {		

			if(jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
				stir_shaken_set_error(ss, "Failed to add @alg to PASSporT", STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_1);
				return STIR_SHAKEN_STATUS_ERR;
			}
		}

		// Payload
		{
			char *jstr = NULL;
			ks_json_t *json = ks_json_create_object();

			if (!json) {
				stir_shaken_set_error(ss, "Passport can't create JSON object", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_2);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!ks_json_add_number_to_object(json, "iat", iat)) {
				stir_shaken_set_error(ss, "Failed to add @iat to PASSporT", STIR_SHAKEN_ERROR_KSJSON_ADD_IAT);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!attest) {
				stir_shaken_set_error(ss, "Passport @attest is missing", STIR_SHAKEN_ERROR_PASSPORT_ATTEST_MISSING);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!((*attest == 'A' || *attest == 'B' || *attest == 'C') && attest[1] == '\0')) {
				stir_shaken_set_error(ss, "Passport @attest must be 'A', 'B' or 'C'", STIR_SHAKEN_ERROR_PASSPORT_ATTEST_VALUE);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!ks_json_add_string_to_object(json, "attest", attest)) {
				stir_shaken_set_error(ss, "Failed to add @attest to PASSporT", STIR_SHAKEN_ERROR_KSJSON_ADD_ATTEST);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!origid) {
				stir_shaken_set_error(ss, "Passport @origid is missing", STIR_SHAKEN_ERROR_PASSPORT_ORIGID_MISSING);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!ks_json_add_string_to_object(json, "origid", origid)) {
				stir_shaken_set_error(ss, "Failed to add @origid to PASSporT", STIR_SHAKEN_ERROR_KSJSON_ADD_ORIGID);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!origtn_val) {

				stir_shaken_set_error(ss, "PASSporT @origtn_val missing", STIR_SHAKEN_ERROR_PASSPORT_ORIG_TN_MISSING);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;

			} else {

				ks_json_t *orig = NULL, *tn = NULL, *e = NULL;

				orig = ks_json_create_object();
				if (!orig) {
					stir_shaken_set_error(ss, "Passport create json: Error in ks_json, @orig", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_ORIG);
					ks_json_delete(&json);
					return STIR_SHAKEN_STATUS_ERR;
				}

				// If @origtn_key is NULL or empty, use "tn" form

				if (origtn_key && !strcmp(origtn_key, "uri")) {

					tn = ks_json_create_array();
					if (!tn) {
						stir_shaken_set_error(ss, "Passport create json: Error in ks_json, can't create @orig array", STIR_SHAKEN_ERROR_KSJSON_CREATE_ARRAY_ORIG);
						ks_json_delete(&orig);
						ks_json_delete(&json);
						return STIR_SHAKEN_STATUS_ERR;
					}

					if (!ks_json_add_string_to_array(tn, origtn_val)) {
						stir_shaken_set_error(ss, "Passport create json: Failed to add @orig to array", STIR_SHAKEN_ERROR_KSJSON_ADD_ORIG_TO_ARRAY);
						ks_json_delete(&tn);
						ks_json_delete(&orig);
						ks_json_delete(&json);
						return STIR_SHAKEN_STATUS_ERR;
					}

					if (!ks_json_add_item_to_object(orig, origtn_key, tn)) {
						stir_shaken_set_error(ss, "Passport create json: Failed to add @orig array", STIR_SHAKEN_ERROR_KSJSON_ADD_ORIG_ARRAY);
						ks_json_delete(&tn);
						ks_json_delete(&orig);
						ks_json_delete(&json);
						return STIR_SHAKEN_STATUS_ERR;
					}

				} else {

					if (!ks_json_add_string_to_object(orig, "tn", origtn_val)) {
						stir_shaken_set_error(ss, "Passport create json: Failed to add @origtn", STIR_SHAKEN_ERROR_KSJSON_ADD_TN);
						ks_json_delete(&orig);
						ks_json_delete(&json);
						return STIR_SHAKEN_STATUS_ERR;
					}
				}

				if (!ks_json_add_item_to_object(json, "orig", orig)) {
					stir_shaken_set_error(ss, "Passport create json: Failed to add @orig", STIR_SHAKEN_ERROR_KSJSON_ADD_ORIG);
					ks_json_delete(&orig);
					ks_json_delete(&json);
					return STIR_SHAKEN_STATUS_ERR;
				}
			}

			if (!desttn_val) {

				stir_shaken_set_error(ss, "PASSporT @desttn_val missing", STIR_SHAKEN_ERROR_PASSPORT_DEST_TN_MISSING);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_ERR;

			} else {

				ks_json_t *dest = NULL, *tn = NULL, *e = NULL;

				dest = ks_json_create_object();
				if (!dest) {
					stir_shaken_set_error(ss, "Passport create json: Error in ks_json, @dest", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_DEST);
					ks_json_delete(&json);
					return STIR_SHAKEN_STATUS_ERR;
				}

				// For @dest grant always use array format

				tn = ks_json_create_array();
				if (!tn) {
					stir_shaken_set_error(ss, "Passport create json: Error in ks_json, @desttn array", STIR_SHAKEN_ERROR_KSJSON_CREATE_ARRAY_DEST);
					ks_json_delete(&dest);
					ks_json_delete(&json);
					return STIR_SHAKEN_STATUS_ERR;
				}

				if (!ks_json_add_string_to_array(tn, desttn_val)) {
						stir_shaken_set_error(ss, "Passport create json: Failed to add @desttn to array", STIR_SHAKEN_ERROR_KSJSON_ADD_DEST_TO_ARRAY);
						ks_json_delete(&tn);
						ks_json_delete(&dest);
						ks_json_delete(&json);
						return STIR_SHAKEN_STATUS_ERR;
					}

				// If @desttn_key is NULL or empty, use "tn" form

				if ((stir_shaken_zstr(desttn_key) && !ks_json_add_item_to_object(dest, "tn", tn)) || (!stir_shaken_zstr(desttn_key) && !ks_json_add_item_to_object(dest, desttn_key, tn))) {
					stir_shaken_set_error(ss, "Passport create json: Failed to add @dest array", STIR_SHAKEN_ERROR_KSJSON_ADD_DEST_ARRAY);
					ks_json_delete(&tn);
					ks_json_delete(&dest);
					ks_json_delete(&json);
					return STIR_SHAKEN_STATUS_ERR;
				}

				if (!ks_json_add_item_to_object(json, "dest", dest)) {
					stir_shaken_set_error(ss, "Passport create json: Failed to add @dest", STIR_SHAKEN_ERROR_KSJSON_ADD_DEST);
					ks_json_delete(&dest);
					ks_json_delete(&json);
					return STIR_SHAKEN_STATUS_ERR;
				}
			}

			jstr = ks_json_print_unformatted(json);
			if (!jstr) {
				stir_shaken_set_error(ss, "JWT init from JSON: Failed to print json", STIR_SHAKEN_ERROR_PASSPORT_JWT_PRINT_JSON);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_TERM;
			}

			if (jwt_add_grants_json(jwt, jstr) != 0) {
				stir_shaken_set_error(ss, "JWT init from JSON: Failed to add grants from json", STIR_SHAKEN_ERROR_PASSPORT_JWT_ADD_GRANTS_JSON);
				ks_json_delete(&json);
				return STIR_SHAKEN_STATUS_TERM;
			}

			ks_json_delete(&json);
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_passport_jwt_init_from_json(stir_shaken_context_t *ss, jwt_t *jwt, const char *headers_json, const char *grants_json, unsigned char *key, uint32_t keylen)
{
	if (!jwt) {
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (headers_json) {

		if (jwt_add_headers_json(jwt, headers_json) != 0) {
			stir_shaken_set_error(ss, "JWT init from JSON: Failed to add headers from json", STIR_SHAKEN_ERROR_JWT_ADD_HEADERS_JSON);
			return STIR_SHAKEN_STATUS_TERM;
		}
	}

	if (grants_json) {

		if (jwt_add_grants_json(jwt, grants_json) != 0) {
			stir_shaken_set_error(ss, "JWT init from JSON: Failed to add grants from json", STIR_SHAKEN_ERROR_JWT_ADD_GRANTS_JSON);
			return STIR_SHAKEN_STATUS_TERM;
		}
	}

	if (key && keylen) {		

		if(jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
			stir_shaken_set_error(ss, "JWT init from JSON: Failed to set algorithm and key", STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_2);
			return STIR_SHAKEN_STATUS_ERR;
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

jwt_t* stir_shaken_passport_jwt_create_new(stir_shaken_context_t *ss)
{
	jwt_t *jwt = NULL;

	if (jwt_new(&jwt) != 0) {

		stir_shaken_set_error(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	return jwt;
}

stir_shaken_status_t stir_shaken_passport_init(stir_shaken_context_t *ss, stir_shaken_passport_t *where, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	if (!where) return STIR_SHAKEN_STATUS_TERM;

	if (!where->jwt) {

		where->jwt = stir_shaken_passport_jwt_create_new(ss);
		if (!where->jwt) {
			stir_shaken_set_error(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_PASSPORT_JWT_CREATE_1);
			return STIR_SHAKEN_STATUS_RESTART;
		}
	}

	if (params) {

		if (stir_shaken_passport_jwt_init(ss, where->jwt, params, key, keylen) != STIR_SHAKEN_STATUS_OK) {
			stir_shaken_set_error(ss, "Cannot init JWT", STIR_SHAKEN_ERROR_PASSPORT_JWT_INIT);
			return STIR_SHAKEN_STATUS_FALSE;
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

void stir_shaken_passport_deinit(stir_shaken_passport_t *passport)
{
	if (!passport) return;
	if (passport->jwt) jwt_free(passport->jwt);
	passport->jwt = NULL;
}

stir_shaken_passport_t*	stir_shaken_passport_create(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	stir_shaken_passport_t	*passport = NULL;

	passport = malloc(sizeof(*passport));
	if (!passport) {
		stir_shaken_set_error(ss, "Can't allocate passport", STIR_SHAKEN_ERROR_MEM_PASSPORT);
		return NULL;
	}
	memset(passport, 0, sizeof(*passport));

	passport->jwt = stir_shaken_passport_jwt_create_new(ss);
	if (!passport->jwt) {
		stir_shaken_set_error(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_PASSPORT_JWT_CREATE_2);
		goto fail;
	}

	if (stir_shaken_passport_init(ss, passport, params, key, keylen) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "Failed init PASSporT", STIR_SHAKEN_ERROR_PASSPORT_INIT_2);
		goto fail;
	}

	return passport;

fail:
	if (passport) {
		stir_shaken_passport_destroy(&passport);
	}
	return NULL;
}

void stir_shaken_passport_destroy(stir_shaken_passport_t **passport)
{
	if (!passport || *passport == NULL) return;
	stir_shaken_passport_deinit(*passport);
	free(*passport);
	*passport = NULL;
}

stir_shaken_status_t stir_shaken_passport_sign(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, unsigned char *key, uint32_t keylen, char **out)
{
	if (!passport || !passport->jwt) return STIR_SHAKEN_STATUS_TERM;

	if (key && keylen) {

		// Install new key

		if(jwt_set_alg(passport->jwt, JWT_ALG_ES256, key, keylen) != 0) {
			stir_shaken_set_error(ss, "JWT PASSporT Sign: Failed to set key and algorithm on JWT", STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_3);
			return STIR_SHAKEN_STATUS_ERR;
		}
	}

	*out = jwt_encode_str(passport->jwt);
	if (!*out) {
		stir_shaken_set_error(ss, "JWT PASSporT Sign: Failed to encode JWT", STIR_SHAKEN_ERROR_JWT_ENCODE);
		return STIR_SHAKEN_STATUS_RESTART;
	}

	return STIR_SHAKEN_STATUS_OK;
}

// TODO Mallocs memory for identity header, free later
char* stir_shaken_jwt_sip_identity_create(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, unsigned char *key, uint32_t keylen)
{
    char *sih = NULL;
	char *token = NULL;
	const char *info = NULL, *alg = NULL, *ppt = NULL;
    size_t len = 0;

	stir_shaken_clear_error(ss);

    if (!passport || !passport->jwt) {
		stir_shaken_set_error(ss, "SIP Identity create: Bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
		return NULL;
	}

	if ((stir_shaken_passport_sign(ss, passport, key, keylen, &token) != STIR_SHAKEN_STATUS_OK) || !token) {
		stir_shaken_set_error(ss, "SIP Identity create: Failed to sign JWT", STIR_SHAKEN_ERROR_PASSPORT_SIGN);
		return NULL;
	}

	info = stir_shaken_passport_get_header(ss, passport, "x5u");
	if (stir_shaken_zstr(info)) {
		stir_shaken_set_error(ss, "SIP Identity create: @x5u missing", STIR_SHAKEN_ERROR_PASSPORT_X5U);
		return NULL;
	}

	alg = stir_shaken_passport_get_header(ss, passport, "alg");
	if (stir_shaken_zstr(alg)) {
		stir_shaken_set_error(ss, "SIP Identity create: @alg missing", STIR_SHAKEN_ERROR_PASSPORT_ALG);
		return NULL;
	}

	ppt = stir_shaken_passport_get_header(ss, passport, "ppt");
	if (stir_shaken_zstr(ppt)) {
		stir_shaken_set_error(ss, "SIP Identity create: @ppt missing", STIR_SHAKEN_ERROR_PASSPORT_PPT);
		return NULL;
	}

    // extra length of 15 for info=<> alg= ppt=
    len = strlen(token) + 3 + strlen(info) + 1 + strlen(alg) + 1 + strlen(ppt) + 1 + 15;
    sih = malloc(len);
    if (!sih) {
		jwt_free_str(token);
		stir_shaken_set_error(ss, "SIP Identity create: Out of memory", STIR_SHAKEN_ERROR_MEM_SIH);
		return NULL;
	}
	memset(sih, 0, len);
    snprintf(sih, len, "%s;info=<%s>;alg=%s;ppt=%s", token, info, alg, ppt);

	jwt_free_str(token);

    return sih;
}

/*
 * Authenticate the call, forget PASSporT (local PASSporT used and destroyed).
 *
 * Authenticate (assert/sign) call identity with cert of Service Provider.
 * 
 * @ss - (in) context to set error if any
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 * @params - (in) describe PASSporT content
 * @key - (in) EC raw key used to sign the JWT token 
 * @keylen - (in) length of the EC raw key used to sign the JWT token
 * @passport - (out) result PASSporT 
 *
 */
stir_shaken_status_t stir_shaken_jwt_authenticate_keep_passport(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen, stir_shaken_passport_t **passport_out)
{
	stir_shaken_passport_t *passport = NULL;


	passport = stir_shaken_passport_create(ss, params, key, keylen);
	if (!passport) {
		stir_shaken_set_error(ss, "Failed to create PASSporT", STIR_SHAKEN_ERROR_PASSPORT_CREATE_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	*sih = stir_shaken_jwt_sip_identity_create(ss, passport, key, keylen);
	if (!*sih) {
		stir_shaken_set_error(ss, "Failed to create SIP Identity Header from JWT PASSporT", STIR_SHAKEN_ERROR_SIH_CREATE);
		stir_shaken_passport_destroy(&passport);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (passport_out) {
		*passport_out = passport;
	} else {
		stir_shaken_passport_destroy(&passport);
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_jwt_authenticate(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	return stir_shaken_jwt_authenticate_keep_passport(ss, sih, params, key, keylen, NULL);
}

char* stir_shaken_passport_dump_str(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, uint8_t pretty)
{
	if (!passport || !passport->jwt) {
		stir_shaken_set_error(ss, "Bad params (passport or jwt missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_2);
		return NULL;
	}

	return jwt_dump_str(passport->jwt, pretty);
}

void stir_shaken_free_jwt_str(char *s)
{
	if (!s) return;
	jwt_free_str(s);
}

/*
 * NOTE: @passport takes sownership of @jwt.
 */
jwt_t* stir_shaken_jwt_move_to_passport(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_passport_t *passport)
{
	if (!passport) {
		stir_shaken_set_error(ss, "PASSporT jwt move to PASSporT: bad params (passport missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_3);
		return NULL;
	}

	if (passport->jwt) jwt_free(passport->jwt);
	passport->jwt = jwt;
	return jwt;
}

const char* stir_shaken_passport_get_header(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key)
{
	if (!passport || !key) {
		stir_shaken_set_error(ss, "PASSporT get header: bad params (passport or key missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_4);
		return NULL;
	}

	return jwt_get_header(passport->jwt, key);

}

/**
 * Returns headers in JSON. Must be freed by caller.
 */
char* stir_shaken_passport_get_headers_json(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key)
{
	if (!passport || !key) {
		stir_shaken_set_error(ss, "PASSporT get headers json: bad params (passport or key missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_5);
		return NULL;
	}

	return jwt_get_headers_json(passport->jwt, key);
}

const char* stir_shaken_passport_get_grant(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key)
{
	if (!passport || !key) {
		stir_shaken_set_error(ss, "PASSporT get grant json: bad params (passport or key missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_6);
		return NULL;
	}

	return jwt_get_grant(passport->jwt, key);
}

long int stir_shaken_passport_get_grant_int(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key)
{
	if (!passport || !key) {
		stir_shaken_set_error(ss, "PASSporT get grant int: bad params (passport or key missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_7);
		errno = ENOENT;
		return 0;
	}

	return jwt_get_grant_int(passport->jwt, key);
}

/**
 * Returns grants in JSON. Must be freed by caller.
 */
char* stir_shaken_passport_get_grants_json(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key)
{
	if (!passport || !key) {
		stir_shaken_set_error(ss, "PASSporT get grants json: bad params (passport or key missing)", STIR_SHAKEN_ERROR_BAD_PARAMS_8);
		return NULL;
	}

	return jwt_get_grants_json(passport->jwt, key);
}

/**
 * Returns id if found. Must be freed by caller.
 */
char* stir_shaken_passport_get_identity(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, int *is_tn)
{
	char *id = NULL;
	char *orig = NULL;
	int tn_form = 0;
	int id_int = 0;
	ks_json_t *item = NULL;
	ks_json_t *origjson = NULL;

	if (!passport) return NULL;

	orig = stir_shaken_passport_get_grants_json(ss, passport, "orig");
	if (!orig) {
		stir_shaken_set_error(ss, "@orig grant is missing", STIR_SHAKEN_ERROR_PASSPORT_ORIG_MISSING);
		return NULL;
	}

	origjson = ks_json_parse(orig);
	if (!origjson) {
		stir_shaken_set_error(ss, "Failed to convert @orig to JSON", STIR_SHAKEN_ERROR_PASSPORT_ORIG_PARSE);
		free(orig);
		return NULL;
	}

	if (ks_json_type_get(origjson) == KS_JSON_TYPE_ARRAY) {

		item = ks_json_get_array_item(origjson, 0);
		if (!item) {
			stir_shaken_set_error(ss, "@orig array is empty", STIR_SHAKEN_ERROR_PASSPORT_ARRAY_ITEM);
			ks_json_delete(&origjson);
			free(orig);
			return NULL;
		}

		if (ks_json_get_object_item(item, "tn")) {
			tn_form = 1;
		}

	} else {

		ks_json_t *tn = NULL;

		if ((item = ks_json_get_object_item(origjson, "tn"))) {
		
			tn_form = 1;

		} else if ((item = ks_json_get_object_item(origjson, "uri"))) {

			tn_form = 0;

		} else {
				stir_shaken_set_error(ss, "@orig grant is neither in @tn nor @uri form", STIR_SHAKEN_ERROR_PASSPORT_ORIG_FORM);
				ks_json_delete(&origjson);
				free(orig);
				return NULL;
		}
	}

	if (ks_json_type_get(item) == KS_JSON_TYPE_STRING) {
		id = strdup(ks_json_value_string(item));
	} else if (ks_json_type_get(item) == KS_JSON_TYPE_NUMBER) {
		id_int = ks_json_value_number_int(item);
		id = malloc(20);
		if (!id) {
			stir_shaken_set_error(ss, "Not enough memory", STIR_SHAKEN_ERROR_MEM_ID);
			ks_json_delete(&origjson);
			free(orig);
			return NULL;
		}
		snprintf(id, 20, "%d", id_int);
	} else {
		stir_shaken_set_error(ss, "@orig's @tn/@uri is neither string nor number", STIR_SHAKEN_ERROR_PASSPORT_ORIG_TN_URI_TYPE);
		ks_json_delete(&origjson);
		free(orig);
		return NULL;
	}

	if (is_tn) *is_tn = tn_form;
	ks_json_delete(&origjson);
	free(orig);
	return id;
}

/**
 * Validate that the PASSporT includes all of the baseline claims.
 */
stir_shaken_status_t stir_shaken_passport_validate_headers(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	char err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	const char *h = NULL;

	if (!passport) return STIR_SHAKEN_STATUS_TERM;
	
	h = stir_shaken_passport_get_header(ss, passport, "alg");
	if (!h || strcmp(h, "ES256")) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @alg should be 'ES256' but is (%s)", h);  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_ALG);	
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "ppt");
	if (!h || strcmp(h, "shaken")) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @ppt should be 'shaken' but is (%s)", h);  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_PPT);	
		return STIR_SHAKEN_STATUS_FALSE;
	}
	
	h = stir_shaken_passport_get_header(ss, passport, "typ");
	if (!h || strcmp(h, "passport")) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @typ should be 'passport' but is (%s)", h);  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_TYP);	
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "x5u");
	if (stir_shaken_zstr(h)) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @x5u is missing");  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_X5U);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

/**
 * Validate that the PASSporT includes the SHAKEN extension claims.
 */
stir_shaken_status_t stir_shaken_passport_validate_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	char err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	const char *h = NULL;
	long int iat = -1;

	if (!passport) return STIR_SHAKEN_STATUS_TERM;

	iat = stir_shaken_passport_get_grant_int(ss, passport, "iat");
	if (errno == ENOENT) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @iat is missing");  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (iat == 0 ) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @iat is 0");  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_grant(ss, passport, "origid");
	if (!h || !strcmp(h, "")) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @origid is missing");  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_ORIGID);
		return STIR_SHAKEN_STATUS_FALSE;
	}
	
	h = stir_shaken_passport_get_grant(ss, passport, "attest");
	if (!h || !strcmp(h, "")) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @attest is missing");  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_ATTEST);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_grants_json(ss, passport, "orig");
	if (!h || !strcmp(h, "")) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @orig is missing");  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_ORIG);
		if (h) free((char*)h);
		return STIR_SHAKEN_STATUS_FALSE;
	}
	free((char*)h);
	h = NULL;

	h = stir_shaken_passport_get_grants_json(ss, passport, "dest");
	if (!h || !strcmp(h, "")) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT Invalid. @dest is missing");  
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		if (h) free((char*)h);
		return STIR_SHAKEN_STATUS_FALSE;
	}
	free((char*)h);
	h = NULL;

	return STIR_SHAKEN_STATUS_OK;
}

/**
 * Validate that the PASSporT includes all of the baseline claims, as well as the SHAKEN extension claims.
 */
stir_shaken_status_t stir_shaken_passport_validate_headers_and_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;

	if (!passport) return STIR_SHAKEN_STATUS_TERM;

	status = stir_shaken_passport_validate_headers(ss, passport);
	if (status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "PASSporT headers invalid", STIR_SHAKEN_ERROR_PASSPORT_HEADERS_INVALID);
		return status;
	}
	
	status = stir_shaken_passport_validate_grants(ss, passport);
	if (status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "PASSporT grants invalid", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		return status;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_passport_validate_iat_against_freshness(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, time_t iat_freshness)
{
	char	err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	time_t	iat = 0;
	time_t	now_s = time(NULL);


	// Validate @iat against @iat freshness

	if (!passport) {
		stir_shaken_set_error(ss, "Verify PASSporT @iat against: Bad params", STIR_SHAKEN_ERROR_PASSPORT_MISSING_3);
        return -1;
	}

	if (iat_freshness >= now_s) {
		return STIR_SHAKEN_STATUS_OK;
	}

	iat = stir_shaken_passport_get_grant_int(ss, passport, "iat");
	if (errno == ENOENT || iat == 0) {
		stir_shaken_set_error(ss, "PASSporT must have @iat param (application should reply with SIP 438 INVALID IDENTITY HEADER error)\n", STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (now_s < iat) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT's @iat (in seconds) is: %zu, freshness is: %zu, BUT now is %zu (this is PASSporT to the future, too young, not valid yet)", iat, iat_freshness, now_s);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_FUTURE);
		return STIR_SHAKEN_STATUS_ERR;
	}

	if (iat + iat_freshness < now_s) {
		snprintf(err_buf, STIR_SHAKEN_ERROR_BUF_LEN, "PASSporT's @iat (in seconds) is: %zu, freshness is: %zu, BUT now is %zu (PASSporT too old, expired)", iat, iat_freshness, now_s);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_EXPIRED);
		return STIR_SHAKEN_STATUS_ERR;
	}

	return STIR_SHAKEN_STATUS_OK;
}
