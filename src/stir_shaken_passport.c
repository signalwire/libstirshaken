#include "stir_shaken.h"


/* Produce JWT.
 *
 *          // JSON JOSE Header (alg, ppt, typ, x5u)
 *              // alg      This value indicates the encryption algorithm. Must be 'ES256'.
 *              // ppt      This value indicates the extension used. Must be 'shaken'.
 *              // typ      This value indicates the token type. Must be 'passport'.
 *				// x5u      This value indicates the location of the certificate used to sign the token.
 *          // JWS Payload (grants)
 *				// attest   This value indicates the attestation level. Must be either A, B, or C.
 *				// dest     This value indicates the called number(s) or called Uniform Resource Identifier(s).
 *              // iat      This value indicates the timestamp when the token was created. The timestamp is the number of seconds that have passed since the beginning of 00:00:00 UTC 1 January 1970.
 *				// orig     This value indicates the calling number or calling Uniform Resource Identifier.
 *				// origid   This value indicates the origination identifier.
 */
stir_shaken_status_t stir_shaken_jwt_passport_jwt_init(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	if (!jwt) {
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (params) {

		// TODO Produce @jwt from @params

		const char *x5u = params->x5u;
		const char *attest = params->attest;
		const char *desttn_key = params->desttn_key;
		const char *desttn_val = params->desttn_val;
		int iat = params->iat;
		const char *origtn_key = params->origtn_key;
		const char *origtn_val = params->origtn_val;
		const char *origid = params->origid;
		uint8_t ppt_ignore = params->ppt_ignore;


		// Header

		if (jwt_add_header(jwt, "ppt", "shaken") != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}

		if (jwt_add_header(jwt, "typ", "passport") != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}

		if (jwt_add_header(jwt, "x5u", x5u) != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}

		if (key && keylen) {		

			if(jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
				return STIR_SHAKEN_STATUS_ERR;
			}
		}

		// Payload

		if (jwt_add_grant_int(jwt, "iat", iat) != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}

		if (attest && (*attest == 'A' || *attest == 'B' || *attest == 'C')) {
			if (jwt_add_grant(jwt, "attest", attest) != 0) {
				return STIR_SHAKEN_STATUS_ERR;
			}
		}

		if (origid) {
			if (jwt_add_grant(jwt, "origid", origid) != 0) {
				return STIR_SHAKEN_STATUS_ERR;
			}
		}

		if (!origtn_key || !origtn_val) {

			return STIR_SHAKEN_STATUS_ERR;

		} else {

			cJSON *orig = NULL, *tn = NULL, *e = NULL;
			char *jstr = NULL;

			orig = cJSON_CreateObject();
			if (!orig) {
				stir_shaken_set_error(ss, "Passport create json: Error in cjson, @orig", STIR_SHAKEN_ERROR_CJSON);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!strcmp(origtn_key, "uri")) {
			
				tn = cJSON_CreateArray();
				if (!tn) {
					stir_shaken_set_error(ss, "Passport create json: Error in cjson, @origtn [key]", STIR_SHAKEN_ERROR_CJSON);
					cJSON_Delete(orig);
					return STIR_SHAKEN_STATUS_ERR;
				}
				cJSON_AddItemToObject(orig, origtn_key, tn);

				e = cJSON_CreateString(origtn_val);
				if (!e) {
					stir_shaken_set_error(ss, "Passport create json: Error in cjson, @origtn [val]", STIR_SHAKEN_ERROR_CJSON);
					cJSON_Delete(orig);
					return STIR_SHAKEN_STATUS_ERR;
				}
				cJSON_AddItemToArray(tn, e);
			
			} else {
			
				cJSON_AddStringToObject(orig, "tn", origtn_val);
			}

			jstr = cJSON_PrintUnformatted(orig);
			if (!jstr || (jwt_add_grant(jwt, "orig", jstr) != 0)) {
				cJSON_Delete(orig);
				return STIR_SHAKEN_STATUS_ERR;
			}

			cJSON_Delete(orig);
			free(jstr);
		}
	
		if (!desttn_key || !desttn_val) {

			return STIR_SHAKEN_STATUS_ERR;

		} else {

			cJSON *dest = NULL, *tn = NULL, *e = NULL;
			char *jstr = NULL;

			dest = cJSON_CreateObject();
			if (!dest) {
				stir_shaken_set_error(ss, "Passport create json: Error in cjson, @dest", STIR_SHAKEN_ERROR_CJSON);
				return STIR_SHAKEN_STATUS_ERR;
			}

			if (!strcmp(desttn_key, "uri")) {

				tn = cJSON_CreateArray();
				if (!tn) {
					stir_shaken_set_error(ss, "Passport create json: Error in cjson, @desttn [key]", STIR_SHAKEN_ERROR_CJSON);
					cJSON_Delete(dest);
					return STIR_SHAKEN_STATUS_ERR;
				}
				cJSON_AddItemToObject(dest, desttn_key, tn);

				e = cJSON_CreateString(desttn_val);
				if (!e) {
					stir_shaken_set_error(ss, "Passport create json: Error in cjson, @desttn [val]", STIR_SHAKEN_ERROR_CJSON);
					cJSON_Delete(dest);
					return STIR_SHAKEN_STATUS_ERR;
				}
				cJSON_AddItemToArray(tn, e);

			} else {

				cJSON_AddStringToObject(dest, "tn", desttn_val);
			}

			jstr = cJSON_PrintUnformatted(dest);
			if (!jstr || (jwt_add_grant(jwt, "dest", jstr) != 0)) {
				cJSON_Delete(dest);
				return STIR_SHAKEN_STATUS_ERR;
			}

			cJSON_Delete(dest);
			free(jstr);
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_jwt_passport_jwt_init_from_json(stir_shaken_context_t *ss, jwt_t *jwt, const char *headers_json, const char *grants_json, unsigned char *key, uint32_t keylen)
{
	if (!jwt) {
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (headers_json) {

		if (jwt_add_headers_json(jwt, headers_json) != 0) {
			stir_shaken_set_error_if_clear(ss, "JWT init from JSON: Failed to add headers from json", STIR_SHAKEN_ERROR_GENERAL);
			return STIR_SHAKEN_STATUS_TERM;
		}
	}

	if (grants_json) {

		if (jwt_add_grants_json(jwt, grants_json) != 0) {
			stir_shaken_set_error_if_clear(ss, "JWT init from JSON: Failed to add grants from json", STIR_SHAKEN_ERROR_GENERAL);
			return STIR_SHAKEN_STATUS_TERM;
		}
	}

	if (key && keylen) {		

		if(jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
			stir_shaken_set_error_if_clear(ss, "JWT init from JSON: Failed to set algorithm and key", STIR_SHAKEN_ERROR_GENERAL);
			return STIR_SHAKEN_STATUS_ERR;
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

jwt_t* stir_shaken_jwt_passport_jwt_create_new(stir_shaken_context_t *ss)
{
	jwt_t *jwt = NULL;

	if (jwt_new(&jwt) != 0) {

		stir_shaken_set_error_if_clear(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	return jwt;
}

stir_shaken_status_t stir_shaken_jwt_passport_init(stir_shaken_context_t *ss, stir_shaken_jwt_passport_t *where, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	if (!where) return STIR_SHAKEN_STATUS_TERM;

	if (!where->jwt) {

		where->jwt = stir_shaken_jwt_passport_jwt_create_new(ss);
		if (!where->jwt) {
			stir_shaken_set_error_if_clear(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
			return STIR_SHAKEN_STATUS_RESTART;
		}
	}

	if (params) {

		if (stir_shaken_jwt_passport_jwt_init(ss, where->jwt, params, key, keylen) != STIR_SHAKEN_STATUS_OK) {
			stir_shaken_set_error_if_clear(ss, "Cannot init JWT", STIR_SHAKEN_ERROR_GENERAL);
			return STIR_SHAKEN_STATUS_FALSE;
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_jwt_passport_t*	stir_shaken_jwt_passport_create_new(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	stir_shaken_jwt_passport_t	*passport = NULL;

	passport = malloc(sizeof(*passport));
	if (!passport) {
		stir_shaken_set_error_if_clear(ss, "Out of memory", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	passport->jwt = stir_shaken_jwt_passport_jwt_create_new(ss);
	if (!passport->jwt) {
		stir_shaken_set_error_if_clear(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	if (stir_shaken_jwt_passport_init(ss, passport, params, key, keylen) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error_if_clear(ss, "Failed init PASSporT", STIR_SHAKEN_ERROR_GENERAL);
		goto fail;
	}

	return passport;

fail:
	if (passport) {
		stir_shaken_jwt_passport_destroy(passport);
		free(passport);
		passport = NULL;
	}
	stir_shaken_set_error_if_clear(ss, "Failed create new PASSporT", STIR_SHAKEN_ERROR_GENERAL);
	return NULL;
}

void stir_shaken_jwt_passport_destroy(stir_shaken_jwt_passport_t *passport)
{
	if (!passport) return;
	if (passport->jwt) jwt_free(passport->jwt);
	passport->jwt = NULL;
}

stir_shaken_status_t stir_shaken_jwt_passport_sign(stir_shaken_context_t *ss, stir_shaken_jwt_passport_t *passport, unsigned char *key, uint32_t keylen, char **out)
{
	if (!passport || !passport->jwt) return STIR_SHAKEN_STATUS_TERM;

	if (key && keylen) {

		// Install new key

		if(jwt_set_alg(passport->jwt, JWT_ALG_ES256, key, keylen) != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}
	}

	*out = jwt_encode_str(passport->jwt);
	if (!*out) {
		return STIR_SHAKEN_STATUS_RESTART;
	}

	return STIR_SHAKEN_STATUS_OK;
}

// TODO Mallocs memory for identity header, free later
char* stir_shaken_jwt_sip_identity_create(stir_shaken_context_t *ss, stir_shaken_jwt_passport_t *passport, unsigned char *key, uint32_t keylen)
{
    char *sih = NULL;
	char *token = NULL;
	const char *info = NULL, *alg = NULL, *ppt = NULL;
    size_t len = 0;

	stir_shaken_clear_error(ss);

    if (!passport || !passport->jwt) {
		stir_shaken_set_error(ss, "SIP Identity create: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	if ((stir_shaken_jwt_passport_sign(ss, passport, key, keylen, &token) != STIR_SHAKEN_STATUS_OK) || !token) {
		stir_shaken_set_error(ss, "SIP Identity create: Failed to sign JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	info = jwt_get_header(passport->jwt, "x5u");
	alg = jwt_get_header(passport->jwt, "alg");
	ppt = jwt_get_header(passport->jwt, "ppt");

	if (!info || !alg || !ppt) {
		stir_shaken_set_error(ss, "SIP Identity create: Bad JWT", STIR_SHAKEN_ERROR_GENERAL);
		jwt_free_str(token);
		return NULL;
	}

    // extra length of 15 for info=<> alg= ppt=
    len = strlen(token) + 3 + strlen(info) + 1 + strlen(alg) + 1 + strlen(ppt) + 1 + 15;
    sih = malloc(len); // TODO free
    if (!sih) {
		jwt_free_str(token);
		stir_shaken_set_error(ss, "SIP Identity create: Out of memory", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}
	memset(sih, 0, len);
    sprintf(sih, "%s;info=<%s>;alg=%s;ppt=%s", token, info, alg, ppt);

	jwt_free_str(token);

    return sih;
}

/*
 * Authorize the call, forget PASSporT (local PASSporT used and destroyed).
 *
 * Authorize (assert/sign) call identity with cert of Service Provider.
 * 
 * @ss - (in) context to set error if any
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 * @params - (in) describe PASSporT content
 * @key - (in) EC raw key used to sign the JWT token 
 * @keylen - (in) length of the EC raw key used to sign the JWT token 
 *
 * Note: If @keep_passport is true, the PASSporT returned from this function must be destroyed later.
 */
stir_shaken_status_t stir_shaken_jwt_authorize(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	stir_shaken_jwt_passport_t	local_passport = {0};   // It will only allow you to cross this function's border

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_jwt_passport_init(ss, &local_passport, params, key, keylen)) {
		stir_shaken_set_error_if_clear(ss, "JWT Authorize: jwt passport init failed", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_TERM;
	}

	*sih = stir_shaken_jwt_sip_identity_create(ss, &local_passport, key, keylen);
	if (!*sih) {
		stir_shaken_set_error_if_clear(ss, "JWT Authorize: Failed to create SIP Identity Header", STIR_SHAKEN_ERROR_GENERAL);
		stir_shaken_jwt_passport_destroy(&local_passport);
		return STIR_SHAKEN_STATUS_TERM;
	}

	stir_shaken_jwt_passport_destroy(&local_passport);
	return STIR_SHAKEN_STATUS_OK;
}

char* stir_shaken_jwt_passport_dump_str(stir_shaken_jwt_passport_t *passport, uint8_t pretty)
{
	if (!passport || !passport->jwt) return NULL;

	return jwt_dump_str(passport->jwt, pretty);
}

void stir_shaken_jwt_passport_free_str(char *s)
{
	if (!s) return;
	jwt_free_str(s);
}
