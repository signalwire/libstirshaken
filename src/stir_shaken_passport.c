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

jwt_t* stir_shaken_jwt_passport_jwt_create_new(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	jwt_t *jwt = NULL;

	if (jwt_new(&jwt) != 0) {

		stir_shaken_set_error_if_clear(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	if (params) {

		if (stir_shaken_jwt_passport_jwt_init(ss, jwt, params, key, keylen) != STIR_SHAKEN_STATUS_OK) {
			jwt_free(jwt);
			stir_shaken_set_error_if_clear(ss, "Cannot init JWT", STIR_SHAKEN_ERROR_GENERAL);
			return NULL;
		}
	}

	return jwt;
}

stir_shaken_status_t stir_shaken_jwt_passport_init(stir_shaken_context_t *ss, stir_shaken_jwt_passport_t *where, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	if (!where) return STIR_SHAKEN_STATUS_TERM;

	if (!where->jwt) {
		
		if ((where->jwt = stir_shaken_jwt_passport_jwt_create_new(ss, params, key, keylen)) == NULL) {
			return STIR_SHAKEN_STATUS_RESTART;
		}

	} else {

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

	if (params) {

		// Create JWT from params
		passport->jwt = stir_shaken_jwt_passport_jwt_create_new(ss, params, key, keylen);
		if (!passport->jwt) {
			free(passport);
			stir_shaken_set_error_if_clear(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
			return NULL;
		}
	}

	return passport;
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

void stir_shaken_jwt_passport_destroy(stir_shaken_jwt_passport_t *passport)
{
	if (!passport) return;
	jwt_free(passport->jwt);
	passport->jwt = NULL;
}

// TODO Mallocs memory for identity header, free later
char* stir_shaken_jwt_sip_identity_create(stir_shaken_context_t *ss, stir_shaken_jwt_passport_t *passport, unsigned char *key, uint32_t keylen)
{
    char *sih = NULL;
	char *token = NULL;
	const char *info = NULL, *alg = NULL, *ppt = NULL;
    size_t len = 0;

	stir_shaken_clear_error(ss);

    if (!passport || !passport->jwt || !key || !keylen) {
		stir_shaken_set_error(ss, "SIP Identity create: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	info = jwt_get_header(passport->jwt, "info");
	alg = jwt_get_header(passport->jwt, "alg");
	ppt = jwt_get_header(passport->jwt, "ppt");

	if (!info || !alg || !ppt) {
		stir_shaken_set_error(ss, "SIP Identity create: Bad JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	if ((stir_shaken_jwt_passport_sign(ss, passport, key, keylen, &token) != STIR_SHAKEN_STATUS_OK) || !token) {
		stir_shaken_set_error(ss, "SIP Identity create: Failed to sign JWT", STIR_SHAKEN_ERROR_GENERAL);
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
 * Sign the call data with the @key, and keep pointer to created PASSporT (if @keep_passport is true). 
 * SIP Identity header is returned (and PASSporT if @keep_passport is true).
 * @ss - (in) context to set error if any
 * @params - (in) describe PASSporT content
 * @key - (in) EC raw key used to sign the JWT token 
 * @keylen - (in) length of the EC raw key used to sign the JWT token 
 * @passport - (out) will point to created PASSporT
 * @keep_passport - (in) false if PASSporT is not needed (is destroyed then inside this method after SIP Identity Header is returned), true if PASSporT should not be destroyed (@passport points then to it)
 *
 * Note: If @keep_passport is true, the PASSporT returned from this function must be destroyed later.
 */
char* stir_shaken_jwt_do_sign_keep_passport(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen, stir_shaken_jwt_passport_t **passport, uint8_t keep_passport)
{
    char					*sih = NULL;
    stir_shaken_jwt_passport_t	local_passport = {0};   // It will only allow you to cross this function's border
	
	
	stir_shaken_clear_error(ss);

    if (!key || !keylen || !params) {
		stir_shaken_set_error(ss, "JWT Do sign keep passport: Bad params", STIR_SHAKEN_ERROR_GENERAL);
        return NULL;
	}

    // Create PASSporT
    if (keep_passport) {

        *passport = stir_shaken_jwt_passport_create_new(ss, params, key, keylen);
        if (!*passport) {
			stir_shaken_set_error(ss, "JWT Do sign keep passport: Failed to create new PASSporT", STIR_SHAKEN_ERROR_GENERAL);
            goto err;
		}

        // Sign PASSpoprT and create SIP Identity header
        sih = stir_shaken_jwt_sip_identity_create(ss, *passport, key, keylen);
        if (!sih) {
			stir_shaken_set_error_if_clear(ss, "JWT Do sign keep passport: SIP Identity create failed [1]", STIR_SHAKEN_ERROR_GENERAL);
            goto err;
        }

    } else {

        if (STIR_SHAKEN_STATUS_OK != stir_shaken_jwt_passport_init(ss, &local_passport, params, key, keylen)) {
			stir_shaken_set_error_if_clear(ss, "JWT Do sign keep passport: jwt passport init failed", STIR_SHAKEN_ERROR_GENERAL);
            return NULL;
        }

        // Create SIP Identity header
        sih = stir_shaken_jwt_sip_identity_create(ss, &local_passport, key, keylen);
        if (!sih) {
			stir_shaken_jwt_passport_destroy(&local_passport);
			stir_shaken_set_error_if_clear(ss, "JWT Do sign keep passport: SIP Identity create failed [2]", STIR_SHAKEN_ERROR_GENERAL);
            return NULL;
        }

		stir_shaken_jwt_passport_destroy(&local_passport);
    }

    return sih;

err:
	if (*passport) {
		stir_shaken_jwt_passport_destroy(*passport);
		free(*passport);
		*passport = NULL;
	}
	stir_shaken_set_error_if_clear(ss, "JWT Do sign keep passport: Error", STIR_SHAKEN_ERROR_GENERAL);

    return NULL;
}

/*
 * Sign the call data with the @key. 
 * Local PASSporT object is created and destroyed. Only SIP Identity header is returned.
 * If you want to keep the PASSporT, then use stir_shaken_jwt_do_sign_keep_passport instead.
 *
 * External parameters that must be given to this method to be able to sign the SDP:
 * X means "needed"
 *
 *      // Signed JSON web token (JWT)
 *          // JSON JOSE Header (alg, ppt, typ, x5u)
 *              // alg      This value indicates the encryption algorithm. Must be 'ES256'.
 *              // ppt      This value indicates the extension used. Must be 'shaken'.
 *              // typ      This value indicates the token type. Must be 'passport'.
 * X            // x5u      This value indicates the location of the certificate used to sign the token.
 *          // JWS Payload (grants)
 * X            // attest   This value indicates the attestation level. Must be either A, B, or C.
 * X            // dest     This value indicates the called number(s) or called Uniform Resource Identifier(s).
 *              // iat      This value indicates the timestamp when the token was created. The timestamp is the number of seconds that have passed since the beginning of 00:00:00 UTC 1 January 1970.
 * X            // orig     This value indicates the calling number or calling Uniform Resource Identifier.
 * X            // origid   This value indicates the origination identifier.
 *          // JWS Signature
 *
 *      // Parameters
 *          //Alg
 * X(==x5u) //Info
 *          //PPT
 */ 
char* stir_shaken_jwt_do_sign(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	stir_shaken_clear_error(ss);

    if (!key || !keylen ||  !params) {
		
		stir_shaken_set_error(ss, "JWT Do sign: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

    return stir_shaken_jwt_do_sign_keep_passport(ss, params, key, keylen, NULL, 0);
}

/*
 * Authorize (assert/sign) call identity with cert of Service Provider.
 * If @keep_passport is true then keep pointer to PASSporT.
 * 
 * @ss - (in) context to set error if any
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 * @params - (in) describe PASSporT content
 * @passport - (out) will point to created PASSporT
 * @keep_passport - (in) false if PASSporT is not needed (is destroyed then inside this method after SIP Identity Header is returned), true if PASSporT should not be destroyed (@passport points then to it)
 * @key - (in) EC raw key used to sign the JWT token 
 * @keylen - (in) length of the EC raw key used to sign the JWT token 
 *
 * Note: If @keep_passport is true, the PASSporT returned from this function must be destroyed later.
 */
stir_shaken_status_t stir_shaken_jwt_authorize_keep_passport(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, stir_shaken_jwt_passport_t **passport, uint8_t keep_passport, unsigned char *key, uint32_t keylen, stir_shaken_cert_t *cert)
{
    /* Let's start from this. */
    *sih = NULL;
	
	stir_shaken_clear_error(ss);

    if (!params || !params->attest || (*params->attest != 'A' && *params->attest != 'B' && *params->attest != 'C') || !key || !keylen) {
		
		stir_shaken_set_error(ss, "JWT Authorize keep passport: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

    /* Assert/sign call identity with a private key associated with cert. */
    
    *sih = stir_shaken_jwt_do_sign_keep_passport(ss, params, key, keylen, passport, keep_passport);
    if (!*sih) {
		
		stir_shaken_set_error_if_clear(ss, "JWT Authorize keep passport: JWT Do sign keep passport failed", STIR_SHAKEN_ERROR_GENERAL);
        goto err;
    }

    return STIR_SHAKEN_STATUS_OK;

err:
    
	stir_shaken_set_error_if_clear(ss, "JWT Authorize keep passport: Error", STIR_SHAKEN_ERROR_GENERAL);

    return STIR_SHAKEN_STATUS_FALSE;
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
stir_shaken_status_t stir_shaken_jwt_authorize(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen, stir_shaken_cert_t *cert)
{
    return stir_shaken_jwt_authorize_keep_passport(ss, sih, params, NULL, 0, key, keylen, cert);
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
