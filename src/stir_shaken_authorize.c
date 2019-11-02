#include "stir_shaken.h"


cJSON* stir_shaken_passport_create_json(stir_shaken_context_t *ss, stir_shaken_passport_params_t *pparams)
{
    /**
     * Create main JSON object with members: @jwt and @params (Jason Web Token and Parameters)
     */

    char *p = NULL;
    unsigned char buf[PBUF_LEN];

    const char  *x5u = NULL;
    const char  *attest = NULL;
    const char  *desttn_key = NULL;
    const char  *desttn_val = NULL;
    int         iat = 0;
    const char  *origtn_key = NULL;
    const char  *origtn_val = NULL;
    const char  *origid = NULL;
    uint8_t     ppt_ignore = 0;

    cJSON *json = NULL, *jwt = NULL, *params = NULL, *hdr = NULL, *e = NULL, *payload = NULL, *dest = NULL, *tn = NULL, *orig = NULL;

	stir_shaken_clear_error(ss);

    if (!pparams) {
		stir_shaken_set_error(ss, "Passport create json: Bad params", STIR_SHAKEN_ERROR_GENERAL);
        return NULL;
    }

    x5u = pparams->x5u;
    attest = pparams->attest;
    desttn_key = pparams->desttn_key;
    desttn_val = pparams->desttn_val;
    iat = pparams->iat;
    origtn_key = pparams->origtn_key;
    origtn_val = pparams->origtn_val;
    origid = pparams->origid;
    ppt_ignore = pparams->ppt_ignore;

    // 1. Main JSON object
    json = cJSON_CreateObject();
    if (!json) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @json", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    
    // 1.1 JSON web token
    jwt = cJSON_CreateObject();
    if (!jwt) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @jwt", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(json, "jwt", jwt);

    // 1.1.1 JSON JOSE Header (alg, ppt, typ, x5u)
    hdr = cJSON_CreateObject();
    if (!hdr) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @hdr", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(jwt, "header", hdr);

    e = cJSON_CreateString("ES256");
    if (!e) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, header @ES256", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(hdr, "alg", e);
   
    if (!ppt_ignore) { 
        e = cJSON_CreateString("shaken");
        if (!e) {
			stir_shaken_set_error(ss, "Passport create json: Error in cjson, @ppt", STIR_SHAKEN_ERROR_CJSON);
			goto err;
		}
        cJSON_AddItemToObject(hdr, "ppt", e);
    }
    
    e = cJSON_CreateString("passport");
    if (!e) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @typ", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(hdr, "typ", e);
    
    e = cJSON_CreateString(x5u);
    if (!e) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @x5u", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(hdr, "x5u", e);

    // 1.1.2 JWS Payload
    payload = cJSON_CreateObject();
    if (!payload) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @payload", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(jwt, "payload", payload);
    
    if (attest && (*attest == 'A' || *attest == 'B' || *attest == 'C')) {
        cJSON_AddStringToObject(payload, "attest", attest);
    }
    
    dest = cJSON_CreateObject();
    if (!dest) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @dest", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(payload, "dest", dest);

    if (!strcmp(desttn_key, "uri")) {
        tn = cJSON_CreateArray();
        if (!tn) {
			stir_shaken_set_error(ss, "Passport create json: Error in cjson, @desttn [key]", STIR_SHAKEN_ERROR_CJSON);
			goto err;
		}
        cJSON_AddItemToObject(dest, desttn_key, tn);

        e = cJSON_CreateString(desttn_val);
        if (!e) {
			stir_shaken_set_error(ss, "Passport create json: Error in cjson, @desttn [val]", STIR_SHAKEN_ERROR_CJSON);
			goto err;
		}
        cJSON_AddItemToArray(tn, e);
    } else {
        cJSON_AddStringToObject(dest, "tn", desttn_val);
    }
    
    cJSON_AddNumberToObject(payload, "iat", iat);
    
    orig = cJSON_CreateObject();
    if (!orig) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @orig", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(payload, "orig", orig);
    
    if (!strcmp(origtn_key, "uri")) {
        tn = cJSON_CreateArray();
        if (!tn) {
			stir_shaken_set_error(ss, "Passport create json: Error in cjson, @origtn [key]", STIR_SHAKEN_ERROR_CJSON);
			goto err;
		}
        cJSON_AddItemToObject(orig, origtn_key, tn);

        e = cJSON_CreateString(origtn_val);
        if (!e) {
			stir_shaken_set_error(ss, "Passport create json: Error in cjson, @origtn [val]", STIR_SHAKEN_ERROR_CJSON);
			goto err;
		}
        cJSON_AddItemToArray(tn, e);
    } else {
        cJSON_AddStringToObject(orig, "tn", origtn_val);
    }

    if (origid) {
        cJSON_AddStringToObject(payload, "origid", origid);
    }

    // Generate signature
    p = cJSON_PrintUnformatted(hdr);
    if (!p) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, print @header", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    if (stir_shaken_b64_encode((unsigned char *) p, strlen(p), &buf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) goto err;
    free(p); p = NULL;

    p = cJSON_PrintUnformatted(payload);
    if (!p) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, print @payload", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    if (stir_shaken_b64_encode((unsigned char *) p, strlen(p), &buf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) goto err;
    free(p); p = NULL;
   
    // 1.2 Parameters
    params = cJSON_CreateObject();
    if (!params) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, @params", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(json, "params", params);
    
    // 1.2.1 Alg
    e = cJSON_CreateString("ES256");
    if (!e) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, params @alg", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(params, "alg", e);
    
    // 1.2.2 Info
    e = cJSON_CreateString(x5u); // TODO info must be same as @x5u but within "<>", i.e. "<@x5u>" (Enclose @x5u within "<>")
    if (!e) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, params @x5u", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(params, "info", e);
    
    // 1.2.3 PPT
    e = cJSON_CreateString("shaken");
    if (!e) {
		stir_shaken_set_error(ss, "Passport create json: Error in cjson, params @ppt", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddItemToObject(params, "ppt", e);

    // TODO: need to call cJSON_Delete on it later
    return json;

err:
    if (json) {
        cJSON_Delete(json);
    }
    if (p) {
        free(p);
    }
	stir_shaken_set_error_if_clear(ss, "Passport create json: Error", STIR_SHAKEN_ERROR_CJSON);

    return NULL;
}

stir_shaken_status_t stir_shaken_passport_finalise_json(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, EVP_PKEY *pkey)
{
    const char      *digest_name = "sha256";
    char *p = NULL;
    unsigned char hbuf[PBUF_LEN] = {0};
    unsigned char pbuf[PBUF_LEN] = {0};
    cJSON *jwt = NULL, *info = NULL, *payload = NULL, *header = NULL;
    
    int plen = 0, hlen = 0;
    char sbuf[2*PBUF_LEN + 2] = {0}; // + '.' and '\0'
    char ebuf[2*PBUF_LEN + 2] = {0};

    unsigned char   signature[PBUF_LEN] = {0};
    size_t   signature_len = PBUF_LEN;


	stir_shaken_clear_error(ss);

    if (!passport) {
		stir_shaken_set_error(ss, "Passport finalise json: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}
    
    jwt = cJSON_GetObjectItem(passport->json, "jwt");
    if (!jwt) {
		stir_shaken_set_error(ss, "Passport finalise json: Bad @jwt", STIR_SHAKEN_ERROR_GENERAL);
		goto err;
	}

    payload = cJSON_GetObjectItem(jwt, "payload");
    if (!payload) {
		stir_shaken_set_error(ss, "Passport finalise json: Bad @payload", STIR_SHAKEN_ERROR_GENERAL);
		goto err;
	}
    
    header = cJSON_GetObjectItem(jwt, "header");
    if (!header) {
		stir_shaken_set_error(ss, "Passport finalise json: Bad @header", STIR_SHAKEN_ERROR_GENERAL);
		goto err;
	}
   
    if (passport->info) {
        cJSON_Delete(passport->info);
    }

    // Help info 
    info = cJSON_CreateObject();
    if (!info) {
		stir_shaken_set_error(ss, "Passport finalise json: Bad @info", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    
    // Generate signature

    // Paylaod signature
    p = cJSON_PrintUnformatted(payload);
    if (!p) {
		stir_shaken_set_error(ss, "Passport finalise json: Error in cjson", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddStringToObject(info, "payload_serialised", p);
    plen = strlen(p);
    if (stir_shaken_b64_encode((unsigned char *) p, plen, &pbuf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "Passport finalise json: Error encoding payload b64", STIR_SHAKEN_ERROR_GENERAL);
		goto err;
	}
    plen = strlen((const char*) &pbuf[0]);
    free(p); p = NULL;
    cJSON_AddStringToObject(info, "payload_base64", (const char *) &pbuf[0]);

    // Header signature
    p = cJSON_PrintUnformatted(header);
    if (!p) {
		stir_shaken_set_error(ss, "Passport finalise json: Error in cjson", STIR_SHAKEN_ERROR_CJSON);
		goto err;
	}
    cJSON_AddStringToObject(info, "header_serialised", p);
    hlen = strlen(p);
    if (stir_shaken_b64_encode((unsigned char *) p, hlen, &hbuf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "Passport finalise json: Error encoding header b64", STIR_SHAKEN_ERROR_GENERAL);
		goto err;
	}
    hlen = strlen((const char*) &hbuf[0]);
    free(p); p = NULL;
    cJSON_AddStringToObject(info, "header_base64", (const char *) &hbuf[0]);
    
    if (pkey) {
        
        // Main Signature
        // BASE64URL(UTF8(JWS Protected Header)) + "." + BASE64URL(JWS Payload)
        // This is input for computation of digital JWS Signature:
        // JWS Signature = ES256(ASCII(BASE64URL(UTF8(JWS Protected Header)) || "." || BASE64URL(JWS Payload)))

        memcpy(&sbuf[0], &hbuf[0], hlen);
        sbuf[hlen] = '.';
        memcpy(&sbuf[hlen + 1], &pbuf[0], plen);
        sbuf[hlen + plen + 1] = '\0';
        cJSON_AddStringToObject(info, "main_signature", (const char *) &sbuf[0]);

        // Terminates output with '\0' but returned length excludes this
        if (STIR_SHAKEN_STATUS_OK != stir_shaken_do_sign_data_with_digest(ss, digest_name, pkey, &sbuf[0], hlen + plen + 1, signature, &signature_len)) {
			
			stir_shaken_set_error_if_clear(ss, "Passport finalise json: Signing failed", STIR_SHAKEN_ERROR_GENERAL);
            goto err;
        }

        memset(ebuf, 0, sizeof(ebuf));

        // Signature is BASE64URL(JWS Signature)
        if (stir_shaken_b64_encode((unsigned char *) &signature[0], signature_len, (unsigned char*) &ebuf[0], 2*PBUF_LEN + 2) != STIR_SHAKEN_STATUS_OK) {
			
			stir_shaken_set_error(ss, "Passport finalise json: Encoding signature in base 64 failed", STIR_SHAKEN_ERROR_GENERAL);
            goto err;
        }

        cJSON_AddStringToObject(jwt, "signature", (const char *) &ebuf[0]);
        cJSON_AddStringToObject(info, "signature", (const char *) &ebuf[0]);
    }

    passport->info = info;   

    return STIR_SHAKEN_STATUS_OK;

err:
	
	stir_shaken_set_error_if_clear(ss, "Passport finalise json: Failed to sign json", STIR_SHAKEN_ERROR_GENERAL);

    if (info) {
        cJSON_Delete(info);
        info = NULL;
    }
    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_passport_create(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, stir_shaken_passport_params_t *params, EVP_PKEY *pkey)
{
	stir_shaken_clear_error(ss);

    if (!passport || passport->json || !params || !pkey) {
		stir_shaken_set_error_if_clear(ss, "Passport create: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

    memset(passport, 0, sizeof(*passport));

    /* Init @jwt JSON with all ASCII info */
    passport->json = stir_shaken_passport_create_json(ss, params);
    if (!passport->json) {
		stir_shaken_set_error_if_clear(ss, "Passport create: Create json failed", STIR_SHAKEN_ERROR_GENERAL);
		goto err;
	}

    /* Finalise PASSporT: create @jwt JSON signatures and save intermediate results in @info */ 
    if (stir_shaken_passport_finalise_json(ss, passport, pkey) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error_if_clear(ss, "Passport create: Finalise json failed", STIR_SHAKEN_ERROR_GENERAL);
        goto err;
    }

    return STIR_SHAKEN_STATUS_OK;

err:
    if (passport->json) {
        cJSON_Delete(passport->json);
        passport->json = NULL;
    }
    if (passport->info) {
        cJSON_Delete(passport->info);
        passport->info = NULL;
    }
	stir_shaken_set_error_if_clear(ss, "Passport create: Error", STIR_SHAKEN_ERROR_GENERAL);

    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_jwt_passport_jwt_init(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_passport_params_t *params)
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

		// TODO set key
		unsigned char key256[32] = "012345678901234567890123456789XY";

		// Header

		/**if (jwt_add_header(jwt, "alg", "es256") != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}**/

		printf("SS JWT:\n%s\n", jwt_dump_str(jwt, 1));
		
		/**if(jwt_set_alg(jwt, JWT_ALG_ES256, key256, sizeof(key256)) != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}
		printf("SS JWT ALG:\n%s\n", jwt_dump_str(jwt, 1));**/

		if (jwt_add_header(jwt, "ppt", "shaken") != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}
		printf("SS JWT PPT:\n%s\n", jwt_dump_str(jwt, 1));

		jwt_del_headers(jwt, NULL);
		printf("SS JWT DEL all:\n%s\n", jwt_dump_str(jwt, 1));
		jwt_del_headers(jwt, "typ");
		printf("SS JWT DEL typ:\n%s\n", jwt_dump_str(jwt, 1));

		if (jwt_add_header(jwt, "typ", "passport") != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}
		printf("SS JWT typ:\n%s\n", jwt_dump_str(jwt, 1));
		if (jwt_add_header(jwt, "x5u", x5u) != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}
		printf("SS JWT x5u:\n%s\n", jwt_dump_str(jwt, 1));
		
		if(jwt_set_alg(jwt, JWT_ALG_ES256, key256, sizeof(key256)) != 0) {
			return STIR_SHAKEN_STATUS_ERR;
		}
		printf("SS JWT ALG:\n%s\n", jwt_dump_str(jwt, 1));

		// Payload

		if (jwt_add_header_int(jwt, "iat", (long)time(NULL)) != 0) {
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

jwt_t* stir_shaken_jwt_passport_jwt_create_new(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params)
{
	jwt_t *jwt = NULL;

	if (jwt_new(&jwt) != 0) {

		stir_shaken_set_error_if_clear(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	if (params) {

		if (stir_shaken_jwt_passport_jwt_init(ss, jwt, params) != STIR_SHAKEN_STATUS_OK) {
			jwt_free(jwt);
			stir_shaken_set_error_if_clear(ss, "Cannot init JWT", STIR_SHAKEN_ERROR_GENERAL);
			return NULL;
		}
	}

	return jwt;
}

stir_shaken_status_t stir_shaken_jwt_passport_init(stir_shaken_context_t *ss, stir_shaken_jwt_passport_t *where, stir_shaken_passport_params_t *params)
{
	if (!where) return STIR_SHAKEN_STATUS_TERM;

	if (!where->jwt) {
		
		if ((where->jwt = stir_shaken_jwt_passport_jwt_create_new(ss, params)) == NULL) {
			return STIR_SHAKEN_STATUS_RESTART;
		}

	} else {

		if (stir_shaken_jwt_passport_jwt_init(ss, where->jwt, params) != STIR_SHAKEN_STATUS_OK) {
			stir_shaken_set_error_if_clear(ss, "Cannot init JWT", STIR_SHAKEN_ERROR_GENERAL);
			return STIR_SHAKEN_STATUS_FALSE;
		}
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_jwt_passport_t*	stir_shaken_jwt_passport_create_new(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params)
{
	stir_shaken_jwt_passport_t	*passport = NULL;

	passport = malloc(sizeof(*passport));
	if (!passport) {
		stir_shaken_set_error_if_clear(ss, "Out of memory", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

	if (params) {

		// Create JWT from params
		passport->jwt = stir_shaken_jwt_passport_jwt_create_new(ss, params);
		if (!passport->jwt) {
			free(passport);
			stir_shaken_set_error_if_clear(ss, "Cannot create JWT", STIR_SHAKEN_ERROR_GENERAL);
			return NULL;
		}
	}

	return passport;
}

stir_shaken_status_t stir_shaken_jwt_passport_sign(stir_shaken_context_t *ss, stir_shaken_jwt_passport_t *passport, EVP_PKEY *pkey)
{
	if (!passport || !pkey) return STIR_SHAKEN_STATUS_TERM;
	return STIR_SHAKEN_STATUS_OK;
}

void stir_shaken_jwt_passport_destroy(stir_shaken_jwt_passport_t *passport)
{
	if (!passport) return;
	jwt_free(passport->jwt);
}

void stir_shaken_passport_destroy(stir_shaken_passport_t *passport)
{
    if (!passport) {
		return;
	}

    if (passport->json) {
        cJSON_Delete(passport->json);
        passport->json = NULL;
    }

    if (passport->info) {
        cJSON_Delete(passport->info);
        passport->info = NULL;
    }
}

// TODO Mallocs memory for identity header, free later
char* stir_shaken_sip_identity_create(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
    char *sih = NULL;
    cJSON *h_sig = NULL, *p_sig = NULL, *jwt = NULL, *sig = NULL, *params = NULL, *info = NULL, *alg = NULL, *ppt = NULL;
    size_t len = 0;

	stir_shaken_clear_error(ss);

    if (!passport || !passport->info || !passport->json) {
		stir_shaken_set_error(ss, "SIP Identity create: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}
    
    h_sig = cJSON_GetObjectItem(passport->info, "header_base64");
    p_sig = cJSON_GetObjectItem(passport->info, "payload_base64");
    jwt = cJSON_GetObjectItem(passport->json, "jwt");
    params = cJSON_GetObjectItem(passport->json, "params");

    if (!h_sig || !p_sig || !jwt || !params) {

		stir_shaken_set_error(ss, "SIP Identity create: Error in cjson [1]", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

    sig = cJSON_GetObjectItem(jwt, "signature");
    info = cJSON_GetObjectItem(params, "info");
    alg = cJSON_GetObjectItem(params, "alg");
    ppt = cJSON_GetObjectItem(params, "ppt");

    if (!sig || !info || !alg || !ppt) {

		stir_shaken_set_error(ss, "SIP Identity create: Error in cjson [2]", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

    // extra length of 15 for info=<> alg= ppt=
    len = strlen(h_sig->valuestring) + 1 + strlen(p_sig->valuestring) + 1 + strlen(sig->valuestring) + 1 + strlen(info->valuestring) + 1 + strlen(alg->valuestring) + 1 + strlen(ppt->valuestring) + 1 + 15;
    sih = malloc(len); // TODO free
    if (!sih) {
		stir_shaken_set_error(ss, "SIP Identity create: Out of memory", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}
	memset(sih, 0, len);
    sprintf(sih, "%s.%s.%s;info=<%s>;alg=%s;ppt=%s", h_sig->valuestring, p_sig->valuestring, sig->valuestring, info->valuestring, alg->valuestring, ppt->valuestring);
    return sih;
}

// TODO May malloc memory for passport, free later
/*
 * Sign the call data with the @pkey, and keep pointer to created PASSporT (if @keep_passport is true). 
 * SIP Identity header is returned and PASSporT.
 * @passport - (out) will point to created PASSporT
 */
char* stir_shaken_do_sign_keep_passport(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_passport_t **passport, uint8_t keep_passport)
{
    char					*sih = NULL;
    stir_shaken_passport_t	local_passport = {0};   // It will only allow you to cross this function's border
	
	
	stir_shaken_clear_error(ss);

    if (!pkey || !params) {
		stir_shaken_set_error(ss, "Do sign keep passport: Bad params", STIR_SHAKEN_ERROR_GENERAL);
        return NULL;
	}

    // Create PASSporT
    if (keep_passport) {

        *passport = malloc(sizeof(stir_shaken_passport_t));	// TODO free
        if (!*passport) {
			stir_shaken_set_error(ss, "Do sign keep passport: Out of memory", STIR_SHAKEN_ERROR_GENERAL);
            goto err;
		}
		memset(*passport, 0, sizeof(stir_shaken_passport_t));

        if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_create(ss, *passport, params, pkey)) {
			stir_shaken_set_error_if_clear(ss, "Do sign keep passport: Passport create failed [1]", STIR_SHAKEN_ERROR_GENERAL);
            goto err;
        }

        // Sign PASSpoprT and create SIP Identity header
        sih = stir_shaken_sip_identity_create(ss, *passport);
        if (!sih) {
			stir_shaken_set_error_if_clear(ss, "Do sign keep passport: SIP Identity create failed [1]", STIR_SHAKEN_ERROR_GENERAL);
            goto err;
        }

    } else {

        if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_create(ss, &local_passport, params, pkey)) {
			stir_shaken_set_error_if_clear(ss, "Do sign keep passport: Passport create failed [2]", STIR_SHAKEN_ERROR_GENERAL);
            return NULL;
        }

        // Create SIP Identity header
        sih = stir_shaken_sip_identity_create(ss, &local_passport);
		stir_shaken_passport_destroy(&local_passport);
        if (!sih) {
			stir_shaken_set_error_if_clear(ss, "Do sign keep passport: SIP Identity create failed [2]", STIR_SHAKEN_ERROR_GENERAL);
            return NULL;
        }
    }

    return sih;

err:
	if (*passport) {
		free(*passport);
		*passport = NULL;
	}
	stir_shaken_set_error_if_clear(ss, "Do sign keep passport: Error", STIR_SHAKEN_ERROR_GENERAL);

    return NULL;
}

/*
 * Sign the call data with the @pkey. 
 * Local PASSporT object is created and destroyed. Only SIP Identity header is returned.
 * If you want to keep the PASSporT, then use stir_shaken_shaken_do_sign_keep_passport instead.
 *
 * External parameters that must be given to this method to be able to sign the SDP:
 * X means "needed"
 *
 *      // JSON web token (JWT)
 *          // JSON JOSE Header (alg, ppt, typ, x5u)
 *              // alg      This value indicates the encryption algorithm. Must be 'ES256'.
 *              // ppt      This value indicates the extension used. Must be 'shaken'.
 *              // typ      This value indicates the token type. Must be 'passport'.
 * X            // x5u      This value indicates the location of the certificate used to sign the token.
 *          // JWS Payload
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
char* stir_shaken_do_sign(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, EVP_PKEY *pkey)
{
	stir_shaken_clear_error(ss);

    if (!pkey || !params) {
		
		stir_shaken_set_error(ss, "Do sign: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return NULL;
	}

    return stir_shaken_do_sign_keep_passport(ss, params, pkey, NULL, 0);
}

/*
 * Authorize (assert/sign) call identity with cert of Service Provider.
 * If @keep_passport is true then keep pointer to PASSporT.
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 */
stir_shaken_status_t stir_shaken_authorize_keep_passport(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport, uint8_t keep_passport, EVP_PKEY *pkey, stir_shaken_cert_t *cert)
{
    /* Let's start from this. */
    *sih = NULL;
	
	stir_shaken_clear_error(ss);

    if (!params || !params->attest || (*params->attest != 'A' && *params->attest != 'B' && *params->attest != 'C')) {
		
		stir_shaken_set_error(ss, "Authorize keep passport: Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

    /* Assert/sign call identity with a private key associated with cert. */
    
    *sih = stir_shaken_do_sign_keep_passport(ss, params, pkey, passport, keep_passport);
    if (!*sih) {
		
		stir_shaken_set_error_if_clear(ss, "Authorize keep passport: Do sign keep passport failed", STIR_SHAKEN_ERROR_GENERAL);
        goto err;
    }

    return STIR_SHAKEN_STATUS_OK;

err:
    
	stir_shaken_set_error_if_clear(ss, "Authorize keep passport: Error", STIR_SHAKEN_ERROR_GENERAL);

    return STIR_SHAKEN_STATUS_FALSE;
}

/*
 * Authorize the call.
 */
stir_shaken_status_t stir_shaken_authorize(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_cert_t *cert)
{
    return stir_shaken_authorize_keep_passport(ss, sih, params, NULL, 0, pkey, cert);
}

// TODO destroy cert, free memory
stir_shaken_status_t stir_shaken_cert_configure(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, const char *name, const char *install_dir, const char *install_url)
{
    char a[500] = {0};
    char b[500] = {0};
    int c = 0;
    int d = 0;
    int n = 0;
    int e = 0;


    stir_shaken_clear_error(ss);

    if (!cert) {
        stir_shaken_set_error(ss, "Cert configure: Cert not set", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_FALSE;
    }


    // Cert's installation dir

    if (install_dir) {

        c = strlen(install_dir);
        cert->install_dir = malloc(c + 5);
        if (!cert->install_dir) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->install_dir, 0, c + 5);
        e = snprintf(b, 500, "%s/", install_dir);
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->install_dir, b, e);
        stir_shaken_remove_multiple_adjacent(cert->install_dir, '/');
    }

    // Cert's installation URL

    if (install_url) {
    
        d = strlen(install_url);
        cert->install_url = malloc(d + 15);
        if (!cert->install_url) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->install_url, 0, d + 15);
        e = snprintf(b, 500, "%s/", install_url);
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->install_url, b, e);
        if (strstr(cert->install_url, "http://") == cert->install_url) {
            stir_shaken_remove_multiple_adjacent(cert->install_url + 7, '/');
        } else {
            stir_shaken_remove_multiple_adjacent(cert->install_url, '/');
        }
    }

    // Cert's full name

    if (name) {
        
        n = strlen(name);

        cert->original_name = strdup(name);
        
        memcpy(a, name, n + 1);
        cert->basename = strdup(basename(a));

        cert->full_name = malloc(c + n + 5);
        if (!cert->full_name) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->full_name, 0, c + n + 5);
        if (install_dir) {
            memcpy(a, name, n + 1);
            e = snprintf(b, 500, "%s/%s", install_dir, basename(a));
        } else {
            e = snprintf(b, 500, "%s", basename(a));
        }
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->full_name, b, e);
        stir_shaken_remove_multiple_adjacent(cert->full_name, '/');

        // Cert's publicly accessible URL
        cert->public_url = malloc(d + n + 5);
        if (!cert->public_url) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->public_url, 0, d + n + 5);
        if (install_url) {
            e = snprintf(b, 500, "%s/%s", install_url, cert->name);
        } else {
            e = snprintf(b, 500, "%s", cert->name);
        }
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->public_url, b, e);
        if (strstr(cert->public_url, "http://") == cert->public_url) {
            stir_shaken_remove_multiple_adjacent(cert->public_url + 7, '/');
        } else {
            stir_shaken_remove_multiple_adjacent(cert->public_url, '/');
        }
    }

    return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_install_cert(stir_shaken_context_t *ss, stir_shaken_cert_t *cert)
{
	BIO *out = NULL;
	int i = 0;
	char			err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

	stir_shaken_clear_error(ss);

    if (!cert) {

		stir_shaken_set_error(ss, "Install cert: Cert not set", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_FALSE;
    }
	
	if (!cert->full_name) {
        
		stir_shaken_set_error(ss, "Install cert: Cert's @full_name not set. Where should I create the cert? How would others verify the call if I don't know where to place the certificate? Please configure certificate.", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_FALSE;
    }

	if (stir_shaken_file_exists(cert->full_name) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_file_remove(cert->full_name);
	}

	out = BIO_new(BIO_s_file());
	if (!out) goto fail;
	i = BIO_write_filename(out, (char*) cert->full_name);
	if (i == 0) {
		
		sprintf(err_buf, "Install cert: Failed to redirect bio to file %s", cert->full_name);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL);
		goto fail;
	}

	i = PEM_write_bio_X509(out, cert->x);
	if (i == 0) {
	
		sprintf(err_buf, "Install cert: Failed to write certificate to file %s", cert->full_name);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL);
		goto fail;
	}

	// TODO remove
	printf("STIR-Shaken: Install cert: Written certificate to file %s\n", cert->full_name);

	BIO_free_all(out);
	out = NULL;

	return STIR_SHAKEN_STATUS_OK;

fail:
	if (out) {
		BIO_free_all(out);
	}
	
	stir_shaken_set_error_if_clear(ss, "Install cert: Error", STIR_SHAKEN_ERROR_GENERAL);

	return STIR_SHAKEN_STATUS_FALSE;
}
