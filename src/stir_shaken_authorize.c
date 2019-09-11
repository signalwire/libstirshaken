#include "stir_shaken.h"


cJSON* stir_shaken_passport_create_json(stir_shaken_passport_params_t *pparams)
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

    if (!pparams) {
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
    if (!json) goto err;
    
    // 1.1 JSON web token
    jwt = cJSON_CreateObject();
    if (!jwt) goto err;
    cJSON_AddItemToObject(json, "jwt", jwt);

    // 1.1.1 JSON JOSE Header (alg, ppt, typ, x5u)
    hdr = cJSON_CreateObject();
    if (!hdr) goto err;
    cJSON_AddItemToObject(jwt, "header", hdr);

    e = cJSON_CreateString("ES256");
    if (!e) goto err;
    cJSON_AddItemToObject(hdr, "alg", e);
   
    if (!ppt_ignore) { 
        e = cJSON_CreateString("shaken");
        if (!e) goto err;
        cJSON_AddItemToObject(hdr, "ppt", e);
    }
    
    e = cJSON_CreateString("passport");
    if (!e) goto err;
    cJSON_AddItemToObject(hdr, "typ", e);
    
    e = cJSON_CreateString(x5u);
    if (!e) goto err;
    cJSON_AddItemToObject(hdr, "x5u", e);

    // 1.1.2 JWS Payload
    payload = cJSON_CreateObject();
    if (!payload) goto err;
    cJSON_AddItemToObject(jwt, "payload", payload);
    
    if (attest && (*attest == 'A' || *attest == 'B' || *attest == 'C')) {
        cJSON_AddStringToObject(payload, "attest", attest);
    }
    
    dest = cJSON_CreateObject();
    if (!dest) goto err;
    cJSON_AddItemToObject(payload, "dest", dest);

    if (!strcmp(desttn_key, "uri")) {
        tn = cJSON_CreateArray();
        if (!tn) goto err;
        cJSON_AddItemToObject(dest, desttn_key, tn);

        e = cJSON_CreateString(desttn_val);
        if (!e) goto err;
        cJSON_AddItemToArray(tn, e);
    } else {
        cJSON_AddStringToObject(dest, "tn", desttn_val);
    }
    
    cJSON_AddNumberToObject(payload, "iat", iat);
    
    orig = cJSON_CreateObject();
    if (!orig) goto err;
    cJSON_AddItemToObject(payload, "orig", orig);
    
    if (!strcmp(origtn_key, "uri")) {
        tn = cJSON_CreateArray();
        if (!tn) goto err;
        cJSON_AddItemToObject(orig, origtn_key, tn);

        e = cJSON_CreateString(origtn_val);
        if (!e) goto err;
        cJSON_AddItemToArray(tn, e);
    } else {
        cJSON_AddStringToObject(orig, "tn", origtn_val);
    }

    if (origid) {
        cJSON_AddStringToObject(payload, "origid", origid);
    }

    // Generate signature
    p = cJSON_PrintUnformatted(hdr);
    if (!p) goto err;
    if (stir_shaken_b64_encode((unsigned char *) p, strlen(p), &buf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) goto err;
    free(p); p = NULL;

    p = cJSON_PrintUnformatted(payload);
    if (!p) goto err;
    if (stir_shaken_b64_encode((unsigned char *) p, strlen(p), &buf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) goto err;
    free(p); p = NULL;
   
    // 1.2 Parameters
    params = cJSON_CreateObject();
    if (!params) goto err;
    cJSON_AddItemToObject(json, "params", params);
    
    // 1.2.1 Alg
    e = cJSON_CreateString("ES256");
    if (!e) goto err;
    cJSON_AddItemToObject(params, "alg", e);
    
    // 1.2.2 Info
    e = cJSON_CreateString(x5u); // TODO info must be same as @x5u but within "<>", i.e. "<@x5u>" (Enclose @x5u within "<>")
    if (!e) goto err;
    cJSON_AddItemToObject(params, "info", e);
    
    // 1.2.3 PPT
    e = cJSON_CreateString("shaken");
    if (!e) goto err;
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

    return NULL;
}

stir_shaken_status_t stir_shaken_passport_finalise_json(stir_shaken_passport_t *passport, EVP_PKEY *pkey)
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

    if (!passport) return STIR_SHAKEN_STATUS_FALSE;
    
    jwt = cJSON_GetObjectItem(passport->json, "jwt");
    if (!jwt) goto err;

    payload = cJSON_GetObjectItem(jwt, "payload");
    if (!jwt) goto err;
    
    header = cJSON_GetObjectItem(jwt, "header");
    if (!jwt) goto err;
   
    if (passport->info) {
        cJSON_Delete(passport->info);
    }

    // Help info 
    info = cJSON_CreateObject();
    if (!info) goto err;
    
    // Generate signature

    // Paylaod signature
    p = cJSON_PrintUnformatted(payload);
    if (!p) goto err;
    cJSON_AddStringToObject(info, "payload_serialised", p);
    plen = strlen(p);
    if (stir_shaken_b64_encode((unsigned char *) p, plen, &pbuf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) goto err;
    plen = strlen((const char*) &pbuf[0]);
    free(p); p = NULL;
    cJSON_AddStringToObject(info, "payload_base64", (const char *) &pbuf[0]);

    // Header signature
    p = cJSON_PrintUnformatted(header);
    if (!p) goto err;
    cJSON_AddStringToObject(info, "header_serialised", p);
    hlen = strlen(p);
    if (stir_shaken_b64_encode((unsigned char *) p, hlen, &hbuf[0], PBUF_LEN) != STIR_SHAKEN_STATUS_OK) goto err;
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
        if (STIR_SHAKEN_STATUS_OK != stir_shaken_do_sign_data_with_digest(digest_name, pkey, &sbuf[0], hlen + plen + 1, signature, &signature_len)) {
	
			// TODO set error string, allow for retrieval printf("STIR-Shaken: Signing failed\n");
            goto err;
        }

        memset(ebuf, 0, sizeof(ebuf));

        // Signature is BASE64URL(JWS Signature)
        if (stir_shaken_b64_encode((unsigned char *) &signature[0], signature_len, (unsigned char*) &ebuf[0], 2*PBUF_LEN + 2) != STIR_SHAKEN_STATUS_OK) {
			
			// TODO set error string, allow for retrieval printf("STIR-Shaken: Encoding base 64 failed\n");
            goto err;
        }

        cJSON_AddStringToObject(jwt, "signature", (const char *) &ebuf[0]);
        cJSON_AddStringToObject(info, "signature", (const char *) &ebuf[0]);
    }

    passport->info = info;   

    return STIR_SHAKEN_STATUS_OK;

err:
	
	// TODO set error string, allow for retrieval printf("STIR-Shaken: Failed to sign json\n");

    if (info) {
        cJSON_Delete(info);
        info = NULL;
    }
    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_passport_create(stir_shaken_passport_t *passport, stir_shaken_passport_params_t *params, EVP_PKEY *pkey)
{
    if (!passport || passport->json || !params || !pkey) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

    memset(passport, 0, sizeof(*passport));

    /* Init @jwt JSON with all ASCII info */
    passport->json = stir_shaken_passport_create_json(params);
    if (!passport->json) goto err;

    /* Finalise PASSporT: create @jwt JSON signatures and save intermediate results in @info */ 
    if (stir_shaken_passport_finalise_json(passport, pkey) != STIR_SHAKEN_STATUS_OK) {
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
    return STIR_SHAKEN_STATUS_FALSE;
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
char* stir_shaken_sip_identity_create(stir_shaken_passport_t *passport)
{
    char *sih = NULL;
    cJSON *h_sig = NULL, *p_sig = NULL, *jwt = NULL, *sig = NULL, *params = NULL, *info = NULL, *alg = NULL, *ppt = NULL;
    size_t len = 0;

    if (!passport || !passport->info || !passport->json) return NULL;
    
    h_sig = cJSON_GetObjectItem(passport->info, "header_base64");
    p_sig = cJSON_GetObjectItem(passport->info, "payload_base64");
    jwt = cJSON_GetObjectItem(passport->json, "jwt");
    params = cJSON_GetObjectItem(passport->json, "params");

    if (!h_sig || !p_sig || !jwt || !params) return NULL;

    sig = cJSON_GetObjectItem(jwt, "signature");
    info = cJSON_GetObjectItem(params, "info");
    alg = cJSON_GetObjectItem(params, "alg");
    ppt = cJSON_GetObjectItem(params, "ppt");

    if (!sig || !info || !alg || !ppt) return NULL;

    // extra length of 15 for info=<> alg= ppt=
    len = strlen(h_sig->valuestring) + 1 + strlen(p_sig->valuestring) + 1 + strlen(sig->valuestring) + 1 + strlen(info->valuestring) + 1 + strlen(alg->valuestring) + 1 + strlen(ppt->valuestring) + 1 + 15;
    sih = malloc(len); // TODO free
	memset(sih, 0, len);
    if (!sih) return NULL;
    sprintf(sih, "%s.%s.%s;info=<%s>;alg=%s;ppt=%s", h_sig->valuestring, p_sig->valuestring, sig->valuestring, info->valuestring, alg->valuestring, ppt->valuestring);
    return sih;
}

// TODO May malloc memory for passport, free later
/*
 * Sign the call data with the @pkey, and keep pointer to created PASSporT (if @keep_passport is true). 
 * SIP Identity header is returned and PASSporT.
 * @passport - (out) will point to created PASSporT
 */
char* stir_shaken_do_sign_keep_passport(stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_passport_t **passport, uint8_t keep_passport)
{
    char					*sih = NULL;
    stir_shaken_passport_t	local_passport = {0};   // It will only allow you to cross this function's border

    if (!pkey || !params)
        return NULL;

    // Create PASSporT
    if (keep_passport) {

        *passport = malloc(sizeof(stir_shaken_passport_t));	// TODO free
        if (!*passport)
            goto err;
		memset(*passport, 0, sizeof(stir_shaken_passport_t));

        if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_create(*passport, params, pkey)) {
            goto err;
        }

        // Sign PASSpoprT and create SIP Identity header
        sih = stir_shaken_sip_identity_create(*passport);
        if (!sih) {
            goto err;
        }

    } else {

        if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_create(&local_passport, params, pkey)) {
            return NULL;
        }

        // Create SIP Identity header
        sih = stir_shaken_sip_identity_create(&local_passport);
		stir_shaken_passport_destroy(&local_passport);
        if (!sih) {
            return NULL;
        }
    }

    return sih;

err:
	if (*passport) {
		free(*passport);
		*passport = NULL;
	}

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
char* stir_shaken_do_sign(stir_shaken_passport_params_t *params, EVP_PKEY *pkey)
{
    if (!pkey || !params) return NULL;

    return stir_shaken_do_sign_keep_passport(params, pkey, NULL, 0);
}

/*
 * Authorize (assert/sign) call identity with cert of Service Provider.
 * If @keep_passport is true then keep pointer to PASSporT.
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 */
stir_shaken_status_t stir_shaken_authorize_keep_passport(char **sih, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport, uint8_t keep_passport, EVP_PKEY *pkey, stir_shaken_cert_t *cert)
{
    /* Let's start from this. */
    *sih = NULL;

    if (!params || !params->attest || (*params->attest != 'A' && *params->attest != 'B' && *params->attest != 'C')) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

    /* Assert/sign call identity with a private key associated with cert. */
    
    *sih = stir_shaken_do_sign_keep_passport(params, pkey, passport, keep_passport);
    if (!*sih) {
        goto err;
    }

    return STIR_SHAKEN_STATUS_OK;

err:
    /* TODO Logging with error details. */

    return STIR_SHAKEN_STATUS_FALSE;
}

/*
 * Authorize the call.
 */
stir_shaken_status_t stir_shaken_authorize(char **sih, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_cert_t *cert)
{
    return stir_shaken_authorize_keep_passport(sih, params, NULL, 0, pkey, cert);
}

stir_shaken_status_t stir_shaken_install_cert(stir_shaken_cert_t *cert)
{
	char cert_full_name[300] = {0};
	BIO *out = NULL;
	int i = 0;

    if (!cert) {

		// TODO remove	
		printf("STIR-Shaken: Cert not set\n");
        return STIR_SHAKEN_STATUS_FALSE;
    }
	
	if (!cert->install_path) {
        
		// TODO remove	
		printf("STIR-Shaken: Cert's @install_path not set. Where should I create the cert? How would others verify the call if I don't know where to place the certificate?\n");
        return STIR_SHAKEN_STATUS_FALSE;
    }

	snprintf(cert_full_name, 300, "%s%s", cert->install_path, cert->name);

	if (stir_shaken_file_exists(cert_full_name) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_file_remove(cert_full_name);
	}

	out = BIO_new(BIO_s_file());
	if (!out) goto fail;
	i = BIO_write_filename(out, (char*) cert_full_name);
	if (i == 0) {
		
		// TODO remove	
		printf("STIR-Shaken: Install: Failed to redirect bio to file %s\n", cert_full_name);
		goto fail;
	}

	i = PEM_write_bio_X509(out, cert->x);
	if (i == 0) {
	
		// TODO remove	
		printf("STIR-Shaken: Install: Failed to write certificate to file %s\n", cert_full_name);
		goto fail;
	}
	printf("STIR-Shaken: Install: Written certificate to file %s\n", cert_full_name);

	BIO_free_all(out);
	out = NULL;

	return STIR_SHAKEN_STATUS_OK;

fail:
	if (out) {
		BIO_free_all(out);
	}
	return STIR_SHAKEN_STATUS_FALSE;
}
