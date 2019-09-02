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
    if (!passport || passport->json || !params || !pkey) return STIR_SHAKEN_STATUS_FALSE;
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
