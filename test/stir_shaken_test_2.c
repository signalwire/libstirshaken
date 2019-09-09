#include <stir_shaken.h>

/**
 * STIR/Shaken PASSporT creation Unit test
 * According to RFC 8225:
 * "Appendix A.  Example ES256-Based PASSporT JWS Serialization and Signature"
 */
#define BUF_LEN 1000
stir_shaken_status_t stir_shaken_unit_test_passport_create(void)
{
    stir_shaken_passport_t	passport = {0};
    stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;
    const char *x5u = "https://cert.example.org/passport.cer";      // ref
    const char *attest = NULL;                                      // ignore, ref test case doesn't include this field
    const char *desttn_key = "uri";                                 // ref
    const char *desttn_val = "sip:alice@example.com";               // ref
    int iat = 1471375418;                                           // ref
    const char *origtn_key = "tn";                                  // ref test for orig telephone number
    const char *origtn_val = "12155551212";                         // ref
    const char *origid = NULL;                                      // ignore, ref test case doesn't include this field
    uint8_t ppt_ignore = 1;                                         // ignore, ref test case doesn't include this field

    /* Reference test values */
    const char *payload_serialised_ref = "{\"dest\":{\"uri\":[\"sip:alice@example.com\"]},\"iat\":1471375418,\"orig\":{\"tn\":\"12155551212\"}}";
    const char *payload_base64_ref = "eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI6MTQ3MTM3NTQxOCwib3JpZyI6eyJ0biI6IjEyMTU1NTUxMjEyIn19";
    const char *header_serialised_ref = "{\"alg\":\"ES256\",\"typ\":\"passport\",\"x5u\":\"https://cert.example.org/passport.cer\"}";
    const char *header_base64_ref = "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9";
    const char *signature_ref = "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9.eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI6MTQ3MTM3NTQxOCwib3JpZyI6eyJ0biI6IjEyMTU1NTUxMjEyIn19";
    //const char *signature_base64_ref = "ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluQmhjM053YjNKMElpd2llRFYxSWpvaWFIUjBjSE02THk5alpYSjBMbVY0WVcxd2JHVXViM0puTDNCaGMzTndiM0owTG1ObGNpSjkuZXlKa1pYTjBJanA3SW5WeWFTSTZXeUp6YVhBNllXeHBZMlZBWlhoaGJYQnNaUzVqYjIwaVhYMHNJbWxoZENJNk1UUTNNVE0zTlRReE9Dd2liM0pwWnlJNmV5SjBiaUk2SWpFeU1UVTFOVFV4TWpFeUluMTk=";
    //const char *signature_encoded_ref = "VLBCIVDCaeK6M4hLJb6SHQvacAQVvoiiEOWQ_iUkqk79UD81fHQ0E1b3_GluIkba7UWYRM47ZbNFdOJquE35cw";

    cJSON *jwt = NULL;
    char *p = NULL;
    cJSON *h_ser = NULL, *h_sig = NULL, *p_ser = NULL, *p_sig = NULL, *sig = NULL;
    
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid, .ppt_ignore = ppt_ignore};

	pthread_mutex_lock(&stir_shaken_globals.mutex);
	sprintf(private_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u2_private_key.pem");
	sprintf(public_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u2_public_key.pem");
	pthread_mutex_unlock(&stir_shaken_globals.mutex);
    
    printf("=== Unit testing: STIR/Shaken PASSporT creation [stir_shaken_unit_test_passport_create]\n\n");
    
    // Generate new keys for this test
	pthread_mutex_lock(&stir_shaken_globals.mutex);
	status = stir_shaken_generate_keys(&ec_key, &private_key, &public_key, private_key_name, public_key_name);
	pthread_mutex_unlock(&stir_shaken_globals.mutex);

	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key");
	stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
    status = stir_shaken_passport_create(&passport, &params, private_key);

    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "PASSporT has not been created");
    stir_shaken_assert(passport.json != NULL, "JSON @json has not been created");
    stir_shaken_assert(passport.info != NULL, "JSON @info has not been created");

    printf("JSON (json):\n%s\n", p = cJSON_Print(passport.json)); free(p); p = NULL;
    printf("JSON (json) minified:\n%s\n\n", p = cJSON_PrintUnformatted(passport.json)); free(p); p = NULL;
    printf("JSON (info):\n%s\n", p = cJSON_Print(passport.info)); free(p); p = NULL;
    
    jwt = cJSON_GetObjectItem(passport.json, "jwt");
    stir_shaken_assert(jwt != NULL, "PASSporT JSON is missing \"jwt\"");

    // 1. Test serialisation
    printf("1. Test serialisation\n\n");

    // Payload serialisation
    p_ser = cJSON_GetObjectItem(passport.info, "payload_serialised");
    stir_shaken_assert(p_ser != NULL, "PASSporT @info is missing \"payload_serialised\"");
    printf("Payload serialised:\n%s\n", p_ser->valuestring);
    stir_shaken_assert(!strcmp(p_ser->valuestring, payload_serialised_ref), "Wrong PASSporT's serialised payload");
    printf("OK\n\n");


    // Header serialisation
    h_ser = cJSON_GetObjectItem(passport.info, "header_serialised");
    stir_shaken_assert(h_ser != NULL, "PASSporT @info is missing \"header_serialised\"");
    printf("Header serialised:\n%s\n", h_ser->valuestring);
    stir_shaken_assert(!strcmp(h_ser->valuestring, header_serialised_ref), "Wrong PASSporT's serialised header");
    printf("OK\n\n");

    
    // 2. Test signatures
    printf("2. Test signatures\n\n");

    // Payload signature
    
    p_sig = cJSON_GetObjectItem(passport.info, "payload_base64");
    stir_shaken_assert(p_sig != NULL, "PASSporT @info is missing \"payload_base64\"");
    printf("Payload base64:\n%s\n", p_sig->valuestring);
    stir_shaken_assert(!strcmp(p_sig->valuestring, payload_base64_ref), "Wrong PASSporT's payload base64");
    printf("OK\n\n");
    
    // Header signature
    
    h_sig = cJSON_GetObjectItem(passport.info, "header_base64");
    stir_shaken_assert(h_sig != NULL, "PASSporT @info is missing \"header_base64\"");
    printf("Header base64:\n%s\n", h_sig->valuestring);
    stir_shaken_assert(!strcmp(h_sig->valuestring, header_base64_ref), "Wrong PASSporT's header base64");
    printf("OK\n\n");

    // 3. Main Signature

    // Main Signature = BASE64URL(UTF8(JWS Protected Header)) + "." + BASE64URL(JWS Payload)
    // This is input for computation of digital JWS Signature
    sig = cJSON_GetObjectItem(passport.info, "main_signature");
    stir_shaken_assert(sig != NULL, "PASSporT @info is missing \"main_signature\"");
    printf("Main signature (joint, before signing):\n%s\n", sig->valuestring);
    stir_shaken_assert(!strcmp(sig->valuestring, signature_ref), "Wrong PASSporT's signature (joint, before signing)");
    printf("OK\n\n");
    
    // JWS Signature encoded in base 64
    // JWS Signature = ES256(Main Signature)
    // signature = base64(JWS Signature)
    sig = cJSON_GetObjectItem(jwt, "signature");
    stir_shaken_assert(sig != NULL, "PASSporT @jwt is missing \"signature\"");
    printf("Signature:\n%s\n", sig->valuestring);
    //switch_stir_shaken_assert(!strcmp(sig->valuestring, signature_ref), "Wrong PASSporT's signature", stream);
    printf("OK\n\n");

    /* Need to free JSON object allocated by cJSON lib. */
	stir_shaken_passport_destroy(&passport);
	
	pthread_mutex_lock(&stir_shaken_globals.mutex);
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
	pthread_mutex_unlock(&stir_shaken_globals.mutex);

	return status;
}

int main(void)
{
	const char *path = "./test/run";

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {
	
			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	stir_shaken_settings_set_path(path);

	if (stir_shaken_unit_test_passport_create() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}

	printf("OK\n");

	return 0;
}
