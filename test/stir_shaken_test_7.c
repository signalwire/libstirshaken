#include <stir_shaken.h>


stir_shaken_status_t stir_shaken_unit_test_authorize_keep_passport(void)
{
    stir_shaken_passport_t *passport = NULL;                          // will be allocated
    char *p = NULL;
    const char *x5u = "https://not.here.org/passport.cer";
    const char *attest = "B";
    const char *desttn_key = "uri";
    const char *desttn_val = "sip:Obama@democrats.com";
    int iat = 9876543;
    const char *origtn_key = "";
    const char *origtn_val = "07483866525";
    const char *origid = "Trump's Office";
    char *sih = NULL;
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid };
    cJSON *jwt = NULL, *jHeader = NULL, *jPayload = NULL, *jParams = NULL, *j = NULL, *sig = NULL;
    
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;


	pthread_mutex_lock(&stir_shaken_globals.mutex);
	sprintf(private_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u7_private_key.pem");
	sprintf(public_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u7_public_key.pem");
	pthread_mutex_unlock(&stir_shaken_globals.mutex);

    printf("=== Unit testing: STIR/Shaken Authorization (keep passport) [stir_shaken_unit_test_authorize_keep_passport]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(&ec_key, &private_key, &public_key, private_key_name, public_key_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
    status = stir_shaken_authorize_keep_passport(&sih, &params, &passport, 1, private_key, NULL);
    stir_shaken_assert(passport != NULL, "PASSporT has not been created");
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    
    stir_shaken_assert(passport->json != NULL, "JSON @json has not been created");
    stir_shaken_assert(passport->info != NULL, "JSON @info has not been created");
    
    printf("JSON (json):\n%s\n", p = cJSON_Print(passport->json)); free(p); p = NULL;
    printf("JSON (json) minified:\n%s\n\n", p = cJSON_PrintUnformatted(passport->json)); free(p); p = NULL;
    printf("JSON (info):\n%s\n", p = cJSON_Print(passport->info)); free(p); p = NULL;

    jwt = cJSON_GetObjectItem(passport->json, "jwt");
    stir_shaken_assert(jwt != NULL, "PASSporT JSON is missing \"jwt\"");
    
    jHeader = cJSON_GetObjectItem(jwt, "header");
    jPayload = cJSON_GetObjectItem(jwt, "payload");
    jParams = cJSON_GetObjectItem(passport->json, "params");

    // test JWT header
    j = cJSON_GetObjectItem(jHeader, "alg");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, "ES256"), "ERROR: wrong param value");

    j = cJSON_GetObjectItem(jHeader, "ppt");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, "shaken"), "ERROR: wrong param value");

    j = cJSON_GetObjectItem(jHeader, "typ");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, "passport"), "ERROR: wrong param value");

    j = cJSON_GetObjectItem(jHeader, "x5u");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, x5u), "ERROR: wrong param value");

    // test JWT paylaod
    j = cJSON_GetObjectItem(jPayload, "attest");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, attest), "ERROR: wrong param value");
    
    j = cJSON_GetObjectItem(jPayload, "dest");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    j = cJSON_GetObjectItem(j, "uri");
    j = cJSON_GetArrayItem(j, 0);
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, "sip:Obama@democrats.com"), "ERROR: wrong param value");
    
    j = cJSON_GetObjectItem(jPayload, "iat");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(j->valueint == iat, "ERROR: wrong param value");
    
    j = cJSON_GetObjectItem(jPayload, "orig");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    j = cJSON_GetObjectItem(j, "tn");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, origtn_val), "ERROR: wrong param value");
    
    j = cJSON_GetObjectItem(jPayload, "origid");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, origid), "ERROR: wrong param value");

    // test Parameters
    j = cJSON_GetObjectItem(jParams, "alg");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, "ES256"), "ERROR: wrong param value");
    
    j = cJSON_GetObjectItem(jParams, "info");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, x5u), "ERROR: wrong param value");
    
    j = cJSON_GetObjectItem(jParams, "ppt");
    stir_shaken_assert(j != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(j->valuestring, "shaken"), "ERROR: wrong param value");

    sig = cJSON_GetObjectItem(jwt, "signature");
    stir_shaken_assert(sig != NULL, "PASSporT @jwt is missing \"signature\"");
    printf("Signature:\n%s\n", sig->valuestring);
    sig = cJSON_GetObjectItem(passport->info, "signature");
    stir_shaken_assert(sig != NULL, "Failed to create Signature");
    printf("OK\n\n");
	
	free(sih);
	sih = NULL;
    
	/* Need to free JSON object allocated by cJSON lib. */
	stir_shaken_passport_destroy(passport);
	free(passport);
	passport = NULL;
	
	pthread_mutex_lock(&stir_shaken_globals.mutex);
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
	pthread_mutex_unlock(&stir_shaken_globals.mutex);
    
    return STIR_SHAKEN_STATUS_OK;
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

	if (stir_shaken_unit_test_authorize_keep_passport() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}

	printf("OK\n");

	return 0;
}
