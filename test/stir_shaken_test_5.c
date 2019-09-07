#include <stir_shaken.h>


stir_shaken_status_t stir_shaken_unit_test_sip_identity_header_keep_passport(void)
{
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
    stir_shaken_passport_t *passport = NULL;                          // will be allocated
    char *p = NULL;
    const char *x5u = "https://cert.example.org/passport.cer";      // ref
    const char *attest = NULL;                                      // ignore, ref test case doesn't include this field
    const char *desttn_key = "uri";                                 // ref
    const char *desttn_val = "sip:alice@example.com";               // ref
    int iat = 1471375418;                                           // ref
    const char *origtn_key = "tn";                                  // ref test for orig telephone number
    const char *origtn_val = "12155551212";                         // ref
    const char *origid = NULL;                                      // ignore, ref test case doesn't include this field
    uint8_t ppt_ignore = 1;                                         // ignore, ref test case doesn't include this field
    char *sih = NULL;

    char sip_identity_header_ref[1500] = {0};
    const char *sip_identity_header_ref_front = "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9.eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI6MTQ3MTM3NTQxOCwib3JpZyI6eyJ0biI6IjEyMTU1NTUxMjEyIn19.";
    const char *sip_identity_header_ref_end = ";info=<https://cert.example.org/passport.cer>;alg=ES256;ppt=shaken";
    cJSON *sig = NULL, *jwt = NULL;
    
    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid, .ppt_ignore = ppt_ignore};
    
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;


	pthread_mutex_lock(&stir_shaken_globals.mutex);
	sprintf(private_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u5_private_key.pem");
	sprintf(public_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u5_public_key.pem");
	pthread_mutex_unlock(&stir_shaken_globals.mutex);

    printf("=== Unit testing: STIR/Shaken SIP Identity Header (keep passport) creation [stir_shaken_unit_test_sip_identity_header_keep_passport]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(&ec_key, &private_key, &public_key, private_key_name, public_key_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
    sih =  stir_shaken_do_sign_keep_passport(&params, private_key, &passport, 1);
    stir_shaken_assert(passport != NULL, "PASSporT has not been created");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    printf("SIP Identity Header:\n%s\n", sih);
    
    stir_shaken_assert(passport->json != NULL, "JSON @json has not been created");
    stir_shaken_assert(passport->info != NULL, "JSON @info has not been created");
    
    printf("JSON (json):\n%s\n", p = cJSON_Print(passport->json)); free(p); p = NULL;
    printf("JSON (json) minified:\n%s\n\n", p = cJSON_PrintUnformatted(passport->json)); free(p); p = NULL;
    printf("JSON (info):\n%s\n", p = cJSON_Print(passport->info)); free(p); p = NULL;
    
    jwt = cJSON_GetObjectItem(passport->json, "jwt");
    stir_shaken_assert(jwt != NULL, "PASSporT JSON is missing \"jwt\"");
    sig = cJSON_GetObjectItem(passport->info, "signature");
    stir_shaken_assert(sig != NULL, "Failed to create Signature");
    sprintf(sip_identity_header_ref, "%s%s%s", sip_identity_header_ref_front, sig->valuestring, sip_identity_header_ref_end);
    printf("Reference SIP Identity Header:\n%s\n", sip_identity_header_ref);
    stir_shaken_assert(!strcmp(sih, sip_identity_header_ref), "Wrong SIP Identity Header");
    printf("OK\n\n");
    
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

	if (stir_shaken_unit_test_sip_identity_header_keep_passport() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}

	printf("OK\n");

	return 0;
}
