#include <stir_shaken.h>


stir_shaken_status_t stir_shaken_unit_test_verify_spoofed(void)
{
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
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
	
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
	char csr_name[300] = { 0 };
	char csr_text_name[300] = { 0 };
	char cert_name[300] = { 0 };
	char cert_text_name[300] = { 0 };

    uint32_t sp_code = 1800;

    stir_shaken_csr_t csr = {0};
    stir_shaken_cert_t cert = {0};
    
    stir_shaken_passport_t *passport = NULL;
    char *spoofed_sih = NULL;
    const char *spoofed_origtn_val = "07643866222";
    cJSON *jwt = NULL, *jPayload = NULL, *orig = NULL;


	pthread_mutex_lock(&stir_shaken_globals.mutex);
	sprintf(private_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u9_private_key.pem");
	sprintf(public_key_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u9_public_key.pem");
    sprintf(csr_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u9_csr.pem");
    sprintf(csr_text_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u9_csr_text.pem");
    sprintf(cert_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u9_cert.crt");
    sprintf(cert_text_name, "%s%c%s", stir_shaken_globals.settings.path, '/', "u9_cert_text.crt");
	pthread_mutex_unlock(&stir_shaken_globals.mutex);


    printf("=== Unit testing: STIR/Shaken Verification against good and spoofed SIP Identity Header [stir_shaken_unit_test_verify]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(NULL, &ec_key, &private_key, &public_key, private_key_name, public_key_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
    printf("Authorizing...\n\n");
    status = stir_shaken_authorize_keep_passport(NULL, &sih, &params, &passport, 1, private_key, NULL);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(passport != NULL, "Failed to create PASSporT");
    stir_shaken_assert(passport->json != NULL, "Failed to create PASSporT json");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    
    printf("SIP Identity Header:\n%s\n\n", sih);

    printf("Creating CSR\n");
    status = stir_shaken_generate_csr(sp_code, &csr.req, private_key, public_key, csr_name, csr_text_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");
    
    printf("Creating Certificate\n");
    status = stir_shaken_generate_cert_from_csr(sp_code, &cert, &csr, private_key, public_key, cert_name, cert_text_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating Cert");

    printf("Verifying SIP Identity Header's signature with Cert... (against good data)\n\n");
    status = stir_shaken_verify_with_cert(NULL, sih, &cert);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, verifying");

    // Spoofed SIP Identity Header
    jwt = cJSON_GetObjectItem(passport->json, "jwt");
    jPayload = cJSON_GetObjectItem(jwt, "payload");
    cJSON_DeleteItemFromObject(jPayload, "orig");
    
    orig = cJSON_CreateObject();
    cJSON_AddItemToObject(jPayload, "orig", orig);
    cJSON_AddStringToObject(orig, "tn", spoofed_origtn_val);
    // Need to update @info as stir_shaken_sip_identity_create takes header and payload base 64 from @info,
    // otherwise spoofed SIP Identity Header would be same as original header (even if @jwt changed).
    // Second arg is NULL, so only header and payload will change but signature won't be touched
    status = stir_shaken_passport_finalise_json(NULL, passport, NULL);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, updating json");

    // Using same signature, same data, apart from spoofed Telephone Number
    spoofed_sih = stir_shaken_sip_identity_create(NULL, passport);
    stir_shaken_assert(spoofed_sih != NULL, "Failed to create (spoofed) SIP Identity Header");
    printf("Spoofed SIP Identity Header:\n%s\n\n", spoofed_sih);
    
    printf("Verifying SIP Identity Header's signature with Cert... (against spoofed SIP Identity Header)\n\n");
    status = stir_shaken_verify_with_cert(NULL, spoofed_sih, &cert);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Err, verifying");

	stir_shaken_passport_destroy(passport);
	free(passport);
	passport = NULL;
	
	X509_REQ_free(csr.req);
	csr.req = NULL;
		
	X509_free(cert.x);
	cert.x = NULL;

	free(sih);
	sih = NULL;
	
	free(spoofed_sih);
	spoofed_sih = NULL;
	
	pthread_mutex_lock(&stir_shaken_globals.mutex);
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
	pthread_mutex_unlock(&stir_shaken_globals.mutex);
    
    return STIR_SHAKEN_STATUS_OK;
}

int main(void)
{
	const char *path = "./test/run";
	
	stir_shaken_do_init(NULL);

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {
	
			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	stir_shaken_settings_set_path(path);

	if (stir_shaken_unit_test_verify_spoofed() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
