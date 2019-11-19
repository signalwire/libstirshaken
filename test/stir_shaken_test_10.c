#include <stir_shaken.h>

const char *path = "./test/run";

stir_shaken_status_t stir_shaken_unit_test_verify_response(void)
{
    const char *x5u = "https://not.here.org/passport.cer";
    const char *attest = "B";
    const char *desttn_key = "uri";
    const char *desttn_val = "sip:Obama@democrats.com";
    int iat = 9876543;
    const char *origtn_key = "";
    const char *origtn_val = "07483866525";
    const char *origid = "Trump's Office";
    char *sih = NULL, *sih_malformed = NULL, *p = NULL;
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss;
	stir_shaken_error_t	error_code = STIR_SHAKEN_ERROR_GENERAL;
	const char *error_description = NULL;

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
	int len = 0;
    const char *spoofed_origtn_val = "07643866222";
    cJSON *jwt = NULL, *jPayload = NULL, *orig = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	stir_shaken_jwt_passport_t jpass = { 0 };
	
	
	memset(&ss, 0, sizeof(ss));


	sprintf(private_key_name, "%s%c%s", path, '/', "u10_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u10_public_key.pem");
    sprintf(csr_name, "%s%c%s", path, '/', "u10_csr.pem");
    sprintf(csr_text_name, "%s%c%s", path, '/', "u10_csr_text.pem");
    sprintf(cert_name, "%s%c%s", path, '/', "u10_cert.crt");
    sprintf(cert_text_name, "%s%c%s", path, '/', "u10_cert_text.crt");

    printf("=== Unit testing: STIR/Shaken verify response error codes [stir_shaken_unit_test_verify_response]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should NULL");

    /* Test */
    printf("Authorizing...\n\n");
    status = stir_shaken_authorize_keep_passport(&ss, &sih, &params, &passport, 1, private_key, NULL);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(passport != NULL, "Failed to create PASSporT");
    stir_shaken_assert(passport->json != NULL, "Failed to create PASSporT json");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should NULL");
    
    printf("SIP Identity Header:\n%s\n\n", sih);
	
    printf("Creating CSR\n");
    status = stir_shaken_generate_csr(&ss, sp_code, &csr.req, private_key, public_key, csr_name, csr_text_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should NULL");
    
    printf("Creating Certificate\n");
    status = stir_shaken_generate_cert_from_csr(&ss, sp_code, &cert, &csr, private_key, public_key, cert_name, cert_text_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating Cert");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should NULL");

	// Test 1: Test case: Cannot download referenced certificate
    printf("=== Testing case [1]: Cannot download referenced certificate\n");
    status = stir_shaken_verify(&ss, sih, "Bad cert URL", &jpass);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Err, should return STATUS_FALSE");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 1, "Err, error condition not set (but should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_description != NULL, "Err, error description not set");
	printf("Error description is: '%s'\n", error_description);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO, "Err, error should be SIP_436_BAD_IDENTITY_INFO");
	
	// Test 2: Test case: malformed SIP Identity header (missing dot separating fields)
    printf("=== Testing case [2]: Malformed SIP Identity header (missing dot separating fields)\n");
	
	// Prepare malformed SIP Identity header
	len = strlen(sih);
	sih_malformed = malloc(len + 1);
	stir_shaken_assert(sih_malformed, "Cannot continue, out of memory");
	memcpy(sih_malformed, sih, len);
	sih_malformed[len] = '\0';
    p = strchr(sih_malformed, '.');
    stir_shaken_assert(p && (p + 1 != strchr(sih_malformed, '\0')), "Err, Bad Idenity Header produced"); 
	*p = 'X';  // (Screw it) Hah, everything you would expect but not this!

    status = stir_shaken_verify_with_cert(&ss, sih_malformed, &cert);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Err, should return STATUS_FALSE");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 1, "Err, error condition not set (but should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_description != NULL, "Err, error description not set");
	printf("Error description is: '%s'\n", error_description);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER, "Err, error should be SIP_438_INVALID_IDENTITY_HEADER");
	
	// Test 3: Test case: malformed SIP Identity header (wrong signature)
    printf("=== Testing case [3]: Malformed SIP Identity header (wrong signature)\n");
	
	// Prepare malformed SIP Identity header
	memcpy(sih_malformed, sih, len);
	
	if (sih_malformed[0] == 'a') {
		sih_malformed[0] = 'b';
	} else {
		sih_malformed[0] = 'a';
	}

    status = stir_shaken_verify_with_cert(&ss, sih_malformed, &cert);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Err, should return STATUS_FALSE");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 1, "Err, error condition not set (but should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_description != NULL, "Err, error description not set");
	printf("Error description is: '%s'\n", error_description);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER_SIGNATURE, "Err, error should be SIP_438_INVALID_IDENTITY_HEADER_SIGNATURE");


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
	
	free(sih_malformed);
	sih_malformed = NULL;
	
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
	stir_shaken_jwt_passport_destroy(&jpass);
    
    return STIR_SHAKEN_STATUS_OK;
}

int main(void)
{
	stir_shaken_do_init(NULL);

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {
	
			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_verify_response() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
