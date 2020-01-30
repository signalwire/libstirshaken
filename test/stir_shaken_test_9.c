#include <stir_shaken.h>

const char *path = "./test/run";


stir_shaken_status_t stir_shaken_unit_test_verify_with_cert_spoofed(void)
{
	stir_shaken_passport_t passport = { 0 };
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
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;

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
	char private_key_name_spoofed[300] = { 0 };
	char public_key_name_spoofed[300] = { 0 };

    uint32_t sp_code = 1800;

    stir_shaken_csr_t csr = {0};
    stir_shaken_cert_t cert = {0};
    
    char *spoofed_sih = NULL, *p = NULL;
    const char *spoofed_origtn_val = "07643866222";
	jwt_t *jwt = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	
    
	EC_KEY *ec_key_spoofed = NULL;
    EVP_PKEY *private_key_spoofed = NULL;
    EVP_PKEY *public_key_spoofed = NULL;
	unsigned char	priv_raw_spoofed[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len_spoofed = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	


	sprintf(private_key_name, "%s%c%s", path, '/', "u9_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u9_public_key.pem");
    sprintf(csr_name, "%s%c%s", path, '/', "u9_csr.pem");
    sprintf(csr_text_name, "%s%c%s", path, '/', "u9_csr_text.pem");
    sprintf(cert_name, "%s%c%s", path, '/', "u9_cert.crt");
    sprintf(cert_text_name, "%s%c%s", path, '/', "u9_cert_text.crt");
	sprintf(private_key_name_spoofed, "%s%c%s", path, '/', "u9_private_key_spoofed.pem");
	sprintf(public_key_name_spoofed, "%s%c%s", path, '/', "u9_public_key_spoofed.pem");

    printf("=== Unit testing: STIR/Shaken Verification against good and spoofed SIP Identity Header [stir_shaken_unit_test_verify]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

    /* Test */
    printf("Authorizing...\n\n");
	status = stir_shaken_jwt_authorize(&ss, &sih, &params, priv_raw, priv_raw_len);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
    
    printf("SIP Identity Header:\n%s\n\n", sih);

    printf("Creating CSR\n");
    status = stir_shaken_generate_csr(&ss, sp_code, &csr.req, private_key, public_key, csr_name, csr_text_name);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
    
    printf("Creating Certificate\n");
    status = stir_shaken_generate_cert_from_csr(&ss, sp_code, &cert, &csr, private_key, public_key, cert_name, cert_text_name, 365);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating Cert");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

    printf("Verifying SIP Identity Header's signature with Cert... (against good data)\n\n");
    status = stir_shaken_jwt_verify_with_cert(&ss, sih, &cert, &passport, NULL);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, verifying");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
	
	printf("Verifying SIP Identity Header's signature with Cert...\n\n");
    status = stir_shaken_jwt_verify_with_cert(&ss, sih, &cert, &passport, NULL);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, verifying");
	stir_shaken_assert(passport.jwt, "Err, verifying: JWT not returned");
	p = stir_shaken_passport_dump_str(&passport, 1);
    printf("PASSporT (decoded from SIH) is:\n%s\n\n", p);
	stir_shaken_free_jwt_str(p);
	p = NULL;

	stir_shaken_passport_destroy(&passport);

    // Spoofed SIP Identity Header
    
	printf("Authorizing with Spoofed SIP Identity Header (changed Telephone Number and signed with wrong key)...\n\n");
    
	// This simulates spoofed Telephone Number value
	params.origtn_val = spoofed_origtn_val;
    
	// Generate spoofed keys
    status = stir_shaken_generate_keys(&ss, &ec_key_spoofed, &private_key_spoofed, &public_key_spoofed, private_key_name_spoofed, public_key_name_spoofed, priv_raw_spoofed, &priv_raw_len_spoofed);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key_spoofed != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key_spoofed != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key_spoofed != NULL, "Err, failed to generate public key");

    // Using same signature, same data, apart from spoofed Telephone Number
	status = stir_shaken_jwt_authorize(&ss, &spoofed_sih, &params, priv_raw_spoofed, priv_raw_len_spoofed);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(spoofed_sih != NULL, "Failed to create (spoofed) SIP Identity Header");
    printf("Spoofed SIP Identity Header:\n%s\n\n", spoofed_sih);
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
    
    printf("Verifying SIP Identity Header's signature with Cert... (against spoofed SIP Identity Header)\n\n");
    status = stir_shaken_jwt_verify_with_cert(&ss, spoofed_sih, &cert, &passport, NULL);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Err, verifying");
	if (passport.jwt != NULL) {
		p = stir_shaken_passport_dump_str(&passport, 1);
		printf("Ooops, PASSporT (decoded from spoofed SIH) is:\n%s\n\n", p);
		stir_shaken_free_jwt_str(p);
		p = NULL;
	}
	stir_shaken_assert(passport.jwt == NULL, "WTF: JWT returned from spoofed call...");

	stir_shaken_passport_destroy(&passport);
	
	X509_REQ_free(csr.req);
	csr.req = NULL;
		
	X509_free(cert.x);
	cert.x = NULL;

	free(sih);
	sih = NULL;
	
	free(spoofed_sih);
	spoofed_sih = NULL;
	
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
	stir_shaken_destroy_keys(&ec_key_spoofed, &private_key_spoofed, &public_key_spoofed);
    
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

	if (stir_shaken_unit_test_verify_with_cert_spoofed() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
