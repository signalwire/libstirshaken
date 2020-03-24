#include <stir_shaken.h>

const char *path = "./test/run";


stir_shaken_status_t stir_shaken_unit_test_verify_with_cert(void)
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
    char *sih = NULL, *p = NULL;
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

    uint32_t sp_code = 1800;

    stir_shaken_csr_t csr = {0};
    stir_shaken_cert_t cert = {0};

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	


	sprintf(private_key_name, "%s%c%s", path, '/', "u8_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u8_public_key.pem");
    sprintf(csr_name, "%s%c%s", path, '/', "u8_csr.pem");
    sprintf(csr_text_name, "%s%c%s", path, '/', "u8_csr_text.pem");
    sprintf(cert_name, "%s%c%s", path, '/', "u8_cert.crt");
    sprintf(cert_text_name, "%s%c%s", path, '/', "u8_cert_text.crt");

    printf("=== Unit testing: STIR/Shaken Verification [stir_shaken_unit_test_verify]\n\n");
    
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
	status = stir_shaken_jwt_authenticate(&ss, &sih, &params, priv_raw, priv_raw_len);
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
    
    printf("Created SIP Identity Header\n\n");
    printf("SIP Identity Header:\n%s\n", sih);

    printf("Creating CSR\n");
    status = stir_shaken_generate_csr(&ss, sp_code, &csr.req, private_key, public_key, "US", "NewSTI-SP, But OK Inc.");
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

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_csr_to_disk(&ss, csr.req, csr_name), "Error writing CSR to disk");
    
    printf("Creating Certificate\n");
    cert.x = stir_shaken_generate_x509_cert_from_csr(&ss, sp_code, csr.req, private_key, "US", "SignalWire Solutions", 1, 365);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(cert.x != NULL, "Err, generating Cert");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_x509_to_disk(&ss, cert.x, cert_name), "Failed to write cert to disk");

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
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	stir_shaken_passport_destroy(&passport);

	X509_REQ_free(csr.req);
	csr.req = NULL;
		
	X509_free(cert.x);
	cert.x = NULL;

	free(sih);
	sih = NULL;
	
	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);
    
    return status;
}

int main(void)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_do_init(NULL, NULL, NULL, STIR_SHAKEN_LOGLEVEL_HIGH), "Cannot init lib");

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {
	
			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_verify_with_cert() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
