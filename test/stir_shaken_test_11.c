#include <stir_shaken.h>

const char *path = "./test/run";

stir_shaken_status_t stir_shaken_unit_test_jwt_authenticate_keep_passport(void)
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

	char *passport_rx = NULL, *passport_tx = NULL;
	stir_shaken_passport_t passport = { 0 };


	sprintf(private_key_name, "%s%c%s", path, '/', "u11_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u11_public_key.pem");
    sprintf(csr_name, "%s%c%s", path, '/', "u11_csr.pem");
    sprintf(csr_text_name, "%s%c%s", path, '/', "u11_csr_text.pem");
    sprintf(cert_name, "%s%c%s", path, '/', "u11_cert.crt");
    sprintf(cert_text_name, "%s%c%s", path, '/', "u11_cert_text.crt");

    printf("=== Unit testing: STIR/Shaken Verification [stir_shaken_unit_test_verify]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");
    
	printf("Creating CSR\n");
    status = stir_shaken_generate_csr(&ss, sp_code, &csr.req, private_key, public_key, "US", "NewSTI-SP, But OK Inc.");
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");
    
    printf("Creating Certificate\n");
    cert.x = stir_shaken_generate_x509_cert_from_csr(&ss, sp_code, csr.req, private_key, "US", "SignalWire", 0, 365);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(cert.x != NULL, "Err, generating Cert");

    /* Test */
    printf("Test 1: Authorizing (forget PASSporT)...\n\n");
	status = stir_shaken_jwt_authenticate(&ss, &sih, &params, priv_raw, priv_raw_len);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    
    printf("Created SIP Identity Header\n\n");
    printf("SIP Identity Header:\n%s\n\n", sih);

    printf("Verifying SIP Identity Header's signature with Cert...\n\n");
    status = stir_shaken_jwt_verify_with_cert(&ss, sih, &cert, &passport, NULL);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, verifying");
	stir_shaken_assert(passport.jwt, "Err, verifying: JWT not returned");
	passport_rx = stir_shaken_passport_dump_str(&passport, 1);
    printf("PASSporT (decoded from SIH) is:\n%s\n\n", passport_rx);
	stir_shaken_free_jwt_str(passport_rx);
	passport_rx = NULL;

	stir_shaken_passport_destroy(&passport);
	free(sih);
	sih = NULL;
    
	printf("Test 2: Authorizing (retrieving PASSporT)...\n\n");
	status = stir_shaken_jwt_authenticate_keep_passport(&ss, &sih, &params, priv_raw, priv_raw_len, &passport);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    
    printf("Created SIP Identity Header\n\n");
    printf("SIP Identity Header:\n%s\n\n", sih);

	// PASSporT transmitted
	passport_tx = stir_shaken_passport_dump_str(&passport, 1);
	stir_shaken_assert(passport_tx != NULL, "Failed to dump PASSporT");
    printf("Created PASSporT\n\n");
    printf("PASSporT:\n%s\n", passport_tx);
	stir_shaken_passport_destroy(&passport);

    printf("Verifying SIP Identity Header's signature with Cert...\n\n");
    status = stir_shaken_jwt_verify_with_cert(&ss, sih, &cert, &passport, NULL);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, verifying");
	stir_shaken_assert(passport.jwt, "Err, verifying: JWT not returned");

	// PASSporT received
	passport_rx = stir_shaken_passport_dump_str(&passport, 1);
    printf("PASSporT (decoded from SIH) is:\n%s\n\n", passport_rx);

	// And now...
    printf("Checking retrieved PASSporT (comparing with source PASSporT used to create SIH)...\n");
	stir_shaken_assert(strcmp(passport_rx, passport_tx) == 0, "Err, PASSporT retrieved is different from used to create it...");
	
	stir_shaken_free_jwt_str(passport_rx);
	passport_rx = NULL;

	stir_shaken_passport_destroy(&passport);
	free(sih);
	sih = NULL;
	stir_shaken_free_jwt_str(passport_tx);
	passport_tx = NULL;

	X509_REQ_free(csr.req);
	csr.req = NULL;
		
	X509_free(cert.x);
	cert.x = NULL;
	
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
    
    return status;
}

int main(void)
{
	stir_shaken_do_init(NULL, NULL, NULL);

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {
	
			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_jwt_authenticate_keep_passport() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
