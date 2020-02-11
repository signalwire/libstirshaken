#include <stir_shaken.h>

const char *path = "./test/run";

/**
 * Note.
 *
 * Running this test may show a "still reachable" memory leak. Example:
 *
 * ==18899==
 * ==18899== HEAP SUMMARY:
 * ==18899==     in use at exit: 192 bytes in 12 blocks
 * ==18899==   total heap usage: 7,484 allocs, 7,472 frees, 526,015 bytes allocated
 * ==18899==
 * ==18899== 48 bytes in 6 blocks are still reachable in loss record 1 of 2
 * ==18899==    at 0x483577F: malloc (vg_replace_malloc.c:299)
 * ==18899==    by 0x5959A93: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595B07B: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F3A4: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F3F8: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F42D: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x59599D9: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595A8CE: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5956788: gcry_control (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5102793: libssh2_init (in /usr/lib/x86_64-linux-gnu/libssh2.so.1.0.1)
 * ==18899==    by 0x48AEA87: ??? (in /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4.5.0)
 * ==18899==    by 0x486813E: stir_shaken_make_http_req (stir_shaken_service.c:410)
 * ==18899==
 * ==18899== 144 bytes in 6 blocks are still reachable in loss record 2 of 2
 * ==18899==    at 0x483577F: malloc (vg_replace_malloc.c:299)
 * ==18899==    by 0x5959A93: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595B07B: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F3C1: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5A1F42D: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x59599D9: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x595A8CE: ??? (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5956788: gcry_control (in /usr/lib/x86_64-linux-gnu/libgcrypt.so.20.2.4)
 * ==18899==    by 0x5102793: libssh2_init (in /usr/lib/x86_64-linux-gnu/libssh2.so.1.0.1)
 * ==18899==    by 0x48AEA87: ??? (in /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4.5.0)
 * ==18899==    by 0x486813E: stir_shaken_make_http_req (stir_shaken_service.c:410)
 * ==18899==    by 0x486AE03: stir_shaken_verify (stir_shaken_verify.c:578)
 *
 * ==18899== LEAK SUMMARY:
 * ==18899==    definitely lost: 0 bytes in 0 blocks
 * ==18899==    indirectly lost: 0 bytes in 0 blocks
 * ==18899==      possibly lost: 0 bytes in 0 blocks
 * ==18899==    still reachable: 192 bytes in 12 blocks
 * ==18899==         suppressed: 0 bytes in 0 blocks
 *
 * This is not really a leak, as the memory is freed on process exit. It is shown because some libs are missing
 * curl_global_cleanup and therefore are not freeing up the memory used by curl.
 *
 * Explanation from StackOverflow (https://stackoverflow.com/questions/51503838/why-libcurl-still-leaves-reachable-blocks-after-cleanup-calls):
 * 
 * "libcurl links against many libraries, and some of them do not have a function like curl_global_cleanup which reverts initialization and frees all memory.
 * This happens when libcurl is linked against NSS for TLS support, and also with libssh2 and its use of libgcrypt.
 * GNUTLS as the TLS implementation is somewhat cleaner in this regard.
 *
 * In general, this is not a problem because these secondary libraries are only used on operating systems where memory is freed on process termination,
 * so an explicit cleanup is not needed (and would even slow down process termination). Only with certain memory debuggers, the effect of missing cleanup routines is visible,
 * and valgrind deals with this situation by differentiating between actual leaks (memory to which no pointers are left) and memory which is still reachable at process termination
 * (so that it could have been used again if the process had not terminated)."
 */


stir_shaken_status_t stir_shaken_unit_test_verify_response(void)
{
	stir_shaken_passport_t passport = { 0 };
    const char *x5u = "https://not.here.org/passport.cer";
    const char *attest = "B";
    const char *desttn_key = "uri";
    const char *desttn_val = "sip:Obama@democrats.com";
    int iat = time(NULL);
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
    
    char *sih_spoofed = NULL;
	int len = 0;
    const char *spoofed_origtn_val = "07643866222";
    cJSON *jwt = NULL, *jPayload = NULL, *orig = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;

	stir_shaken_cert_t *res_cert = NULL;
	
	
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
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

    /* Test */
    printf("Authenticating...\n\n");
	status = stir_shaken_jwt_authenticate_keep_passport(&ss, &sih, &params, priv_raw, priv_raw_len, &passport);
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
    
    printf("Creating Certificate\n");
    cert.x = stir_shaken_generate_x509_cert_from_csr(&ss, sp_code, csr.req, private_key, "US", "SignalWires RoboCaller-FREE Network", 365);
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

	// Test 1: Test case: Cannot download referenced certificate
    printf("=== Testing case [1]: Cannot download referenced certificate\n");
    status = stir_shaken_verify(&ss, sih, "Bad url", &passport, NULL, &res_cert, 3600);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(status != STIR_SHAKEN_STATUS_OK, "Err, should return error");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 1, "Err, error condition not set (but should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_description != NULL, "Err, error description not set");
	printf("Error description is: '%s'\n", error_description);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO, "Err, error should be SIP_436_BAD_IDENTITY_INFO");
	
	stir_shaken_passport_destroy(&passport);
	
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

	stir_shaken_clear_error(&ss);
	status = stir_shaken_jwt_verify_with_cert(&ss, sih_malformed, &cert, &passport, NULL);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Err, should return STATUS_FALSE");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 1, "Err, error condition not set (but should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_description != NULL, "Err, error description not set");
	printf("Error description is: '%s'\n", error_description);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER, "Err, error should be SIP_438_INVALID_IDENTITY_HEADER");
	
	stir_shaken_passport_destroy(&passport);

	// Test 3: Test case: malformed SIP Identity header (wrong signature)
    printf("=== Testing case [3]: Malformed SIP Identity header (wrong signature)\n");
	
	// Prepare malformed SIP Identity header
	len = strlen(sih);
	sih_spoofed = malloc(len + 1);
	stir_shaken_assert(sih_spoofed, "Cannot continue, out of memory");
	memcpy(sih_spoofed, sih, len);
	sih_spoofed[len] = '\0';
	
	memcpy(sih_spoofed, sih, len);
	
	if (sih_spoofed[0] == 'a') {
		sih_spoofed[0] = 'b';
	} else {
		sih_spoofed[0] = 'a';
	}

    status = stir_shaken_jwt_verify_with_cert(&ss, sih_spoofed, &cert, &passport, NULL);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Err, should return STATUS_FALSE");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 1, "Err, error condition not set (but should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_description != NULL, "Err, error description not set");
	printf("Error description is: '%s'\n", error_description);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER, "Err, error should be SIP_438_INVALID_IDENTITY_HEADER");

	X509_REQ_free(csr.req);
	csr.req = NULL;

	stir_shaken_destroy_cert(res_cert);
	free(res_cert);
	res_cert = NULL;
	stir_shaken_destroy_cert(&cert);

	free(sih);
	sih = NULL;
	
	free(sih_spoofed);
	sih_spoofed = NULL;
	
	free(sih_malformed);
	sih_malformed = NULL;
	
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
	stir_shaken_passport_destroy(&passport);
    
    return STIR_SHAKEN_STATUS_OK;
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

	if (stir_shaken_unit_test_verify_response() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
