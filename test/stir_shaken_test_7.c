#include <stir_shaken.h>

const char *path = "./test/run";
const char *x5u = "https://not.here.org/passport.cer";
const char *attest = "B";
const char *desttn_key = "uri";
const char *desttn_val = "sip:Obama@democrats.com";
int iat = 9876543;
const char *origtn_key = "";
const char *origtn_val = "07483866525";
const char *origid = "Trump's Office";


static int test_passport_data(stir_shaken_jwt_passport_t *passport)
{
	const char *p = NULL;
	long int iat_ = -1;

    // test JWT header
    p = stir_shaken_jwt_passport_get_header(passport, "alg");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(p, "ES256"), "ERROR: wrong param value");

    p = stir_shaken_jwt_passport_get_header(passport, "ppt");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(p, "shaken"), "ERROR: wrong param value");

    p = stir_shaken_jwt_passport_get_header(passport, "typ");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(p, "passport"), "ERROR: wrong param value");

    p = stir_shaken_jwt_passport_get_header(passport, "x5u");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(p, x5u), "ERROR: wrong param value");

    // test JWT paylaod
    p = stir_shaken_jwt_passport_get_grant(passport, "attest");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(p, attest), "ERROR: wrong param value");
    
    p = stir_shaken_jwt_passport_get_grant(passport, "dest");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    
    iat_ = stir_shaken_jwt_passport_get_grant_int(passport, "iat");
    stir_shaken_assert(errno != ENOENT, "PASSporT is missing param");
    stir_shaken_assert(iat_ == iat, "ERROR: wrong param value");
    
    p = stir_shaken_jwt_passport_get_grant(passport, "orig");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    
    p = stir_shaken_jwt_passport_get_grant(passport, "origid");
    stir_shaken_assert(p != NULL, "PASSporT is missing param");
    stir_shaken_assert(!strcmp(p, origid), "ERROR: wrong param value");
	
	return 0;
}

stir_shaken_status_t stir_shaken_unit_test_passport_data(void)
{
    stir_shaken_jwt_passport_t passport = { 0 };
    char *p = NULL, *s = NULL, *encoded = NULL;
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid };
    
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	


	sprintf(private_key_name, "%s%c%s", path, '/', "u7_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u7_public_key.pem");

    printf("=== Unit testing: STIR/Shaken PASSporT data\n\n");
    
	// Generate new keys for this test
    status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}

    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

    /* Test */
	status = stir_shaken_jwt_passport_init(&ss, &passport, &params, priv_raw, priv_raw_len);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
    
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "PASSporT has not been created");
    stir_shaken_assert(passport.jwt != NULL, "JWT has not been created");
	s = stir_shaken_jwt_passport_dump_str(&passport, 1);
	printf("1. JWT:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;

	test_passport_data(&passport);

	status = stir_shaken_jwt_passport_sign(&ss, &passport, priv_raw, priv_raw_len, &encoded);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to sign PASSporT");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
	
	test_passport_data(&passport);
    
    printf("OK\n\n");
	
	stir_shaken_free_jwt_str(encoded);
	encoded = NULL;
	
	stir_shaken_jwt_passport_destroy(&passport);
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
    
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

	if (stir_shaken_unit_test_passport_data() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
