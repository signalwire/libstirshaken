#include <stir_shaken.h>


#define BUF_LEN 1000

const char *path = "./test/run";


stir_shaken_status_t stir_shaken_unit_test_passport_create_verify_signature(void)
{
    stir_shaken_passport_t passport = {0};
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
    const char *x5u = "https://cert.example.org/passport.cer";      // ref
    const char *attest = "B";
    const char *desttn_key = "uri";                                 // ref
    const char *desttn_val = "sip:alice@example.com";               // ref
    int iat = 1471375418;                                           // ref
    const char *origtn_key = "tn";                                  // ref test for orig telephone number
    const char *origtn_val = "12155551212";                         // ref
    const char *origid = "Later";
    uint8_t ppt_ignore = 1;                                         // ignore, ref test case doesn't include this field
    
	char *s = NULL, *encoded = NULL;

	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    
    unsigned char signature[BUF_LEN] = {0};
    int len = 0, i = -1, ret = -1;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	
	unsigned char	pub_raw[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int				pub_raw_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid, .ppt_ignore = ppt_ignore};
	jwt_t *jwt = NULL;

    
	sprintf(private_key_name, "%s%c%s", path, '/', "u3_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u3_public_key.pem");

    printf("=== Unit testing: STIR/Shaken PASSporT create/encode/decode\n\n");
    
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
	status = stir_shaken_passport_init(&ss, &passport, &params, priv_raw, priv_raw_len);
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
	s = stir_shaken_passport_dump_str(&passport, 1);
	printf("1. JWT:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;


    // Test encodeing/decoding with libjwt

	encoded = jwt_encode_str(passport.jwt);
	stir_shaken_assert(encoded, "Ooops, libjwt failed to encode string");
	
	ret = stir_shaken_pubkey_to_raw(&ss, public_key, pub_raw, &pub_raw_len);
    if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(ret == STIR_SHAKEN_STATUS_OK, "Failed to get public key raw from EVP KEY");
    stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
    stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
    stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	ret = jwt_decode(&jwt, encoded, pub_raw, pub_raw_len);
	stir_shaken_assert(ret == STIR_SHAKEN_STATUS_OK, "JWT encode/decode does not work");
	jwt_free(jwt);

    printf("\nOK\n\n");

	jwt_free_str(encoded);
	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);
	stir_shaken_passport_destroy(&passport);

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

	if (stir_shaken_unit_test_passport_create_verify_signature() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
