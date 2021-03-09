#include <stir_shaken.h>

const char *path = "./test/run";


stir_shaken_status_t stir_shaken_unit_test_sign_verify_data(void)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	const char *data_test_pass = "unit test 2 pass";
	const char *data_test_fail = "unit test 2 fail";
	size_t datalen = 0;
	unsigned char sig[PBUF_LEN] = { 0 };
	size_t outlen = 0;

	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };

	EC_KEY *ec_key = NULL;
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *public_key = NULL;
	int i = -1;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	

	sprintf(private_key_name, "%s%c%s", path, '/', "u1_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u1_public_key.pem");

	printf("=== Unit testing: STIR/Shaken verify data\n\n");

	// Generate new keys for this test
	status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key");
	stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

	/* Test */
	printf("Signing...\n\n");

	datalen = strlen(data_test_pass);
	outlen = sizeof(sig);
	status = stir_shaken_do_sign_data_with_digest(&ss, "sha256", private_key, data_test_pass, datalen, sig, &outlen);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to sign\n");

	printf("Verifying (against good data)...\n\n");
	i = stir_shaken_do_verify_data(&ss, data_test_pass, strlen(data_test_pass), sig, outlen, public_key);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(i == 0, "Err, verify failed");
	stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	printf("Verifying (against bad data)...\n\n");
	i = stir_shaken_do_verify_data(&ss, data_test_fail, strlen(data_test_fail), sig, outlen, public_key);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(i == 1, "Err, verify failed");
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);

	return STIR_SHAKEN_STATUS_OK;
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

	if (stir_shaken_unit_test_sign_verify_data() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	printf("OK\n");

	stir_shaken_do_deinit();

	return 0;
}
