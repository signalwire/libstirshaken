#include <stir_shaken.h>

const char *path = "./test/run";


stir_shaken_status_t stir_shaken_unit_test_sign_verify_data(void)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
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

	printf("=== Unit testing: STIR/Shaken Sign-verify (in memory) [stir_shaken_unit_test_sign_verify_data]\n\n");

	// Generate new keys for this test
	status = stir_shaken_generate_keys(NULL, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);

	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key");
	stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

	/* Test */
	printf("Signing...\n\n");

	datalen = strlen(data_test_pass);
	outlen = sizeof(sig);
	status = stir_shaken_do_sign_data_with_digest(NULL, "sha256", private_key, data_test_pass, datalen, sig, &outlen);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to sign\n");

	printf("Verifying (against good data)...\n\n");
	i = stir_shaken_do_verify_data(NULL, data_test_pass, strlen(data_test_pass), sig, outlen, public_key);
	stir_shaken_assert(i == 0, "Err, verify failed");

	printf("Verifying (against bad data)...\n\n");
	i = stir_shaken_do_verify_data(NULL, data_test_fail, strlen(data_test_fail), sig, outlen, public_key);
	stir_shaken_assert(i == 1, "Err, verify failed");
	
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

	if (stir_shaken_unit_test_sign_verify_data() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}

	printf("OK\n");

	stir_shaken_do_deinit();

	return 0;
}
