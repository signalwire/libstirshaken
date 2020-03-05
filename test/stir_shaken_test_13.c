#include <stir_shaken.h>

const char *path = "./test/run";


struct sp {
	stir_shaken_ssl_keys_t keys;
	uint32_t code;
	stir_shaken_csr_t csr;
	stir_shaken_cert_t cert;

	char private_key_name[300];
	char public_key_name[300];
	char csr_name[300];
	char csr_text_name[300];
	char cert_name[300];
	char cert_text_name[300];
	const char *subject_c;
	const char *subject_cn;
	int serial;
	int expiry_days;
} sp;

#define PRINT_SHAKEN_ERROR_IF_SET \
	if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

stir_shaken_status_t stir_shaken_unit_test_sp_cert_req(void)
{
	EVP_PKEY *pkey = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;

	stir_shaken_http_req_t http_req = { 0 };
	const char *kid = NULL, *nonce = NULL, *url = NULL, *nb = NULL, *na = NULL;
	char *json = NULL;
	char *spc_token = NULL;


	sprintf(sp.private_key_name, "%s%c%s", path, '/', "13_sp_private_key.pem");
	sprintf(sp.public_key_name, "%s%c%s", path, '/', "13_sp_public_key.pem");
	sprintf(sp.csr_name, "%s%c%s", path, '/', "13_sp_csr.pem");
	sprintf(sp.csr_text_name, "%s%c%s", path, '/', "13_sp_csr_text.pem");
	sprintf(sp.cert_name, "%s%c%s", path, '/', "13_sp_cert.crt");
	sprintf(sp.cert_text_name, "%s%c%s", path, '/', "13_sp_cert_text.crt");


	// 1
	// SP obtains SPC and SPC token from PA and can now construct CSR

	printf("SP: Generate SP keys\n");

	// Generate SP keys
	sp.keys.priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	status = stir_shaken_generate_keys(&ss, &sp.keys.ec_key, &sp.keys.private_key, &sp.keys.public_key, sp.private_key_name, sp.public_key_name, sp.keys.priv_raw, &sp.keys.priv_raw_len);
	PRINT_SHAKEN_ERROR_IF_SET
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(sp.keys.ec_key != NULL, "Err, failed to generate EC key\n\n");
	stir_shaken_assert(sp.keys.private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(sp.keys.public_key != NULL, "Err, failed to generate public key");

	printf("SP: Create CSR\n");
	sp.code = 7777;
	sp.subject_c = "US";
	sp.subject_cn = "NewSTI-SP, But Absolutely Fine Inc.";

	status = stir_shaken_generate_csr(&ss, sp.code, &sp.csr.req, sp.keys.private_key, sp.keys.public_key, sp.subject_c, sp.subject_cn);
	PRINT_SHAKEN_ERROR_IF_SET
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");

	// Reqeust STI cetificate

	kid = NULL;
	nonce = NULL;
	url = "https://sti-ca.com/api";
	nb = "01 Apr 2020";
	na = "01 Apr 2021";
	spc_token = "SPCtoken";
	
	http_req.url = strdup(url);

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_sp_cert_req(&ss, &http_req, kid, nonce, sp.csr.req, nb, na, sp.keys.priv_raw, sp.keys.priv_raw_len, NULL, spc_token)) {
		printf("STIR-Shaken: Failed to execute cert request\n");
		PRINT_SHAKEN_ERROR_IF_SET
		return STIR_SHAKEN_STATUS_TERM;
	}


	// SP cleanup	
	stir_shaken_destroy_cert(&sp.cert);
	stir_shaken_destroy_csr(&sp.csr.req);
	stir_shaken_destroy_keys(&sp.keys.ec_key, &sp.keys.private_key, &sp.keys.public_key);
	stir_shaken_destroy_http_request(&http_req);

	return status;
}

int main(void)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_do_init(NULL, NULL, NULL), "Cannot init lib");

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {

			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_sp_cert_req() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
