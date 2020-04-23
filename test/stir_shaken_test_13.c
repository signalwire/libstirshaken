#include <stir_shaken.h>


const char *path = "./test/run";

stir_shaken_sp_t sp;

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
	const char *kid = NULL, *nonce = NULL, *nb = NULL, *na = NULL;
	char spc[STIR_SHAKEN_BUFLEN] = { 0 };
	char url[STIR_SHAKEN_BUFLEN] = { 0 };
	char *json = NULL;
	char *spc_token = NULL;


	sprintf(sp.private_key_name, "%s%c%s", path, '/', "13_sp_private_key.pem");
	sprintf(sp.public_key_name, "%s%c%s", path, '/', "13_sp_public_key.pem");
	sprintf(sp.csr_name, "%s%c%s", path, '/', "13_sp_csr.pem");
	sprintf(sp.cert_name, "%s%c%s", path, '/', "13_sp_cert.crt");


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
	sp.code = 101;
	sprintf(spc, "%d", sp.code);
	snprintf(sp.subject_c, STIR_SHAKEN_BUFLEN, "US");
	snprintf(sp.subject_cn, STIR_SHAKEN_BUFLEN, "NewSTI-SP 101");

	status = stir_shaken_generate_csr(&ss, sp.code, &sp.csr.req, sp.keys.private_key, sp.keys.public_key, sp.subject_c, sp.subject_cn);
	PRINT_SHAKEN_ERROR_IF_SET
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");

	// Reqeust STI cetificate

	kid = NULL;
	nonce = NULL;
	sprintf(url, "http://%s%s", STI_CA_ACME_ADDR, STI_CA_ACME_CERT_REQ_URL);
	nb = "01 Apr 2020";
	na = "01 Apr 2021";

	// Set SPC token to this:
	// {
	//	"alg": "ES256",
	//	"issuer": "SignalWire STI-PA",
	//	"typ": "JWT",
	//	"x5u": "https://jazzchat.pl/pa.pem"
	// }.{
	//	"notAfter": "1 year from now",
	//	"notBefore": "today",
	//	"spc": "7889",
	//	"type": "spc-token"
	// }
	//
	// Obtained by running:
	//
	//		./stirshaken spc-token --privkey test/ref/pa/pa.priv --url http://190.102.98.199/pa.pem --spc 7889 --issuer_cn "SignalWire STI-PA" -f test/ref/sp/spc_token.txt --vvv
	//
	//spc_token = "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIiwidHlwIjoiSldUIiwieDV1IjoiaHR0cHM6Ly9qYXp6Y2hhdC5wbC9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiNzg4OSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.QLfCOj8sSxqe3ghSN1r2cm6AxOGXodAQdYM5KNqnu2GNz5zNJfq-Bv7fUHDRuTgfkyqqaSLgzfLa-25G_awizA";
	spc_token = "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIiwidHlwIjoiSldUIiwieDV1IjoiaHR0cHM6Ly9qYXp6Y2hhdC5wbC9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMTAxIiwidHlwZSI6InNwYy10b2tlbiJ9.iCoBGdA6sD4FYfSsGGXWMfL4ja9aW747llHHSSY7rvcH67L_l0Q-mFhjiMuEpq2gBkihz7g67CZCs4Tr0FfWNw";
    http_req.url = strdup(url);

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_sp_cert_req_ex(&ss, &http_req, kid, nonce, sp.csr.req, nb, na, spc, sp.keys.priv_raw, sp.keys.priv_raw_len, NULL, spc_token)) {
		printf("STIR-Shaken: Failed to execute cert request\n");
		PRINT_SHAKEN_ERROR_IF_SET
		return STIR_SHAKEN_STATUS_TERM;
	}

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_load_x509_from_mem(&ss, &sp.cert.x, NULL, http_req.response.mem.mem), "Failed to load X509 from memory");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_x509_to_disk(&ss, sp.cert.x, "test/run/13_sp.pem"), "Failed to save the certificate");


	// SP cleanup	
	stir_shaken_sp_destroy(&sp);
	stir_shaken_destroy_http_request(&http_req);

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

	if (stir_shaken_unit_test_sp_cert_req() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
