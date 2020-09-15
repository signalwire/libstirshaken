#include <stir_shaken.h>


/**
 * This example demonstrates how to create and run simplest STI Certificate Authority service (STI-CA).
 * Once the program is running, certificate can be obtained with this call:
 *		./stirshaken sp-cert-req --url http://ca.shaken.signalwire.com/sti-ca/acme/cert --port 8082 --privkey test/ref/sp/sp.priv --pubkey test/ref/sp/sp.pub --csr test/ref/sp/csr.pem --spc 1 --spc_token eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIFRlc3QiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL3BhLnNoYWtlbi5zaWduYWx3aXJlLmNvbS9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.Q2_oc3Ssd_Nz1Ex_B2nm8C8iiN9OzgxBRsljuEqkFdiEh5wkAHhqnQd54bITs2k4M6p9ePfRV5-8qtsXVkUp-Q -f sptest.pem --vvv 
 **/

int main(void)
{
	stir_shaken_ca_t	ca = { .port = 8082, .use_ssl = 0, .issuer_c = "US", .issuer_cn = "SignalWire STI-CA Test", .tn_auth_list_uri = "http://sti-ca/tnauthlist", .expiry_days = 9999, .serial = 1 };
	const char	*error_description = NULL;
	stir_shaken_context_t	ss = { 0 };
	stir_shaken_error_t		error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;


	status = stir_shaken_do_init(&ss, "examples/pa", "NULL", STIR_SHAKEN_LOGLEVEL_HIGH);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("Cannot init lib\n");
		goto exit;
	}
	printf("Loading keys...\n");
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(&ss, &ca.keys.private_key, NULL, "test/ref/ca/ca.priv", NULL, NULL, NULL)) {
		goto exit;
	}

	printf("Loading CA certificate...\n");
	ca.cert.x = stir_shaken_load_x509_from_file(&ss, "test/ref/ca/ca.pem");
	if (!ca.cert.x) {
		goto exit;
	}

	printf("Starting CA service...\n");
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_run_ca_service(&ss, &ca)) {
		goto exit;
	}


exit:

	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}

	stir_shaken_ca_destroy(&ca);
	stir_shaken_do_deinit();

	return 0;
}
