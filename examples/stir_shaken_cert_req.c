#include <stir_shaken.h>


/**
 * This example demonstrates how to execute STI certificate request and download test certificate from SignalWire.
 * This test certificate is signed by test CA (test/ref/ca/ca.pem) and thus it allows to make Shaken protected calls on a network spanned by that CA (built from participants who trust test reference CA).
 * Any STI-SP verification service who trusts that CA (by using it's cert as a root anchor) will honour PASSporTs created with STI certificate obtained by running this code.
 **/

int main(void)
{
	stir_shaken_sp_t sp = { 0 };
	stir_shaken_http_req_t http_req = { 0 };
	char *spc_token = NULL;

	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;


	// We set log to very verbose but it can be less: MEDIUM, BASIC or even NOTHING at all
	status = stir_shaken_do_init(&ss, NULL, NULL, STIR_SHAKEN_LOGLEVEL_HIGH);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("Cannot init lib\n");
		goto exit;
	}

	printf("Loading keys...\n");
	sp.keys.priv_raw_len = sizeof(sp.keys.priv_raw);
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(&ss, &sp.keys.private_key, &sp.keys.public_key, "test/ref/sp/sp.priv", "test/ref/sp/sp.pub", sp.keys.priv_raw, &sp.keys.priv_raw_len)) {
		goto exit;
	}

	printf("Loading CSR...\n");
	sp.csr.req = stir_shaken_load_x509_req_from_file(&ss, "test/ref/sp/csr.pem");
	if (!sp.csr.req) {
		goto exit;
	}

	printf("Requesting STI certificate...\n");

	// Set SPC token to this:
	// SPC token encoded:
	//
	// eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIFRlc3QiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJwYS5zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.l61Y8K1bwZw9APXsrAQPZVPAkx5UIucwNKzRWxn0N5DcdVWaEgA_i5tW65f_aeqA46CTP789l4o6rFpiN7IZUA
	//
	// SPC token decoded:
	//
	//
	// {
	//    "alg": "ES256",
	//    "issuer": "SignalWire STI-PA Test",
	//    "typ": "JWT",
	//    "x5u": "pa.shaken.signalwire.cloud/pa.pem"
	// }
	// .
	// {
	//    "notAfter": "1 year from now",
	//    "notBefore": "today",
	//    "spc": "1",
	//    "type": "spc-token"
	// }



	spc_token = "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIFRlc3QiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJwYS5zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.l61Y8K1bwZw9APXsrAQPZVPAkx5UIucwNKzRWxn0N5DcdVWaEgA_i5tW65f_aeqA46CTP789l4o6rFpiN7IZUA";
	http_req.url = strdup("https://ca.shaken.signalwire.cloud/sti-ca/acme/cert");
	http_req.remote_port = 8082;

	status = stir_shaken_sp_cert_req_ex(&ss, &http_req, NULL, NULL, sp.csr.req, "20 Apr 2020", "20 Apr 2040", "1", sp.keys.priv_raw, sp.keys.priv_raw_len, NULL, spc_token);
	if (status != STIR_SHAKEN_STATUS_OK) {
		printf("Cannot obtain certificate\n");
		goto exit;
	}

	printf("Loading certificate into X509...\n");
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_x509_from_mem(&ss, &sp.cert.x, NULL, http_req.response.mem.mem)) {
		printf("Failed to load SP certificate into X509");
		goto exit;
	}

	printf("Saving certificate as sp_test.pem...\n");
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(&ss, sp.cert.x, "sp_test.pem")) {
		printf("Failed to save SP certificate");
		goto exit;
	}

exit:

	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}

	stir_shaken_sp_destroy(&sp);
	stir_shaken_destroy_http_request(&http_req);
	stir_shaken_do_deinit();

	return 0;
}
