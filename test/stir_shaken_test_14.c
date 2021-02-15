#include <stir_shaken.h>

const char *path = "./test/run";


stir_shaken_ca_t ca;
stir_shaken_sp_t sp;
stir_shaken_cert_t		cert_cached;
stir_shaken_context_t	ss;

const char *sp_pem = "-----BEGIN CERTIFICATE-----\n"
"MIICBTCCAaugAwIBAgIBATAKBggqhkjOPQQDAjAuMQswCQYDVQQGEwJVUzEfMB0G\n"
"A1UEAwwWU2lnbmFsV2lyZSBTVEktQ0EgVGVzdDAeFw0yMDA4MDEwMDM3MTlaFw00\n"
"NzEyMTcwMDM3MTlaMC4xCzAJBgNVBAYTAlVTMR8wHQYDVQQDDBZTaWduYWxXaXJl\n"
"IFNUSS1TUCBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV9UoHnzedLPO\n"
"YsEZzePF2TU//V1WvMfnDzQSjKlHsGEh4gaFROB1DonrO5/zSrGcTqH8eEGKUMeN\n"
"/yb3dsdsKaOBuTCBtjAdBgNVHQ4EFgQUJ3VMh19TxUy7+Hj6OtvBVO4L1VEwHwYD\n"
"VR0jBBgwFoAUFHxMJ2mAvB7OJ3RYuUspH4fqZZ4wNQYJYIZIAYb4QgENBCgWJkFs\n"
"d2F5cyBsb29rIG9uIHRoZSBicmlnaHQgc2lkZSBvZiBsaWZlMD0GCCsGAQUFBwEa\n"
"BDEWL2NhLnNoYWtlbi5zaWduYWx3aXJlLmNvbS9zdGktY2EvYWNtZS9UTkF1dGhM\n"
"aXN0MAoGCCqGSM49BAMCA0gAMEUCIHR+PsVso8HziaiVfMF7qu2s4+lkqJCaslbh\n"
"rLDq/fuDAiEAnomQXpKBGkGpT7KFjcqBwA6kbz14Hnlw8sn8gPSGKYA=\n"
"-----END CERTIFICATE-----";
int http_req_mocked;
int http_req_handled_from_cache;

#define PRINT_SHAKEN_ERROR_IF_SET \
	if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

/*
 * Mock HTTP transfers in this test.
 */
stir_shaken_status_t stir_shaken_make_http_req_mock(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	(void) ss;
	int certlen = strlen(sp_pem);

	printf("\n\nShakening surprise\n\n");
	stir_shaken_assert(http_req != NULL, "http_req is NULL!");

	printf("MOCK HTTP response code to 200 OK\n");
	http_req->response.code = 200;

	certlen = strlen(sp_pem);
	stir_shaken_assert(http_req->response.mem.mem = malloc(certlen + 1), "Malloc failed");
	memset(http_req->response.mem.mem, 0, certlen + 1);
	strncpy(http_req->response.mem.mem, sp_pem, certlen);
	http_req->response.mem.size = certlen + 1;

	http_req_mocked = 1;

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_test_callback(stir_shaken_callback_arg_t *arg)
{
	stir_shaken_assert(arg, "Callback argument missing");
	stir_shaken_assert(STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY == arg->action, "Wrong action");

	switch (arg->action) {

		case STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY:

			// Default behaviour for certificate fetch enquiry is to request downloading, but in some cases it would be useful to avoid that and use pre-cached certificate.
			// Here, we supply libstirshaken with certificate we cached earlier, avoiding HTTP(S) download.
			// We must return STIR_SHAKEN_STATUS_HANDLED to signal this to the library, otherwise it would execute HTTP(S) download

			printf("Supplying certificate from the cache...\n");

			stir_shaken_assert(!strcmp("http://shaken.signalwire.cloud/sp.pem", arg->cert.public_url), "Wrong cert location");
			stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_cert_copy(&ss, &arg->cert, &cert_cached), "Cannot copy certificate");

			http_req_handled_from_cache = 1;

			return STIR_SHAKEN_STATUS_HANDLED;

		default:
			return STIR_SHAKEN_STATUS_NOT_HANDLED;
	}

exit:
	return STIR_SHAKEN_STATUS_NOT_HANDLED;
}

stir_shaken_status_t stir_shaken_unit_test_verify(void)
{
	const char	*error_description = NULL;
	stir_shaken_context_t	ss = { 0 };
	stir_shaken_error_t		error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;


	char *passport_encoded = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNsb3VkL3NwLnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTYwMzQ1ODEzMSwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.G_6hnwPGAeUalviElXbxl4kKR5qenib6fRrCP-cgwKN2hMsSTXYjIFEhl_VqmeTB8dk9fidroDlFe8dPdyPy3g";
	stir_shaken_passport_t	passport = {0};
	stir_shaken_cert_t		*cert = NULL;
	int		iat_freshness_seconds = INT_MAX;
	char	*passport_decoded = NULL;
	jwt_t	*jwt = NULL;


	// Test 1: callback set to default, should perform download of the certificate
	ss.callback = stir_shaken_default_callback;
	status = stir_shaken_jwt_verify_and_check_x509_cert_path(&ss, passport_encoded, &cert, &jwt);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}
	stir_shaken_assert(http_req_mocked == 1, "HTTP request performed");
	stir_shaken_assert(http_req_handled_from_cache == 0, "HTTP request handled with cert from cache");
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Wrong status");
	stir_shaken_assert(!stir_shaken_is_error_set(&ss), "Error not set");

	stir_shaken_assert(stir_shaken_jwt_move_to_passport(NULL, jwt, &passport) == jwt, "JWT Move to PASSporT failed");
	jwt = NULL;

	printf("\nPASSporT Verified.\n\n");

	// Print PASSporT
	passport_decoded = stir_shaken_passport_dump_str(&ss, &passport, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	// Print the certificate
	if (STIR_SHAKEN_STATUS_OK == stir_shaken_read_cert_fields(&ss, cert)) {
		printf("Certificate is:\n");
		stir_shaken_print_cert_fields(stdout, cert);
	}

	// Cache it
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_cert_copy(&ss, &cert_cached, cert), "Cannot cache certificate!");

	stir_shaken_passport_destroy(&passport);
	stir_shaken_destroy_cert(cert);
	free(cert);
	cert = NULL;
	http_req_mocked = 0;

	// Test 2: callback set to custom function supplying certificates from cache
	ss.callback = stir_shaken_test_callback;
	status = stir_shaken_jwt_verify_and_check_x509_cert_path(&ss, passport_encoded, &cert, &jwt);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}
	stir_shaken_assert(http_req_mocked == 0, "HTTP request performed");
	stir_shaken_assert(http_req_handled_from_cache == 1, "HTTP request not handled with cert from cache");
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Wrong status");
	stir_shaken_assert(!stir_shaken_is_error_set(&ss), "Error not set");

	stir_shaken_assert(stir_shaken_jwt_move_to_passport(NULL, jwt, &passport) == jwt, "JWT Move to PASSporT failed");
	jwt = NULL;

	printf("\nPASSporT Verified.\n\n");

	// Print PASSporT
	passport_decoded = stir_shaken_passport_dump_str(&ss, &passport, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	// Print the certificate
	if (STIR_SHAKEN_STATUS_OK == stir_shaken_read_cert_fields(&ss, cert)) {
		printf("Certificate is:\n");
		stir_shaken_print_cert_fields(stdout, cert);
	}

	stir_shaken_passport_destroy(&passport);
	stir_shaken_destroy_cert(cert);
	free(cert);
	cert = NULL;
	stir_shaken_destroy_cert(&cert_cached);

	return STIR_SHAKEN_STATUS_OK;

fail:

	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}

	// Print PASSporT
	passport_decoded = stir_shaken_passport_dump_str(&ss, &passport, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	// Print the certificate
	if (STIR_SHAKEN_STATUS_OK == stir_shaken_read_cert_fields(&ss, cert)) {
		printf("Certificate is:\n");
		stir_shaken_print_cert_fields(stdout, cert);
	}

	stir_shaken_passport_destroy(&passport);
	stir_shaken_destroy_cert(cert);
	free(cert);
	cert = NULL;
	stir_shaken_do_deinit();

	return STIR_SHAKEN_STATUS_FALSE;
}

int main(int argc, char **argv)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_do_init(NULL, "test/ref/ca", NULL, STIR_SHAKEN_LOGLEVEL_HIGH), "Cannot init lib");

	if (argc == 1) {

        // MOCK http transfers by default
		printf("Mocking HTTP requests...\n");
        stir_shaken_make_http_req = stir_shaken_make_http_req_mock;

    } else if (argc > 1 && !stir_shaken_zstr(argv[1]) && !strcmp(argv[1], "nomock")) {

        // do not MOCK
		printf("Not mocking HTTP requests...\n");

    } else {
        printf("ERR: this program takes no argument or one argument which must be 'nomock'\n");
        exit(EXIT_FAILURE);
    }

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {

			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_verify() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
