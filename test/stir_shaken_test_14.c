#include <stir_shaken.h>

const char *path = "./test/run";

#define CA_DIR	"./test/run/ca"
#define CRL_DIR	"./test/run/crl"

stir_shaken_ca_t ca;
stir_shaken_sp_t sp;
stir_shaken_cert_t		cert_cached;
stir_shaken_context_t	ss;

#define PRINT_SHAKEN_ERROR_IF_SET \
	if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

stir_shaken_status_t stir_shaken_test_callback(stir_shaken_callback_arg_t *arg)
{
	if (!arg) return STIR_SHAKEN_STATUS_TERM;

	switch (arg->action) {

		case STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY:
			// Default behaviour for certificate fetch enquiry is to request downloading, but in some cases it would be useful to avoid that and use pre-cached certificate.
			// Here, we supply libstirshaken with certificate we cached earlier, avoiding HTTP(S) download.
			// We must return STIR_SHAKEN_STATUS_HANDLED to signal this to the library, otherwise it would execute HTTP(S) download
			printf("Supplying certificate from the cache...");
			stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_cert_copy(&ss, &arg->cert, &cert_cached), "Cannot copy certificate");
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

	char *passport_encoded = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNvbS9zcC5wZW0ifQ.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTU5OTI1ODkzOCwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.p_lhqTk-zBBNcsZgv5gNmO63xrbvapMwZmqmN2NwfbiJB2VxBait5EeUxgDpFs30EC7r4cm8tQD8CV2gFkFEtw";

	stir_shaken_passport_t	passport = {0};
	stir_shaken_cert_t		*cert = NULL;
	int		iat_freshness_seconds = INT_MAX;
	char	*passport_decoded = NULL;
	jwt_t	*jwt = NULL;


	// Test 1: callback not set, should return error STIR_SHAKEN_ERROR_CERT_FETCH_OR_DOWNLOAD
	status = stir_shaken_jwt_verify(&ss, passport_encoded, &cert, &jwt);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_FALSE, "Wrong status");
	stir_shaken_assert(stir_shaken_is_error_set(&ss), "Error not set");
	stir_shaken_assert(stir_shaken_get_error(&ss, &error_code) && error_code == STIR_SHAKEN_ERROR_CERT_FETCH_OR_DOWNLOAD, "Wrong error code");
	
	// Test 2: callback set to default, should perform download of the certificate
	ss.callback = stir_shaken_default_callback;
	status = stir_shaken_jwt_verify(&ss, passport_encoded, &cert, &jwt);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Wrong status");
	stir_shaken_assert(!stir_shaken_is_error_set(&ss), "Error not set");

	stir_shaken_jwt_move_to_passport(jwt, &passport);
	jwt = NULL;

	printf("\nPASSporT Verified.\n\n");

	// Print PASSporT
	passport_decoded = stir_shaken_passport_dump_str(&passport, 1);
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

	// Test 3: callback set to custom function supplying certificates from cache
	ss.callback = stir_shaken_test_callback;
	status = stir_shaken_jwt_verify(&ss, passport_encoded, &cert, &jwt);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Wrong status");
	stir_shaken_assert(!stir_shaken_is_error_set(&ss), "Error not set");

	stir_shaken_jwt_move_to_passport(jwt, &passport);
	jwt = NULL;

	printf("\nPASSporT Verified.\n\n");

	// Print PASSporT
	passport_decoded = stir_shaken_passport_dump_str(&passport, 1);
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
	passport_decoded = stir_shaken_passport_dump_str(&passport, 1);
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

int main(void)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_do_init(NULL, CA_DIR, CRL_DIR, STIR_SHAKEN_LOGLEVEL_HIGH), "Cannot init lib");

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
