#include <stir_shaken.h>


/**
 * This example demonstrates how to create simplest verification service (STI-SP/VS).
 * We are using here reference PASSporT (you can find it in test/ref/sp folder) we created with this command:
 *		./stirshaken passport-create --privkey test/ref/sp/sp.priv --url http://shaken.signalwire.cloud/sp.pem --vvv -f passport.txt
 *
 * PASSporT is:
 *
 * {
 *     "alg": "ES256",
 *     "ppt": "shaken",
 *     "typ": "passport",
 *     "x5u": "http://shaken.signalwire.cloud/sp.pem"
 * }
 * .
 * {
 *     "attest": "A",
 *     "dest": "{\"tn\":\"01256500600\"}",
 *     "iat": 1603458131,
 *     "orig": "{\"tn\":\"01256789999\"}",
 *     "origid": "ref"
 * }
 *
 * PASSporT signed is:
 * eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNsb3VkL3NwLnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTYwMzQ1ODEzMSwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.G_6hnwPGAeUalviElXbxl4kKR5qenib6fRrCP-cgwKN2hMsSTXYjIFEhl_VqmeTB8dk9fidroDlFe8dPdyPy3g
 *
 * SIP Identity Header with PASSporT is:
 * eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNsb3VkL3NwLnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTYwMzQ1ODEzMSwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.cNI-uIirMOiT19OcQag2UYjHWTgTqtr5jhSk3KxflqSC7FbrrYDr51zCEvzDMoETpge7eQeQ6ASVzb1dhVVhKQ;info=<http://shaken.signalwire.cloud/sp.pem>;alg=ES256;ppt=shaken
 **/

stir_shaken_status_t cache_callback(stir_shaken_callback_arg_t *arg)
{
	stir_shaken_context_t	ss = { 0 };
	const char				*error_description = NULL;
	stir_shaken_error_t		error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_cert_t		cache_copy = { 0 };

	switch (arg->action) {

		case STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY:

			// Default behaviour for certificate fetch enquiry is to request downloading, but in some cases it would be useful to avoid that and use pre-cached certificate.
			// Here, we supply libstirshaken with certificate we cached earlier, avoiding HTTP(S) download.
			// We must return STIR_SHAKEN_STATUS_HANDLED to signal this to the library, otherwise it would execute HTTP(S) download

			if (!strcmp("http://shaken.signalwire.cloud/sp.pem", arg->cert.public_url)) {

				printf("Supplying certificate from the cache: %s...\n", arg->cert.public_url);

				if (!(cache_copy.x = stir_shaken_load_x509_from_file(&ss, "examples/cache/sp.pem"))) {
					printf("Cannot load X509 from file\n");
					goto exit;
				}

				if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_copy(&ss, &arg->cert, &cache_copy)) {
					printf("Cannot copy certificate\n");
					goto exit;
				}

				stir_shaken_destroy_cert(&cache_copy);

				return STIR_SHAKEN_STATUS_HANDLED;
			}

		default:
			return STIR_SHAKEN_STATUS_NOT_HANDLED;
	}

exit:

	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}

	return STIR_SHAKEN_STATUS_NOT_HANDLED;
}

void run_verification_service(stir_shaken_callback_t callback)
{
	const char	*error_description = NULL;
	stir_shaken_context_t	ss = { .callback = callback};
	stir_shaken_error_t		error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;

	char *passport_encoded = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNsb3VkL3NwLnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTYwMzQ1ODEzMSwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.cNI-uIirMOiT19OcQag2UYjHWTgTqtr5jhSk3KxflqSC7FbrrYDr51zCEvzDMoETpge7eQeQ6ASVzb1dhVVhKQ;info=<http://shaken.signalwire.cloud/sp.pem>;alg=ES256;ppt=shaken";
	char *sip_identity_header = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNsb3VkL3NwLnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTYwMzQ1ODEzMSwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.cNI-uIirMOiT19OcQag2UYjHWTgTqtr5jhSk3KxflqSC7FbrrYDr51zCEvzDMoETpge7eQeQ6ASVzb1dhVVhKQ;info=<http://shaken.signalwire.cloud/sp.pem>;alg=ES256;ppt=shaken";
	stir_shaken_passport_t	passport = {0};
	stir_shaken_cert_t		*cert = NULL;
	int		iat_freshness_seconds = INT_MAX;
	char	*passport_decoded = NULL;
	jwt_t	*jwt = NULL;


	status = stir_shaken_do_init(&ss, "examples/ca", "examples/crl", STIR_SHAKEN_LOGLEVEL_HIGH);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("Cannot init lib\n");
		goto exit;
	}

	// For pure Shaken we would have PASSporT as a JWT
	status = stir_shaken_jwt_verify_and_check_x509_cert_path(&ss, passport_encoded, &cert, &jwt);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("PASSporT failed verification\n");
		goto exit;
	}

	printf("\nPASSporT Verified.\n\n");

	// Print PASSporT
	if (!stir_shaken_jwt_move_to_passport(&ss, jwt, &passport)) {
		printf("Cannot assign JWT to PASSporT\n");
		goto exit;
	}
	jwt = NULL;

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

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	status = stir_shaken_sih_verify(&ss, sip_identity_header, &passport, &cert, iat_freshness_seconds);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("SIP Identity Header failed verification\n");
		goto exit;
	}

	printf("\nSIP Identity Header verified.\n\n");


exit:

	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}

	if (passport_encoded) {

		// Print PASSporT
		passport_decoded = stir_shaken_passport_dump_str(&ss, &passport, 1);
		if (passport_decoded) {
			printf("PASSporT is:\n%s\n", passport_decoded);
			stir_shaken_free_jwt_str(passport_decoded);
			passport_decoded = NULL;
		}
	}

	if (cert) {

		// Print the Certificate
		if (STIR_SHAKEN_STATUS_OK == stir_shaken_read_cert_fields(&ss, cert)) {
			printf("Certificate is:\n");
			stir_shaken_print_cert_fields(stdout, cert);
		}
	}

	stir_shaken_passport_destroy(&passport);
	stir_shaken_destroy_cert(cert);
	free(cert);
	cert = NULL;
	stir_shaken_do_deinit();

	if (jwt) {
		jwt_free(jwt);
		jwt = NULL;
	}
}

int main(void)
{
	run_verification_service(NULL);
	run_verification_service(cache_callback);
	return 0;
}
