#include <stir_shaken.h>


/**
 * This example demonstrates how to create simplest verification service (STI-SP/VS).
 * We are using here reference PASSporT (you can find it in test/ref/sp folder) we created with this command:
 *		./stirshaken passport-create --privkey test/ref/sp/sp.priv --url http://shaken.signalwire.com/sp.pem --vvv -f passport.txt
 * PASSporT is:
 * 
 * {
 *    "alg": "ES256",
 *    "ppt": "shaken",
 *    "typ": "passport",
 *    "x5u": "http://shaken.signalwire.com/sp.pem"
 * }
 * .
 * {
 *    "attest": "A",
 *    "dest": "{\"tn\":\"01256500600\"}",
 *    "iat": 1599258938,
 *    "orig": "{\"tn\":\"01256789999\"}",
 *    "origid": "ref"
 * }
 * 
 * PASSporT encoded (signed) is:
 * eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNvbS9zcC5wZW0ifQ.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTU5OTI1ODkzOCwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.p_lhqTk-zBBNcsZgv5gNmO63xrbvapMwZmqmN2NwfbiJB2VxBait5EeUxgDpFs30EC7r4cm8tQD8CV2gFkFEtw
 * 
 * SIP Identity Header is:
 * eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNvbS9zcC5wZW0ifQ.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTU5OTI1ODkzOCwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.URaXwA1TcXJtqfbGKT_FH14y8KgCGM4mrJW8ApdEb2bhstrErjDMSEY1llsAV_zxcWpyIf5hUIk_XI4WpkVACw;info=<http://shaken.signalwire.com/sp.pem>;alg=ES256;ppt=shaken
 **/

int main(void)
{
	const char	*error_description = NULL;
	stir_shaken_context_t	ss = { 0 };
	stir_shaken_error_t		error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;

	char *passport_encoded = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNvbS9zcC5wZW0ifQ.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTU5OTI1ODkzOCwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.p_lhqTk-zBBNcsZgv5gNmO63xrbvapMwZmqmN2NwfbiJB2VxBait5EeUxgDpFs30EC7r4cm8tQD8CV2gFkFEtw";

	char *sip_identity_header = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL3NoYWtlbi5zaWduYWx3aXJlLmNvbS9zcC5wZW0ifQ.eyJhdHRlc3QiOiJBIiwiZGVzdCI6IntcInRuXCI6XCIwMTI1NjUwMDYwMFwifSIsImlhdCI6MTU5OTI1ODkzOCwib3JpZyI6IntcInRuXCI6XCIwMTI1Njc4OTk5OVwifSIsIm9yaWdpZCI6InJlZiJ9.URaXwA1TcXJtqfbGKT_FH14y8KgCGM4mrJW8ApdEb2bhstrErjDMSEY1llsAV_zxcWpyIf5hUIk_XI4WpkVACw;info=<http://shaken.signalwire.com/sp.pem>;alg=ES256;ppt=shaken";

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

	return 0;
}
