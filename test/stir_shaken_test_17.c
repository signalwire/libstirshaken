#include <stir_shaken.h>

const char *path = "./test/run";

#define CA_DIR	"./test/run/ca"
#define CRL_DIR	"./test/run/crl"
#define CACHE_DIR "./test/run/cache"

stir_shaken_ca_t ca;
stir_shaken_sp_t sp;
stir_shaken_context_t ss;
int cache_callback_called;
int http_req_mocked;

#define PRINT_SHAKEN_ERROR_IF_SET \
	if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

stir_shaken_status_t cache_callback(stir_shaken_context_t *ss)
{
	stir_shaken_callback_arg_t *arg = NULL;
	const char				*error_description = NULL;
	stir_shaken_error_t		error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_cert_t		cache_copy = { 0 };

	stir_shaken_assert(ss->user_data = &cache_callback_called, "Pointer to user data invalid");
	(*((int*)(ss->user_data)))++;

	arg = &ss->callback_arg;

	switch (arg->action) {

		case STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY:

			// Default behaviour for certificate fetch enquiry is to request downloading, but in some cases it would be useful to avoid that and use pre-cached certificate.
			// Here, we supply libstirshaken with certificate we cached earlier, avoiding HTTP(S) download.
			// We must return STIR_SHAKEN_STATUS_ACTION_HANDLED to signal this to the library, otherwise it would execute HTTP(S) download

			if (!strcmp("https://sp.com/sp.pem", arg->cert.public_url)) {

				printf("Supplying certificate from the cache: %s...\n", arg->cert.public_url);

				if (!(cache_copy.x = stir_shaken_load_x509_from_file(ss, sp.cert_name))) {
					printf("Cannot load X509 from file\n");
					goto exit;
				}

				if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_copy(ss, &arg->cert, &cache_copy)) {
					printf("Cannot copy certificate\n");
					goto exit;
				}

				stir_shaken_cert_deinit(&cache_copy);

				return STIR_SHAKEN_STATUS_ACTION_HANDLED;
			}

		case STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCHED:

			printf("Callback's action STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCHED not handled...\n");
			return STIR_SHAKEN_STATUS_ACTION_NOT_HANDLED;

		default:
			return STIR_SHAKEN_STATUS_ACTION_NOT_HANDLED;
	}

exit:

	if (stir_shaken_is_error_set(ss)) {
		error_description = stir_shaken_get_error(ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}

	return STIR_SHAKEN_STATUS_ACTION_ERROR;
}

/*
 * Mock HTTP transfers in this test.
 */
stir_shaken_status_t stir_shaken_make_http_req_mock(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	unsigned char raw[STIR_SHAKEN_BUFLEN] = { 0 };
	int raw_len = STIR_SHAKEN_BUFLEN;

	printf("\n\nShakening surprise\n\n");
	stir_shaken_assert(http_req != NULL, "http_req is NULL!");

	printf("MOCK HTTP response code to 200 OK\n");
	http_req->response.code = 200;

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_get_x509_raw(ss, sp.cert.x, raw, &raw_len), "Failed to read cert from X509 to PEM");

	stir_shaken_assert(http_req->response.mem.mem = malloc(raw_len + 1), "Malloc failed");
	memset(http_req->response.mem.mem, 0, raw_len + 1);

	memcpy(http_req->response.mem.mem, raw, raw_len);
	http_req->response.mem.size = raw_len + 1;

	http_req_mocked = 1;

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_unit_test_vs_verify(void)
{
	EVP_PKEY *pkey = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	unsigned long hash = 0;
	char hashstr[100] = { 0 };
	int hashstrlen = 100;
	uint32_t iat = 0, iat_freshness_seconds = 60;
	unsigned long connect_timeout_s = 3;

	stir_shaken_passport_params_t params = {
		.x5u = "https://sp.com/sp.pem",
		.attest = "A",
		.desttn_key = "tn",
		.desttn_val = "01256500600",
		.iat = iat = time(NULL) + 120,
		.origtn_key = "tn",
		.origtn_val = "01256789999",
		.origid = "ref"
	};
	stir_shaken_passport_t *passport = NULL, *passport_2 = NULL, *passport_out = NULL;
	char *passport_encoded = NULL, *passport_decoded = NULL, *sip_identity_header = NULL;
	stir_shaken_cert_t *cert_out = NULL;
	jwt_t *jwt_out = NULL;

	stir_shaken_as_t *as = NULL;
	stir_shaken_vs_t *vs = NULL;


	sprintf(ca.private_key_name, "%s%c%s", path, '/', "17_ca_private_key.pem");
	sprintf(ca.public_key_name, "%s%c%s", path, '/', "17_ca_public_key.pem");
	sprintf(ca.cert_name, "%s%c%s", path, '/', "17_ca_cert.crt");

	sprintf(sp.private_key_name, "%s%c%s", path, '/', "17_sp_private_key.pem");
	sprintf(sp.public_key_name, "%s%c%s", path, '/', "17_sp_public_key.pem");
	sprintf(sp.csr_name, "%s%c%s", path, '/', "17_sp_csr.pem");
	sprintf(sp.cert_name, "%s%c%s", path, '/', "17_sp_cert.crt");

	printf("=== Unit testing: STIR/Shaken VS [stir_shaken_unit_test_vs_verify]\n\n");

	printf("CA: Generate CA keys\n");

	ca.keys.priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	status = stir_shaken_generate_keys(&ss, &ca.keys.ec_key, &ca.keys.private_key, &ca.keys.public_key, ca.private_key_name, ca.public_key_name, ca.keys.priv_raw, &ca.keys.priv_raw_len);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(ca.keys.ec_key != NULL, "Err, failed to generate EC key");
	stir_shaken_assert(ca.keys.private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(ca.keys.public_key != NULL, "Err, failed to generate public key");

	printf("SP: Generate SP keys\n");

	sp.keys.priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	status = stir_shaken_generate_keys(&ss, &sp.keys.ec_key, &sp.keys.private_key, &sp.keys.public_key, sp.private_key_name, sp.public_key_name, sp.keys.priv_raw, &sp.keys.priv_raw_len);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(sp.keys.ec_key != NULL, "Err, failed to generate EC key\n\n");
	stir_shaken_assert(sp.keys.private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(sp.keys.public_key != NULL, "Err, failed to generate public key");

	printf("SP: Create CSR\n");
	sp.code = 1;
	snprintf(sp.subject_c, STIR_SHAKEN_BUFLEN, "US");
	snprintf(sp.subject_cn, STIR_SHAKEN_BUFLEN, "NewSTI-SP, But Absolutely Fine Inc.");

	status = stir_shaken_generate_csr(&ss, sp.code, &sp.csr.req, sp.keys.private_key, sp.keys.public_key, sp.subject_c, sp.subject_cn);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");

	printf("CA: Create self-signed CA Certificate\n");

	snprintf(ca.issuer_c, STIR_SHAKEN_BUFLEN, "US");
	snprintf(ca.issuer_cn, STIR_SHAKEN_BUFLEN, "SignalWire Secure");
	ca.serial = 1;
	ca.expiry_days = 90;
	ca.cert.x = stir_shaken_generate_x509_self_signed_ca_cert(&ss, ca.keys.private_key, ca.keys.public_key, ca.issuer_c, ca.issuer_cn, ca.serial, ca.expiry_days);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(ca.cert.x, "Err, generating CA cert");

	printf("CA: Create end-entity SP Certificate from SP's CSR\n");
	snprintf(ca.tn_auth_list_uri, STIR_SHAKEN_BUFLEN, "http://ca.com/api");
	//sp.cert.x = stir_shaken_generate_x509_cert_from_csr(&ss, sp.code, sp.csr.req, ca.keys.private_key, ca.issuer_c, ca.issuer_cn, sp.serial, sp.expiry_days);
	pkey = X509_REQ_get_pubkey(sp.csr.req);
	stir_shaken_assert(1 == EVP_PKEY_cmp(pkey, sp.keys.public_key), "Public key in CSR different than SP's");
	//sp.cert.x = stir_shaken_generate_x509_end_entity_cert(&ss, ca.cert.x, ca.keys.private_key, sp.keys.public_key, ca.issuer_c, ca.issuer_cn, sp.subject_c, sp.subject_cn, ca.serial_sp, ca.expiry_days_sp, ca.number_start_sp, ca.number_end_sp);
	sp.cert.x = stir_shaken_generate_x509_end_entity_cert_from_csr(&ss, ca.cert.x, ca.keys.private_key, ca.issuer_c, ca.issuer_cn, sp.csr.req, ca.serial, ca.expiry_days, ca.tn_auth_list_uri);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(sp.cert.x != NULL, "Err, generating Cert");

	// SAVE CSR and certificates

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_csr_to_disk(&ss, sp.csr.req, sp.csr_name), "Failed to write CSR to disk");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_x509_to_disk(&ss, ca.cert.x, ca.cert_name), "Failed to write CA certificate to disk");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_x509_to_disk(&ss, sp.cert.x, sp.cert_name), "Failed to write SP certificate to disk");

	// Create PASSporT to test using AS interface
	stir_shaken_assert(as = stir_shaken_as_create(&ss), "Failed to create Authentication Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_as_load_private_key(&ss, as, sp.private_key_name), "Failed to load private key");
	stir_shaken_assert(passport_encoded = stir_shaken_as_authenticate_to_passport(&ss, as, &params, &passport), "PASSporT has not been created");
	stir_shaken_assert(sip_identity_header = stir_shaken_as_authenticate_to_sih(&ss, as, &params, &passport_2), "SIP Identity Header has not been created");
	stir_shaken_assert(passport, "PASSporT not returned");
	stir_shaken_assert(passport_2, "PASSporT not returned");

	printf("\n1. PASSporT encoded:\n%s\n", passport_encoded);

	/* Test prereqs */

	// Add CA cert to CA dir, as trusted anchor
	// Must be in hash.N form for X509_verify_cert to recognize it
	stir_shaken_assert(hash = stir_shaken_get_cert_name_hashed(&ss, ca.cert.x), "Failed to get CA cert name hashed");
	printf("CA name hash is %lu\n", hash);
	stir_shaken_cert_name_hashed_2_string(hash, hashstr, hashstrlen);
	sprintf(ca.cert_name_hashed, "./test/run/ca/%s.0", hashstr);
	printf("Adding CA cert to CA dir as %s\n\n", ca.cert_name_hashed);
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(&ss, ca.cert.x, ca.cert_name_hashed)) { // "Failed to write CA certificate to CA dir");
		PRINT_SHAKEN_ERROR_IF_SET
	}
	cache_callback_called = 0;

	/*
	 * 1. Test with:
	 *
	 *	- callback - OFF
	 *	- X509 - OFF
	 *	- default cert caching - OFF
	*/

	printf("\n=== Test 1. Callback: OFF, X509: OFF, default cert caching: OFF\n\n");

	memset(&ss, 0, sizeof(ss));
	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	/*
	 * 2. Test with:
	 *
	 *	- callback - OFF
	 *	- X509 - OFF
	 *	- default cert caching - ON
	*/

	/* 2.1 First, without cert cached yet (lib should cache it) */

	printf("\n=== Test 2. Callback: OFF, X509: OFF, default cert caching: ON\n");

	printf("\n=== Test 2.1 Callback: OFF, X509: OFF, default cert caching: ON (without cert cached yet, lib should cache it)\n\n");

	if (stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	}
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");


	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Failed to set default cert caching");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.cert_saved_in_cache == 1, "Cert saved in cache should be set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be mocked");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;
	
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.cert_saved_in_cache == 1, "Cert saved in cache should be set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be mocked");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.cert_saved_in_cache == 1, "Cert saved in cache should be set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be mocked");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;
	
	/* 2.2 Second, with cert already cached (lib has cached it) */

	printf("\n=== Test 2.2 Callback: OFF, X509: OFF, default cert caching: ON (with cert already cached, lib has cached it)\n\n");

	stir_shaken_assert(stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Cache dir doesn't exist");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Failed to set default cert caching");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(ss.cert_saved_in_cache == 0, "Cert saved in cache should not be set"); // if it's fetched from cache is never saved in cache (by default cert caching implementation)
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(ss.cert_saved_in_cache == 0, "Cert saved in cache should not be set"); // if it's fetched from cache is never saved in cache (by default cert caching implementation)
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(ss.cert_saved_in_cache == 0, "Cert saved in cache should not be set"); // if it's fetched from cache is never saved in cache (by default cert caching implementation)
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;
	http_req_mocked = 0;

	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");

	/*
	 * 3. Test with:
	 *
	 *	- callback - OFF
	 *	- X509 - ON
	 *	- default cert caching - OFF
	*/

	printf("\n=== Test 3. Callback: OFF, X509: ON, default cert caching: OFF\n\n");

	if (stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	}
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_x509_cert_path_check(&ss, vs, 1), "Failed to turn on x509 cert path check");

	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	
	/*
	 * 4. Test with:
	 *
	 *	- callback - OFF
	 *	- X509 - ON
	 *	- default cert caching - ON
	*/

	/* 4.1 First, without cert cached yet (lib should cache it) */

	printf("\n=== Test 4. Callback: OFF, X509: OFF, default cert caching: ON\n");

	printf("\n=== Test 4.1 Callback: OFF, X509: ON, default cert caching: ON (without cert cached yet, lib should cache it)\n\n");

	if (stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	}
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");


	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_x509_cert_path_check(&ss, vs, 1), "Failed to turn on x509 cert path check");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Failed to set default cert caching");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.cert_saved_in_cache == 1, "Cert saved in cache should be set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be mocked");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;
	
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.cert_saved_in_cache == 1, "Cert saved in cache should be set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be mocked");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 0, "Cert fetched from cache should be not set");
	stir_shaken_assert(ss.cert_saved_in_cache == 1, "Cert saved in cache should be set");
	stir_shaken_assert(http_req_mocked == 1, "HTTP GET should be mocked");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;
	
	/* 4.2 Second, with cert already cached (lib has cached it) */

	printf("\n=== Test 4.2 Callback: OFF, X509: ON, default cert caching: ON (with cert already cached, lib has cached it)\n\n");

	stir_shaken_assert(stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Cache dir doesn't exist");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_x509_cert_path_check(&ss, vs, 1), "Failed to turn on x509 cert path check");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Failed to set default cert caching");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(ss.cert_saved_in_cache == 0, "Cert saved in cache should not be set"); // if it's fetched from cache is never saved in cache (by default cert caching implementation)
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(ss.cert_saved_in_cache == 0, "Cert saved in cache should not be set"); // if it's fetched from cache is never saved in cache (by default cert caching implementation)
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 0, "Cache callback called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(ss.cert_saved_in_cache == 0, "Cert saved in cache should not be set"); // if it's fetched from cache is never saved in cache (by default cert caching implementation)
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;
	http_req_mocked = 0;

	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");

	/*
	 * Test with:
	 *
	 *	- callback - ON
	 *	- X509 - OFF
	 *	- default cert caching - OFF
	*/

	printf("\n=== Test 5. Callback: ON, X509: OFF, default cert caching: OFF\n\n");

	if (stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	}
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	//stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback(&ss, vs, cache_callback), "Failed to set cache callback");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback_user_data(&ss, vs, &cache_callback_called), "Failed to set cache callback user data");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 2, "Cache callback not called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 2, "Cache callback not called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 2, "Cache callback not called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 0, "X509 cert path check should have not been executed");
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	/*
	 * 6. Test with:
	 *
	 *	- callback - ON
	 *	- X509 - OFF
	 *	- default cert caching - ON
	*/

	/* 6.1 Attempt to set callback when default cert caching is already on  */

	printf("\n=== Test 6.1 Callback: ON, X509: OFF, default cert caching: ON - INVALID SETTING\n");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Failed to set default cert caching");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");
	stir_shaken_assert(STIR_SHAKEN_STATUS_FALSE == stir_shaken_vs_set_callback(&ss, vs, cache_callback), "Should fail to set cache callback");
	stir_shaken_assert(STIR_SHAKEN_STATUS_FALSE == stir_shaken_vs_set_callback_user_data(&ss, vs, &cache_callback_called), "Should fail to set cache callback user data");

	memset(&ss, 0, sizeof(ss));
	stir_shaken_vs_destroy(&vs);

	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	
	/* 6.2 Other way around */

	printf("\n=== Test 6.2 Callback: ON, X509: OFF, default cert caching: ON - INVALID SETTING\n\n");

	stir_shaken_assert(stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Cache dir doesn't exist");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback(&ss, vs, cache_callback), "Should fail to set cache callback");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback_user_data(&ss, vs, &cache_callback_called), "Should fail to set cache callback user data");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");
	stir_shaken_assert(STIR_SHAKEN_STATUS_FALSE == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Should fail to set default cert caching");

	memset(&ss, 0, sizeof(ss));
	stir_shaken_vs_destroy(&vs);

	/*
	 * Test with:
	 *
	 *	- callback - ON
	 *	- X509 - ON
	 *	- default cert caching - ON
	*/

	printf("\n=== Test 7. Callback: ON, X509: ON, default cert caching: OFF\n\n");

	if (stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	}
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback(&ss, vs, cache_callback), "Failed to set cache callback");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback_user_data(&ss, vs, &cache_callback_called), "Failed to set cache callback user data");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_x509_cert_path_check(&ss, vs, 1), "Failed to turn on x509 cert path check");

	// For pure Shaken we would have PASSporT
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_to_jwt_verify(&ss, vs, passport_encoded, &cert_out, &jwt_out), "PASSporT verification failed");
	stir_shaken_assert(jwt_out, "jwt not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 2, "Cache callback not called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_cert_destroy(&cert_out);
	jwt_free(jwt_out);
	jwt_out = NULL;
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_passport_verify(&ss, vs, passport_encoded, &cert_out, &passport_out), "PASSporT verification failed");
	stir_shaken_assert(passport_out, "PASSporT not returned");
	stir_shaken_assert(cert_out, "Cert not returned");
	stir_shaken_assert(cache_callback_called == 2, "Cache callback not called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	printf("\nPASSporT Verified.\n");
	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	// For Shaken over SIP we would have PASSporT wrapped into SIP Identity Header
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_sih_verify(&ss, vs, sip_identity_header, &cert_out, &passport_out), "SIP Identity Header failed verification\n");

	printf("\nSIP Identity Header verified.\n\n");

	passport_decoded = stir_shaken_passport_dump_str(&ss, passport_out, 1);
	if (passport_decoded) {
		printf("PASSporT is:\n%s\n", passport_decoded);
		stir_shaken_free_jwt_str(passport_decoded);
		passport_decoded = NULL;
	}
	stir_shaken_assert(cache_callback_called == 2, "Cache callback not called");
	stir_shaken_assert(ss.cert_fetched_from_cache == 1, "Cert fetched from cache should be set");
	stir_shaken_assert(http_req_mocked == 0, "HTTP GET should not be executed");
	stir_shaken_assert(ss.x509_cert_path_checked == 1, "X509 cert path check should have been executed");
	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_cert_destroy(&cert_out);
	stir_shaken_vs_destroy(&vs);
	http_req_mocked = 0;
	memset(&ss, 0, sizeof(ss));
	cache_callback_called = 0;

	/*
	 * 8. Test with:
	 *
	 *	- callback - ON
	 *	- X509 - ON
	 *	- default cert caching - ON
	*/

	/* 8.1 Attempt to set callback when default cert caching is already on  */

	printf("\n=== Test 8.1 Callback: ON, X509: ON, default cert caching: ON - INVALID SETTING\n");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_x509_cert_path_check(&ss, vs, 1), "Failed to turn on x509 cert path check");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Failed to set default cert caching");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");
	stir_shaken_assert(STIR_SHAKEN_STATUS_FALSE == stir_shaken_vs_set_callback(&ss, vs, cache_callback), "Should fail to set cache callback");
	stir_shaken_assert(STIR_SHAKEN_STATUS_FALSE == stir_shaken_vs_set_callback_user_data(&ss, vs, &cache_callback_called), "Should fail to set cache callback user data");

	memset(&ss, 0, sizeof(ss));
	stir_shaken_vs_destroy(&vs);

	stir_shaken_assert(stir_shaken_dir_remove(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to remove cache dir");
	stir_shaken_assert(stir_shaken_dir_create(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Failed to create cache dir");

	
	/* 8.2 Other way around */

	printf("\n=== Test 8.2 Callback: ON, X509: OFF, default cert caching: ON - INVALID SETTING\n\n");

	stir_shaken_assert(stir_shaken_dir_exists(CACHE_DIR) == STIR_SHAKEN_STATUS_OK, "Cache dir doesn't exist");

	stir_shaken_assert(vs = stir_shaken_vs_create(&ss), "Cannot create Verification Service\n");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_load_ca_dir(&ss, vs, CA_DIR), "Failed to init X509 cert store");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_x509_cert_path_check(&ss, vs, 1), "Failed to turn on x509 cert path check");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback(&ss, vs, cache_callback), "Should fail to set cache callback");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_callback_user_data(&ss, vs, &cache_callback_called), "Should fail to set cache callback user data");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_connect_timeout(&ss, vs, connect_timeout_s), "Failed to set connect timeout");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_dir(&ss, vs, CACHE_DIR), "Failed to set cache dir");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_vs_set_cache_expire_seconds(&ss, vs, 60), "Failed to set cache expire seconds");
	stir_shaken_assert(STIR_SHAKEN_STATUS_FALSE == stir_shaken_vs_set_default_cert_caching(&ss, vs, 1), "Should fail to set default cert caching");

	memset(&ss, 0, sizeof(ss));
	stir_shaken_vs_destroy(&vs);

	// CA cleanup	
	stir_shaken_cert_deinit(&ca.cert);
	stir_shaken_destroy_keys_ex(&ca.keys.ec_key, &ca.keys.private_key, &ca.keys.public_key);

	// SP cleanup	
	stir_shaken_sp_destroy(&sp);

	if (pkey) EVP_PKEY_free(pkey);
	if (passport_encoded) free(passport_encoded);
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_passport_destroy(&passport);
	stir_shaken_passport_destroy(&passport_2);
	stir_shaken_cert_destroy(&cert_out);
	if (jwt_out) {
		jwt_free(jwt_out);
	}
	if (sip_identity_header) {
		free(sip_identity_header);
		sip_identity_header = NULL;
	}
	stir_shaken_as_destroy(&as);
	stir_shaken_vs_destroy(&vs);

	return STIR_SHAKEN_STATUS_OK;

fail:

	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}

	// CA cleanup	
	stir_shaken_cert_deinit(&ca.cert);
	stir_shaken_destroy_keys_ex(&ca.keys.ec_key, &ca.keys.private_key, &ca.keys.public_key);

	// SP cleanup	
	stir_shaken_sp_destroy(&sp);

	if (pkey) EVP_PKEY_free(pkey);
	if (passport_encoded) free(passport_encoded);
	stir_shaken_passport_destroy(&passport_out);
	stir_shaken_passport_destroy(&passport);
	stir_shaken_passport_destroy(&passport_2);
	stir_shaken_cert_destroy(&cert_out);
	if (jwt_out) {
		jwt_free(jwt_out);
	}
	if (sip_identity_header) {
		free(sip_identity_header);
		sip_identity_header = NULL;
	}
	stir_shaken_as_destroy(&as);
	stir_shaken_vs_destroy(&vs);

	return STIR_SHAKEN_STATUS_FALSE;
}

int main(void)
{
	if (stir_shaken_dir_exists(CA_DIR) != STIR_SHAKEN_STATUS_OK) {
		if (stir_shaken_dir_create_recursive(CA_DIR) != STIR_SHAKEN_STATUS_OK) {
			printf("ERR: Cannot create test CA dir\n");
			return -1;
		}
	}

	if (stir_shaken_dir_exists(CRL_DIR) != STIR_SHAKEN_STATUS_OK) {
		if (stir_shaken_dir_create_recursive(CRL_DIR) != STIR_SHAKEN_STATUS_OK) {
			printf("ERR: Cannot create test CRL dir\n");
			return -1;
		}
	}

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_init(&ss, STIR_SHAKEN_LOGLEVEL_HIGH), "Cannot init lib");

	// MOCK http transfers
	printf("Mocking HTTP requests...\n");
	stir_shaken_make_http_req = stir_shaken_make_http_req_mock;

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {

			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_vs_verify() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_deinit();

	printf("OK\n");

	return 0;
}
