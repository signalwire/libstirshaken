#include "../include/stir_shaken.h"

const char *path = "./test/run";

#define CA_DIR	"./test/run/ca"
#define CRL_DIR	"./test/run/crl"

stir_shaken_ca_t ca;
stir_shaken_sp_t sp;

#define PRINT_SHAKEN_ERROR_IF_SET \
	if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

stir_shaken_status_t stir_shaken_unit_test_x509_cert_path_verification(void)
{
	EVP_PKEY *pkey = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	unsigned long hash = 0;
	char hashstr[100] = { 0 };
	int hashstrlen = 100;


	sprintf(ca.private_key_name, "%s%c%s", path, '/', "12_ca_private_key.pem");
	sprintf(ca.public_key_name, "%s%c%s", path, '/', "12_ca_public_key.pem");
	sprintf(ca.cert_name, "%s%c%s", path, '/', "12_ca_cert.crt");

	sprintf(sp.private_key_name, "%s%c%s", path, '/', "12_sp_private_key.pem");
	sprintf(sp.public_key_name, "%s%c%s", path, '/', "12_sp_public_key.pem");
	sprintf(sp.csr_name, "%s%c%s", path, '/', "12_sp_csr.pem");
	sprintf(sp.cert_name, "%s%c%s", path, '/', "12_sp_cert.crt");

	printf("=== Unit testing: STIR/Shaken X509 cert path verification [stir_shaken_unit_test_x509_cert_path_verification]\n\n");

	printf("CA: Generate CA keys\n");

	// Generate CA keys
	ca.keys.priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	status = stir_shaken_generate_keys(&ss, &ca.keys.ec_key, &ca.keys.private_key, &ca.keys.public_key, ca.private_key_name, ca.public_key_name, ca.keys.priv_raw, &ca.keys.priv_raw_len);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(ca.keys.ec_key != NULL, "Err, failed to generate EC key\n\n");
	stir_shaken_assert(ca.keys.private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(ca.keys.public_key != NULL, "Err, failed to generate public key");

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
	snprintf(sp.subject_c, STIR_SHAKEN_BUFLEN, "US");
	snprintf(sp.subject_cn, STIR_SHAKEN_BUFLEN, "NewSTI-SP, But Absolutely Fine Inc.");

	status = stir_shaken_generate_csr(&ss, sp.code, &sp.csr.req, sp.keys.private_key, sp.keys.public_key, sp.subject_c, sp.subject_cn);
	PRINT_SHAKEN_ERROR_IF_SET
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");

	// 2
	// CA creates self-signed cert

	printf("CA: Create self-signed CA Certificate\n");

	snprintf(ca.issuer_c, STIR_SHAKEN_BUFLEN, "US");
	snprintf(ca.issuer_cn, STIR_SHAKEN_BUFLEN, "SignalWire Secure");
	ca.serial = 1;
	ca.expiry_days = 90;
	ca.cert.x = stir_shaken_generate_x509_self_signed_ca_cert(&ss, ca.keys.private_key, ca.keys.public_key, ca.issuer_c, ca.issuer_cn, ca.serial, ca.expiry_days);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(ca.cert.x, "Err, generating CA cert");


	// 3
	// SP sends CSR to CA

	// 4
	// CA challanges SP with TNAuthList challenge

	// 5
	// SP responds with SPC token

	// 6
	// CA can generate cert for SP now
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

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_csr_to_disk(&ss, sp.csr.req, sp.csr_name)) {
		printf("STIR-Shaken: Failed to write CSR to disk\n");
		PRINT_SHAKEN_ERROR_IF_SET
			return STIR_SHAKEN_STATUS_TERM;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(&ss, ca.cert.x, ca.cert_name)) {
		printf("Failed to write CA certificate to disk\n");
		PRINT_SHAKEN_ERROR_IF_SET
			return STIR_SHAKEN_STATUS_TERM;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(&ss, sp.cert.x, sp.cert_name)) {
		printf("Failed to write SP certificate to disk\n");
		PRINT_SHAKEN_ERROR_IF_SET
			return STIR_SHAKEN_STATUS_TERM;
	}

	/* Test */
	printf("TEST: verifying end-entity + CA combo cert with X509 cert path verification...\n\n");

	printf("TEST 1: Checking if X509_verify_cert returns error for SP cert\n");
	status = stir_shaken_verify_cert(&ss, &sp.cert);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("X509 cert path verification correctly failed, no CA cert in CA dir yet...\n");
		PRINT_SHAKEN_ERROR_IF_SET
	}
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != status, "Error, status should NOT be OK");

	// Add CA cert to CA dir, as trusted anchor
	// Must be in hash.N form for X509_verify_cert to recognize it
	hash = stir_shaken_get_cert_name_hashed(&ss, ca.cert.x);
	if (hash == 0) {
		printf("Failed to get CA cert name hashed\n");
		PRINT_SHAKEN_ERROR_IF_SET
			return STIR_SHAKEN_STATUS_TERM;
	}
	printf("CA name hash is %lu\n", hash);

	stir_shaken_cert_name_hashed_2_string(hash, hashstr, hashstrlen);

	sprintf(ca.cert_name_hashed, "./test/run/ca/%s.0", hashstr);
	printf("Adding CA cert to CA dir as %s\n", ca.cert_name_hashed);

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(&ss, ca.cert.x, ca.cert_name_hashed)) {
		printf("Failed to write CA certificate to CA dir\n");
		PRINT_SHAKEN_ERROR_IF_SET
			return STIR_SHAKEN_STATUS_TERM;
	}

	printf("Reinitialising X509 cert store...\n");
	// Must reinitialize now X509 cert store
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_init_cert_store(&ss, NULL, CA_DIR, NULL, NULL)) {
		printf("Failed to re-init CA dir\n");
		PRINT_SHAKEN_ERROR_IF_SET
			return STIR_SHAKEN_STATUS_TERM;
	}

	printf("TEST 2: Checking if X509_verify_cert returns SUCCESS for SP cert\n");
	// Now it should work
	status = stir_shaken_verify_cert(&ss, &sp.cert);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("X509 cert path verification failed for SP certificate\n");
		PRINT_SHAKEN_ERROR_IF_SET
	}
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == status, "Error, status should be OK");

	// CA cleanup	
	stir_shaken_destroy_cert(&ca.cert);
	stir_shaken_destroy_keys_ex(&ca.keys.ec_key, &ca.keys.private_key, &ca.keys.public_key);

	// SP cleanup	
	stir_shaken_sp_destroy(&sp);

	EVP_PKEY_free(pkey);

	return status;
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

	if (stir_shaken_unit_test_x509_cert_path_verification() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
