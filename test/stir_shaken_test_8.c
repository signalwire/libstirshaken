#include <stir_shaken.h>

const char *path = "./test/run";

stir_shaken_status_t stir_shaken_unit_test_verify(void)
{
    const char *x5u = "https://not.here.org/passport.cer";
    const char *attest = "B";
    const char *desttn_key = "uri";
    const char *desttn_val = "sip:Obama@democrats.com";
    int iat = 9876543;
    const char *origtn_key = "";
    const char *origtn_val = "07483866525";
    const char *origid = "Trump's Office";
    char *sih = NULL;
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;

	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
	char csr_name[300] = { 0 };
	char csr_text_name[300] = { 0 };
	char cert_name[300] = { 0 };
	char cert_text_name[300] = { 0 };

    uint32_t sp_code = 1800;

    stir_shaken_csr_t csr = {0};
    stir_shaken_cert_t cert = {0};


	sprintf(private_key_name, "%s%c%s", path, '/', "u8_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u8_public_key.pem");
    sprintf(csr_name, "%s%c%s", path, '/', "u8_csr.pem");
    sprintf(csr_text_name, "%s%c%s", path, '/', "u8_csr_text.pem");
    sprintf(cert_name, "%s%c%s", path, '/', "u8_cert.crt");
    sprintf(cert_text_name, "%s%c%s", path, '/', "u8_cert_text.crt");

    printf("=== Unit testing: STIR/Shaken Verification [stir_shaken_unit_test_verify]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(NULL, &ec_key, &private_key, &public_key, private_key_name, public_key_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
    printf("Authorizing...\n\n");
    status = stir_shaken_authorize(NULL, &sih, &params, private_key, NULL);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create SIP Identity Header");
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    
    printf("Created SIP Identity Header\n\n");
    printf("SIP Identity Header:\n%s\n", sih);

    printf("Creating CSR\n");
    status = stir_shaken_generate_csr(NULL, sp_code, &csr.req, private_key, public_key, csr_name, csr_text_name);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");
    
    printf("Creating Certificate\n");
    status = stir_shaken_generate_cert_from_csr(NULL, sp_code, &cert, &csr, private_key, public_key, cert_name, cert_text_name);
    printf("Err, generating Cert\n");

    printf("Verifying SIP Identity Header's signature with Cert...\n\n");
    status = stir_shaken_verify_with_cert(NULL, sih, &cert);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, verifying");

	X509_REQ_free(csr.req);
	csr.req = NULL;
		
	X509_free(cert.x);
	cert.x = NULL;

	free(sih);
	sih = NULL;
	
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
    
    return status;
}

int main(void)
{
	stir_shaken_do_init(NULL);

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
