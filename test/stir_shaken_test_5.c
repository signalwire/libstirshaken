#include <stir_shaken.h>

const char *path = "./test/run";

stir_shaken_status_t stir_shaken_unit_test_sip_identity_header(void)
{
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
    stir_shaken_jwt_passport_t passport = { 0 };
    char *p = NULL;
    const char *x5u = "https://cert.example.org/passport.cer";      // ref
    const char *attest = NULL;                                      // ignore, ref test case doesn't include this field
    const char *desttn_key = "uri";                                 // ref
    const char *desttn_val = "sip:alice@example.com";               // ref
    int iat = 1471375418;                                           // ref
    const char *origtn_key = "tn";                                  // ref test for orig telephone number
    const char *origtn_val = "12155551212";                         // ref
    const char *origid = NULL;                                      // ignore, ref test case doesn't include this field
    uint8_t ppt_ignore = 1;                                         // ignore, ref test case doesn't include this field
    char *s = NULL, *sih = NULL;

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid, .ppt_ignore = ppt_ignore};
    
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	


	sprintf(private_key_name, "%s%c%s", path, '/', "u5_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u5_public_key.pem");

    printf("=== Unit testing: STIR/Shaken SIP Identity Header\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(NULL, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
	status = stir_shaken_jwt_passport_init(NULL, &passport, &params, priv_raw, priv_raw_len);
	
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "PASSporT has not been created");
    stir_shaken_assert(passport.jwt != NULL, "JWT has not been created");
	s = stir_shaken_jwt_passport_dump_str(&passport, 1);
	printf("1. JWT:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;
	
	sih = stir_shaken_jwt_sip_identity_create(NULL, &passport, priv_raw, priv_raw_len);
    stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    printf("SIP Identity Header:\n%s\n", sih);
    
    printf("\nOK\n\n");

	free(sih);
	sih = NULL;
    
	stir_shaken_jwt_passport_destroy(&passport);
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
    
    return STIR_SHAKEN_STATUS_OK;
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

	if (stir_shaken_unit_test_sip_identity_header() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
