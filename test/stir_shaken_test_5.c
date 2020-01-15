#include <stir_shaken.h>

const char *path = "./test/run";

/**
 * STIR/Shaken PASSporT creation using libjwt, Unit test
 * According to RFC 8225:
 * "Appendix A.  Example ES256-Based PASSporT JWS Serialization and Signature"
 */
#define BUF_LEN 1000
stir_shaken_status_t stir_shaken_unit_test_call_authorization(void)
{
	stir_shaken_jwt_passport_t passport = {0};
    stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;
    const char *x5u = "https://cert.example.org/passport.cer";      // ref
    const char *attest = NULL;                                      // ignore, ref test case doesn't include this field
    const char *desttn_key = "uri";                                 // ref
    const char *desttn_val = "sip:alice@example.com";               // ref
    int iat = 1471375418;                                           // ref
    const char *origtn_key = "tn";                                  // ref test for orig telephone number
    const char *origtn_val = "12155551212";                         // ref
    const char *origid = NULL;                                      // ignore, ref test case doesn't include this field
    uint8_t ppt_ignore = 1;                                         // ignore, ref test case doesn't include this field

    /* Reference test values */
    const char *payload_serialised_ref = "{\"dest\":{\"uri\":[\"sip:alice@example.com\"]},\"iat\":1471375418,\"orig\":{\"tn\":\"12155551212\"}}";
    const char *payload_base64_ref = "eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI6MTQ3MTM3NTQxOCwib3JpZyI6eyJ0biI6IjEyMTU1NTUxMjEyIn19";
    const char *header_serialised_ref = "{\"alg\":\"ES256\",\"typ\":\"passport\",\"x5u\":\"https://cert.example.org/passport.cer\"}";
    const char *header_base64_ref = "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9";
    const char *signature_ref = "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9.eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI6MTQ3MTM3NTQxOCwib3JpZyI6eyJ0biI6IjEyMTU1NTUxMjEyIn19";
    //const char *signature_base64_ref = "ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluQmhjM053YjNKMElpd2llRFYxSWpvaWFIUjBjSE02THk5alpYSjBMbVY0WVcxd2JHVXViM0puTDNCaGMzTndiM0owTG1ObGNpSjkuZXlKa1pYTjBJanA3SW5WeWFTSTZXeUp6YVhBNllXeHBZMlZBWlhoaGJYQnNaUzVqYjIwaVhYMHNJbWxoZENJNk1UUTNNVE0zTlRReE9Dd2liM0pwWnlJNmV5SjBiaUk2SWpFeU1UVTFOVFV4TWpFeUluMTk=";
    //const char *signature_encoded_ref = "VLBCIVDCaeK6M4hLJb6SHQvacAQVvoiiEOWQ_iUkqk79UD81fHQ0E1b3_GluIkba7UWYRM47ZbNFdOJquE35cw";

	jwt_t	*jwtpass = NULL;	// PASSporT as a JWT
    cJSON	*jsonpass = NULL;	// PASSporT as a JSON
	char *s = NULL, *sih = NULL;
    
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid, .ppt_ignore = ppt_ignore};

	sprintf(private_key_name, "%s%c%s", path, '/', "u5_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u5_public_key.pem");
    
    printf("=== Unit testing: STIR/Shaken PASSporT creation [stir_shaken_unit_test_jwt_passport_create]\n\n");
    
    // Generate new keys for this test
	status = stir_shaken_generate_keys(NULL, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);

	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key");
	stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
	status = stir_shaken_jwt_passport_init(NULL, &passport, &params, priv_raw, priv_raw_len);

    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "PASSporT has not been created");
    stir_shaken_assert(passport.jwt != NULL, "JWT has not been created");
	printf("1. JWT:\n%s\n", (s = jwt_dump_str(passport.jwt, 1)));
	jwt_free_str(s); s = NULL;

    // Encode using default key
	status = stir_shaken_jwt_passport_sign(NULL, &passport, NULL, 0, &s);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to sign using ES 256");
	stir_shaken_assert(s != NULL, "Failed to sign using ES 256, NULL string");
	printf("2. Encoded (using default key):\n%s\n", s);
	jwt_free_str(s); s = NULL;
	
	// Encode using given key
	status = stir_shaken_jwt_passport_sign(NULL, &passport, priv_raw, priv_raw_len, &s);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to sign using ES 256");
	stir_shaken_assert(s != NULL, "Failed to sign using ES 256, NULL string");
	printf("3. Encoded (using given key):\n%s\n", s);
	jwt_free_str(s); s = NULL;

	printf("4. Encoded via jwt call:\n%s\n\n", (s = jwt_encode_str(passport.jwt)));
	jwt_free_str(s); s = NULL;

	// Test call authorization with given PASSporT and key
	sih = stir_shaken_jwt_sip_identity_create(NULL, &passport, priv_raw, priv_raw_len);
	stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    printf("5.1 SIP Identity Header (call authorization with given PASSporT and key):\n%s\n\n", sih);
	free(sih); sih = NULL;
	
	// Test call authorization with given PASSporT and implicit key
	sih = stir_shaken_jwt_sip_identity_create(NULL, &passport, NULL, 0);
	stir_shaken_assert(sih != NULL, "Failed to create SIP Identity Header");
    printf("5.2 SIP Identity Header (call authorization with given PASSporT and implicit key):\n%s\n\n", sih);
	free(sih); sih = NULL;
	stir_shaken_jwt_passport_destroy(&passport);
	
	// Test call authorization with implicit PASSporT
	status = stir_shaken_jwt_authorize(NULL, &sih, &params, priv_raw, priv_raw_len);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to authorize (status)");
	stir_shaken_assert(sih != NULL, "Failed to authorize (SIP Identity Header)");
    printf("5.3 SIP Identity Header (call authorization with implicit PASSporT):\n%s\n\n", sih);
	free(sih); sih = NULL;
	
	pthread_mutex_lock(&stir_shaken_globals.mutex);
	stir_shaken_destroy_keys(&ec_key, &private_key, &public_key);
	pthread_mutex_unlock(&stir_shaken_globals.mutex);

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

	if (stir_shaken_unit_test_call_authorization() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
