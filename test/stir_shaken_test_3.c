#include <stir_shaken.h>


#define BUF_LEN 1000

const char *path = "./test/run";


stir_shaken_status_t stir_shaken_unit_test_passport_create_verify_signature(void)
{
    stir_shaken_passport_t passport = {0};
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
    const char *x5u = "https://cert.example.org/passport.cer";      // ref
    const char *attest = NULL;                                      // ignore, ref test case doesn't include this field
    const char *desttn_key = "uri";                                 // ref
    const char *desttn_val = "sip:alice@example.com";               // ref
    int iat = 1471375418;                                           // ref
    const char *origtn_key = "tn";                                  // ref test for orig telephone number
    const char *origtn_val = "12155551212";                         // ref
    const char *origid = NULL;                                      // ignore, ref test case doesn't include this field
    uint8_t ppt_ignore = 1;                                         // ignore, ref test case doesn't include this field

    cJSON *jwt = NULL;
    cJSON *sig = NULL, *siginput = NULL;
    
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    
    unsigned char signature[BUF_LEN] = {0};
    int len = 0, i = -1;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	

    stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid, .ppt_ignore = ppt_ignore};

    
	sprintf(private_key_name, "%s%c%s", path, '/', "u3_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u3_public_key.pem");

    printf("=== Unit testing: STIR/Shaken PASSporT create/verify signature [stir_shaken_unit_test_passport_create_verify_signature]\n\n");
    
    // Generate new keys for this test
    status = stir_shaken_generate_keys(NULL, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
    stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key\n\n");
    stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
    stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");

    /* Test */
    status = stir_shaken_passport_create(NULL, &passport, &params, private_key);

    stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "PASSporT has not been created");
    stir_shaken_assert(passport.json != NULL, "JSON @json has not been created");
    stir_shaken_assert(passport.info != NULL, "JSON @info has not been created");

    jwt = cJSON_GetObjectItem(passport.json, "jwt");
    stir_shaken_assert(jwt != NULL, "PASSporT JSON is missing \"jwt\"");

    // Test signature

    // JWS Signature encoded in base 64
    // JWS Signature = ES256(Main Signature)
    // signature = base64(JWS Signature)
    sig = cJSON_GetObjectItem(jwt, "signature");
    stir_shaken_assert(sig != NULL, "PASSporT @jwt is missing \"signature\"");
    printf("Signature:\n%s\n", sig->valuestring);
    
    siginput = cJSON_GetObjectItem(passport.info, "main_signature");
    stir_shaken_assert(siginput != NULL, "PASSporT @info is missing \"main_signature\"");

    // Decode from base 64
    len = stir_shaken_b64_decode(sig->valuestring, (char*) signature, sizeof(signature));
    stir_shaken_assert(len > 1, "Signature length");
    len = len - 1;  // stir_shaken_b64_decode returns length of the data plus 1 for '\0' which it appends

    // Verify
    i = stir_shaken_do_verify_data(NULL, siginput->valuestring, strlen(siginput->valuestring), signature, len, public_key);
    stir_shaken_assert(i == 0, "Err, verify failed\n\n");

    printf("OK\n\n");

    /* Need to free JSON object allocated by cJSON lib. */
	stir_shaken_passport_destroy(&passport);

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

	if (stir_shaken_unit_test_passport_create_verify_signature() != STIR_SHAKEN_STATUS_OK) {
		
		printf("Fail\n");
		return -2;
	}
	
	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
