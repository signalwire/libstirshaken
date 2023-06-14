#include <stir_shaken.h>

const char *path = "./test/run";
const char *x5u = "https://not.here.org/passport.cer";
const char *attest = "B";
const char *desttn_key = "tn";
const char *desttn_val = "+90 2235";
int iat = 0;
int iat_freshness = 60;
const char *origtn_key = "tn";
const char *origtn_val = "+80 2234";
const char *origid = "Just testing";


static int test_passport_data(stir_shaken_passport_t *passport)
{
	const char *p = NULL;
	long int iat_ = -1;

	// test JWT header
	p = stir_shaken_passport_get_header(NULL, passport, "alg");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	stir_shaken_assert(!strcmp(p, "ES256"), "ERROR: wrong param value");

	p = stir_shaken_passport_get_header(NULL, passport, "ppt");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	stir_shaken_assert(!strcmp(p, "shaken"), "ERROR: wrong param value");

	p = stir_shaken_passport_get_header(NULL, passport, "typ");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	stir_shaken_assert(!strcmp(p, "passport"), "ERROR: wrong param value");

	p = stir_shaken_passport_get_header(NULL, passport, "x5u");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	stir_shaken_assert(!strcmp(p, x5u), "ERROR: wrong param value");

	// test JWT paylaod
	p = stir_shaken_passport_get_grant(NULL, passport, "attest");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	stir_shaken_assert(!strcmp(p, attest), "ERROR: wrong param value");

	p = stir_shaken_passport_get_grants_json(NULL, passport, "dest");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	{
		ks_json_t *j = ks_json_parse(p), *item = NULL;
#if KS_VERSION_NUM >= 20000
		const char *item_value = "";
#endif
		stir_shaken_assert(j, "Failed to parse @dest into JSON");
		stir_shaken_assert(NULL != (item = ks_json_get_object_item(j, "tn")), "Failed to get @tn from @dest JSON");
		stir_shaken_assert(NULL != (item = ks_json_get_array_item(item, 0)), "Failed to get array item from @dest @tn array JSON");
#if KS_VERSION_NUM >= 20000
		ks_json_value_string(item, &item_value);
		printf("\n@dest @tn is %s\n", item_value);
		stir_shaken_assert(!strcmp(desttn_val, item_value), "@dest invalid");
#else
		printf("\n@dest @tn is %s\n", ks_json_value_string(item));
		stir_shaken_assert(!strcmp(desttn_val, ks_json_value_string(item)), "@dest invalid");
#endif
		ks_json_delete(&j);
	}
	free((char*)p);
	p = NULL;

	iat_ = stir_shaken_passport_get_grant_int(NULL, passport, "iat");
	stir_shaken_assert(errno != ENOENT, "PASSporT is missing param");
	stir_shaken_assert(iat_ == iat, "ERROR: wrong param value");

	p = stir_shaken_passport_get_grants_json(NULL, passport, "orig");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	{
		ks_json_t *j = ks_json_parse(p), *item = NULL;
#if KS_VERSION_NUM >= 20000
		const char *item_value = "";
#endif
		stir_shaken_assert(j, "Failed to parse @orig into JSON");
		stir_shaken_assert(NULL != (item = ks_json_get_object_item(j, "tn")), "Failed to get @tn from @orig JSON");
#if KS_VERSION_NUM >= 20000
		ks_json_value_string(item, &item_value);
		printf("\n@orig @tn is %s\n", item_value);
		stir_shaken_assert(!strcmp(origtn_val, item_value), "@orig invalid");
#else
		printf("\n@orig @tn is %s\n", ks_json_value_string(item));
		stir_shaken_assert(!strcmp(origtn_val, ks_json_value_string(item)), "@orig invalid");
#endif
		ks_json_delete(&j);
	}
	free((char*)p);
	p = NULL;

	p = stir_shaken_passport_get_grant(NULL, passport, "origid");
	stir_shaken_assert(p != NULL, "PASSporT is missing param");
	stir_shaken_assert(!strcmp(p, origid), "ERROR: wrong param value");

	return 0;
}

stir_shaken_status_t stir_shaken_unit_test_as_authenticate_to_passport(void)
{
	stir_shaken_passport_t *passport = NULL;
	char *p = NULL, *s = NULL, *encoded = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_as_t	*as = NULL;

	stir_shaken_passport_params_t params = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat = time(NULL), .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid };

	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };

	EC_KEY *ec_key = NULL;
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *public_key = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	char *id = NULL;
	int is_tn = 0;


	sprintf(private_key_name, "%s%c%s", path, '/', "u15_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u15_public_key.pem");

	printf("=== Unit testing: STIR/Shaken AS authenticate to PASSporT\n\n");

	// Generate new keys for this test
	status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}

	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(ec_key != NULL, "Err, failed to generate EC key");
	stir_shaken_assert(private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(public_key != NULL, "Err, failed to generate public key");
	stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	/* Test */
	as = stir_shaken_as_create(&ss);

	stir_shaken_assert(as, "Failed to create Authentication Service");

	status = stir_shaken_as_load_private_key(&ss, as, private_key_name);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == status, "Failed to load private key");

	encoded = stir_shaken_as_authenticate_to_passport(&ss, as, &params, &passport);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	stir_shaken_assert(encoded, "PASSporT has not been created");
	stir_shaken_assert(passport, "PASSporT has not been returned");
	stir_shaken_assert(passport->jwt != NULL, "JWT has not been created");
	printf("\n1. PASSporT encoded:\n%s\n", encoded);
	free(encoded);
	encoded = NULL;

	s = stir_shaken_passport_dump_str(&ss, passport, 1);
	printf("2. PASSporT decoded:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;

	test_passport_data(passport);

	id = stir_shaken_passport_get_identity(&ss, passport, &is_tn);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(id, "Failed to get identity");
	stir_shaken_assert(is_tn == 1, "Wrong tn form returned");
	stir_shaken_assert(!strcmp(id, origtn_val), "Bad @tn returned");
	free(id);
	id = NULL;

	status = stir_shaken_passport_sign(&ss, passport, priv_raw, priv_raw_len, &encoded);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to sign PASSporT");
	stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
	printf("\n3. PASSporT encoded again:\n%s\n", encoded);

	test_passport_data(passport);
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers(&ss, passport), "Err, PASSporT validate headers");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_grants(&ss, passport), "Err, PASSporT validate grants");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers_and_grants(&ss, passport), "Err, PASSporT validate headers and grants");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_iat_against_freshness(&ss, passport, iat_freshness), "Err, PASSporT validate @iat");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate(&ss, passport, iat_freshness), "Err, PASSporT validate");

	stir_shaken_free_jwt_str(encoded);
	encoded = NULL;

	stir_shaken_passport_destroy(&passport);

	encoded = stir_shaken_authenticate_to_passport_with_key(&ss, &params, &passport, priv_raw, priv_raw_len);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");

	stir_shaken_assert(encoded, "PASSporT has not been created");
	stir_shaken_assert(passport, "PASSporT has not been returned");
	stir_shaken_assert(passport->jwt != NULL, "JWT has not been created");
	printf("\n4. PASSporT encoded again:\n%s\n", encoded);
	free(encoded);
	encoded = NULL;

	s = stir_shaken_passport_dump_str(&ss, passport, 1);
	printf("5. PASSporT decoded again:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;

	test_passport_data(passport);

	id = stir_shaken_passport_get_identity(&ss, passport, &is_tn);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(id, "Failed to get identity");
	stir_shaken_assert(is_tn == 1, "Wrong tn form returned");
	stir_shaken_assert(!strcmp(id, origtn_val), "Bad @tn returned");	
	free(id);
	id = NULL;

	status = stir_shaken_passport_sign(&ss, passport, priv_raw, priv_raw_len, &encoded);
	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is: '%s'\n", error_description);
		printf("Error code is: '%d'\n", error_code);
	}
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to sign PASSporT");
	stir_shaken_assert(stir_shaken_is_error_set(&ss) == 0, "Err, error condition set (should not be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_GENERAL, "Err, error should be GENERAL");
	stir_shaken_assert(error_description == NULL, "Err, error description set, should be NULL");
	printf("\n6. PASSporT encoded again:\n%s\n", encoded);

	test_passport_data(passport);
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers(&ss, passport), "Err, PASSporT validate headers");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_grants(&ss, passport), "Err, PASSporT validate grants");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers_and_grants(&ss, passport), "Err, PASSporT validate headers and grants");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_iat_against_freshness(&ss, passport, iat_freshness), "Err, PASSporT validate @iat");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate(&ss, passport, iat_freshness), "Err, PASSporT validate");

	printf("OK\n\n");

	if (encoded) {	
		stir_shaken_free_jwt_str(encoded);
		encoded = NULL;
	}
	if (id) {
		free(id);
		id = NULL;
	}

	stir_shaken_passport_destroy(&passport);
	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);
	stir_shaken_as_destroy(&as);

	return STIR_SHAKEN_STATUS_OK;
}

int main(void)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_do_init(NULL, NULL, NULL, STIR_SHAKEN_LOGLEVEL_HIGH), "Cannot init lib");

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {

			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_as_authenticate_to_passport() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
