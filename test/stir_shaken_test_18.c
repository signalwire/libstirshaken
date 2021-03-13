#include <stir_shaken.h>

const char *path = "./test/run";
const char *x5u = "https://not.here.org/passport.cer";
const char *attest = "B";
const char *desttn_key = "tn";
const char *desttn_val = "+90 2235";
int iat_freshness = 60;
const char *origtn_key = "tn";
const char *origtn_val = "+80 2234";
const char *origid = "Just testing";


stir_shaken_status_t stir_shaken_unit_test_passport_iat_check(void)
{
	stir_shaken_passport_t *passport_1 = NULL;
	stir_shaken_passport_t *passport_2 = NULL;
	stir_shaken_passport_t *passport_3 = NULL;
	char *p = NULL, *s = NULL, *encoded_1 = NULL, *encoded_2 = NULL, *encoded_3 = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_as_t	*as = NULL;
	int iat = time(NULL);

	stir_shaken_passport_params_t params_1 = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat + 70, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid };
	stir_shaken_passport_params_t params_2 = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat - 70, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid };
	stir_shaken_passport_params_t params_3 = { .x5u = x5u, .attest = attest, .desttn_key = desttn_key, .desttn_val = desttn_val, .iat = iat -1, .origtn_key = origtn_key, .origtn_val = origtn_val, .origid = origid };

	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };

	EC_KEY *ec_key = NULL;
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *public_key = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	char *id = NULL;
	int is_tn = 0;


	sprintf(private_key_name, "%s%c%s", path, '/', "u18_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u18_public_key.pem");

	printf("=== Unit testing: PASSporT @iat check (now is %zu)\n\n", iat);

	stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
	as = stir_shaken_as_create(&ss);
	stir_shaken_as_load_private_key(&ss, as, private_key_name);

	printf("=== Unit testing: PASSporT @iat too fresh\n\n");

	// Generate all three PASSporTS to test
	encoded_1 = stir_shaken_as_authenticate_to_passport(&ss, as, &params_1, &passport_1);
	encoded_2 = stir_shaken_as_authenticate_to_passport(&ss, as, &params_2, &passport_2);
	encoded_3 = stir_shaken_as_authenticate_to_passport(&ss, as, &params_3, &passport_3);

	printf("\n\n=== Unit testing: PASSporT @iat too fresh\n\n");

	stir_shaken_assert(encoded_1, "PASSporT has not been created");
	stir_shaken_assert(passport_1, "PASSporT has not been returned");
	stir_shaken_assert(passport_1->jwt != NULL, "JWT has not been created");
	printf("\n1. PASSporT encoded:\n%s\n", encoded_1);
	free(encoded_1);
	encoded_1 = NULL;
	s = stir_shaken_passport_dump_str(&ss, passport_1, 1);
	if (s) {
		printf("PASSporT is:\n%s\n", s);
		stir_shaken_free_jwt_str(s);
		s = NULL;
	}

	stir_shaken_clear_error(&ss);
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers(&ss, passport_1), "Err, PASSporT validate headers");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_grants(&ss, passport_1), "Err, PASSporT validate grants");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers_and_grants(&ss, passport_1), "Err, PASSporT validate headers and grants");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_passport_validate_iat_against_freshness(&ss, passport_1, iat_freshness), "Err, PASSporT validate @iat");
	stir_shaken_assert(stir_shaken_is_error_set(&ss), "Err, error condition not set (should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_FUTURE, "Err, wrong error code");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_passport_validate(&ss, passport_1, iat_freshness), "Err, PASSporT validate shoud fail");
	
	printf("\n\n=== Unit testing: PASSporT @iat expired\n\n");

	stir_shaken_assert(encoded_2, "PASSporT has not been created");
	stir_shaken_assert(passport_2, "PASSporT has not been returned");
	stir_shaken_assert(passport_2->jwt != NULL, "JWT has not been created");
	printf("\n2. PASSporT encoded:\n%s\n", encoded_2);
	free(encoded_2);
	encoded_2 = NULL;
	s = stir_shaken_passport_dump_str(&ss, passport_2, 1);
	if (s) {
		printf("PASSporT is:\n%s\n", s);
		stir_shaken_free_jwt_str(s);
		s = NULL;
	}

	stir_shaken_clear_error(&ss);
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers(&ss, passport_2), "Err, PASSporT validate headers");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_grants(&ss, passport_2), "Err, PASSporT validate grants");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers_and_grants(&ss, passport_2), "Err, PASSporT validate headers and grants");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_passport_validate_iat_against_freshness(&ss, passport_2, iat_freshness), "Err, PASSporT validate @iat");
	stir_shaken_assert(stir_shaken_is_error_set(&ss), "Err, error condition not set (should be set)");
	error_description = stir_shaken_get_error(&ss, &error_code);
	stir_shaken_assert(error_code == STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_EXPIRED, "Err, wrong error code");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_passport_validate(&ss, passport_2, iat_freshness), "Err, PASSporT validate shoud fail");

	printf("\n\n=== Unit testing: PASSporT @iat within range\n\n");

	stir_shaken_assert(encoded_3, "PASSporT has not been created");
	stir_shaken_assert(passport_3, "PASSporT has not been returned");
	stir_shaken_assert(passport_3->jwt != NULL, "JWT has not been created");
	printf("\n3. PASSporT encoded:\n%s\n", encoded_3);
	free(encoded_3);
	encoded_3 = NULL;
	s = stir_shaken_passport_dump_str(&ss, passport_3, 1);
	if (s) {
		printf("PASSporT is:\n%s\n", s);
		stir_shaken_free_jwt_str(s);
		s = NULL;
	}

	stir_shaken_clear_error(&ss);
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers(&ss, passport_3), "Err, PASSporT validate headers");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_grants(&ss, passport_3), "Err, PASSporT validate grants");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_headers_and_grants(&ss, passport_3), "Err, PASSporT validate headers and grants");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate_iat_against_freshness(&ss, passport_3, iat_freshness), "Err, PASSporT validate @iat");
	stir_shaken_assert(!stir_shaken_is_error_set(&ss), "Err, error condition set (should not be set)");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_passport_validate(&ss, passport_3, iat_freshness), "Err, PASSporT validate shoud be successful");


	printf("OK\n\n");

	stir_shaken_passport_destroy(&passport_1);
	stir_shaken_passport_destroy(&passport_2);
	stir_shaken_passport_destroy(&passport_3);
	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);
	stir_shaken_as_destroy(&as);

	return STIR_SHAKEN_STATUS_OK;
}

int main(void)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_init(NULL, STIR_SHAKEN_LOGLEVEL_NOTHING), "Cannot init lib");

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {

			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_passport_iat_check() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_deinit();

	printf("OK\n");

	return 0;
}
