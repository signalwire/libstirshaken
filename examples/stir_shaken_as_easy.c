#include <stir_shaken.h>


/**
 * This example demonstrates how to create simplest authentication service (STI-SP/AS), wrapped into stir_shaken_as_t struct.
 *
 * 1. Create PASSporT stir_shaken_passport_params_t params = { .x5u = "https://sp.com/sp.pem", (...) }
 * 2. Get SSL keys or generate them with stir_shaken_generate_keys
 * 3. Create Authentication Service
 * 4. Call stir_shaken_as_authenticate_to_passport with PASSporT params to get signed PASSporT
 *    (and optionally PASSporT object which can be further manilpulated on it's own, with stir_shaken_passport_sign,
 *    stir_shaken_passport_dump_str, etc)
 * 5. For Shaken over SIP: Get PASSporT wrapped into SIP Identity Header
 *  
 **/

int main(void)
{
	int ret = 0;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_passport_t *passport = NULL;
	stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;

	char *s = NULL, *encoded = NULL, *sih = NULL;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *public_key = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	

	stir_shaken_passport_params_t params = {
		.x5u = "https://sp.com/sp.pem",
		.attest = "A",
		.desttn_key = "tn",
		.desttn_val = "01256500600",
		.iat = time(NULL),
		.origtn_key = "tn",
		.origtn_val = "01256789999",
		.origid = "ref"
	};

	stir_shaken_as_t *as = NULL;


	status = stir_shaken_init(&ss, STIR_SHAKEN_LOGLEVEL_NOTHING);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("Cannot init lib\n");
		goto fail;
	}

	// If you do have your private SSL key already, load it
	if (STIR_SHAKEN_STATUS_OK == stir_shaken_file_exists("sp.priv")) {

		status = stir_shaken_load_key_raw(&ss, "sp.priv", priv_raw, &priv_raw_len);

		// Or for loading private and public at once:
		// status = stir_shaken_load_keys(&ss, &ec_key, &private_key, &public_key, "sp.priv", "sp.pub", priv_raw, &priv_raw_len);

		if (STIR_SHAKEN_STATUS_OK != status) {
			printf("Cannot load SSL key\n");
			goto fail;
		}
	} else {

		// If you do not have SSL keys yet, generate them
		status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, "sp.priv", "sp.pub", priv_raw, &priv_raw_len);
		if (STIR_SHAKEN_STATUS_OK != status) {
			printf("Cannot generate SSL keys\n");
			goto fail;
		}
	}

	as = stir_shaken_as_create(&ss);
	if (!as) {
		printf("Cannot create Authentication Service\n");
		goto fail;
	}

	status = stir_shaken_as_load_private_key(&ss, as, "sp.priv");
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("Failed to load private key");
		goto fail;
	}

	encoded = stir_shaken_as_authenticate_to_passport(&ss, as, &params, &passport);
	if (!encoded) {
		printf("PASSporT has not been created");
		goto fail;
	}

	printf("\n1. PASSporT encoded:\n%s\n", encoded);
	free(encoded);
	encoded = NULL;

	s = stir_shaken_passport_dump_str(&ss, passport, 1);
	printf("\n2. PASSporT decoded:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	stir_shaken_passport_destroy(passport);
	passport = NULL;

	// Use _with_key method to authenticate with specific key
	encoded = stir_shaken_authenticate_to_passport_with_key(&ss, &params, &passport, priv_raw, priv_raw_len);
	if (!encoded) {
		printf("PASSporT has not been created");
		goto fail;
	}

	printf("\n3. PASSporT encoded:\n%s\n", encoded);
	free(encoded);
	encoded = NULL;

	s = stir_shaken_passport_dump_str(&ss, passport, 1);
	printf("\n4. PASSporT decoded:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	stir_shaken_passport_destroy(passport);
	passport = NULL;

	// Authenticate using default key (associated with Authentication Service)
	sih = stir_shaken_as_authenticate_to_sih(&ss, as, &params, &passport);
	if (!sih) {
		printf("SIP Identity Header has not been created");
		goto fail;
	}
	printf("\n5. SIP Identity Header:\n%s\n", sih);
	free(sih); sih = NULL;
	stir_shaken_passport_destroy(passport);
	passport = NULL;

	// Use _with_key method to authenticate with specific key
	sih = stir_shaken_authenticate_to_sih_with_key(&ss, &params, &passport, priv_raw, priv_raw_len);
	if (!sih) {
		printf("SIP Identity Header has not been created");
		goto fail;
	}
	printf("\n6. SIP Identity Header:\n%s\n", sih);
	free(sih); sih = NULL;

	s = stir_shaken_passport_dump_str(&ss, passport, 1);
	printf("\n7. PASSporT decoded:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	// Manipulate PASSporT

	// Get plain version of PASSporT (decoded, not signed, with no signature)
	s = stir_shaken_passport_dump_str(&ss, passport, 1);
	printf("\n8. PASSporT decoded is:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	// Encode (sign) using default key (key associated with PASSporT via Authentication Service)
	status = stir_shaken_passport_sign(&ss, passport, NULL, 0, &s);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("Cannot sign PASSporT\n");
		goto fail;
	}
	printf("\n9. PASSporT encoded (signed again using default key) is:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	// Encode (sign) using specific key
	status = stir_shaken_passport_sign(&ss, passport, priv_raw, priv_raw_len, &s);
	if (STIR_SHAKEN_STATUS_OK != status) {
		printf("Cannot sign PASSporT\n");
		goto fail;
	}
	printf("\n10. PASSporT encoded (signed again using specific key) is:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);
	stir_shaken_file_remove("sp.priv");
	stir_shaken_file_remove("sp.pub");
	stir_shaken_passport_destroy(passport);
	stir_shaken_as_destroy(as);
	free(as);
	stir_shaken_deinit();

	return 0;

fail:

	if (stir_shaken_is_error_set(&ss)) {
		error_description = stir_shaken_get_error(&ss, &error_code);
		printf("Error description is:\n%s\n", error_description);
		printf("Error code is: %d\n", error_code);
	}
	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);
	stir_shaken_file_remove("sp.priv");
	stir_shaken_file_remove("sp.pub");
	stir_shaken_passport_destroy(passport);
	if (as) {
		stir_shaken_as_destroy(as);
		free(as);
	}
	stir_shaken_deinit();

	return -1;
}
