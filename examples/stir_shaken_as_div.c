#include <stir_shaken.h>

int main(void)
{
	stir_shaken_context_t ss = { 0 };
	stir_shaken_as_t *as = NULL;
	stir_shaken_div_passport_params_t div_params = { 0 };
	stir_shaken_passport_t *div_passport = NULL;
	const char *new_dest = "12155551214";
	const char *new_dests[1] = { new_dest };
	char *div_identity = NULL;
	int success = 0;

	const char *original_identity =
		"eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL2V4YW1wbGUuY29tL29yaWcucGVtIn0."
		"eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIxMjE1NTU1MTIxMyJdfSwiaWF0IjoxNDQzMjA4MzQ1LCJvcmlnIjp7InRuIjoiMTIxNTU1NTEyMTIifSwib3JpZ2lkIjoib3JpZy1pZCJ9."
		"signature;info=<http://example.com/orig.pem>;alg=ES256;ppt=shaken";

	stir_shaken_init(NULL, STIR_SHAKEN_LOGLEVEL_NOTHING);
	as = stir_shaken_as_create(&ss);
	if (!as) goto done;

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_as_load_private_key(&ss, as, "./sp.priv")) {
		goto done;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_div_params_from_original_sih(
			&ss,
			original_identity,
			"https://example.com/div.pem",
			"tn",
			new_dests,
			1,
			NULL,
			NULL,
			&div_params)) {
		goto done;
	}

	div_identity = stir_shaken_as_div_authenticate_to_sih(&ss, as, &div_params, &div_passport);
	if (!div_identity) goto done;

	printf("Forward these as two separate SIP Identity header fields:\n");
	printf("Identity: %s\n", original_identity);
	printf("Identity: %s\n", div_identity);
	success = 1;

done:
	free(div_identity);
	stir_shaken_passport_destroy(&div_passport);
	stir_shaken_div_passport_params_destroy(&div_params);
	stir_shaken_as_destroy(&as);
	stir_shaken_deinit();
	return success ? 0 : 1;
}
