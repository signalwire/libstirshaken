#include <stir_shaken_tool.h>


stir_shaken_status_t stirshaken_command_validate(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, const char *ca_dir, const char *crl_dir)
{
	switch (command) {

		case COMMAND_KEYS:

			if (stir_shaken_zstr(ca->private_key_name) && stir_shaken_zstr(ca->public_key_name)) {
				goto fail;
			}
			break;

		case COMMAND_CERT_CA:

			if (stir_shaken_zstr(ca->cert_name)) {
				goto fail;
			}
			break;
		
		case COMMAND_CERT_SP:
			if (stir_shaken_zstr(ca->cert_name)) {
				goto fail;
			}
			break;

		case COMMAND_INSTALL_CERT:
			break;

		case COMMAND_UNKNOWN:
		default:
			goto fail;
	}

	return STIR_SHAKEN_STATUS_OK;

fail:
	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stirshaken_command_execute(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, const char *ca_dir, const char *crl_dir)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
	unsigned long	hash = 0;
	char			hashstr[100] = { 0 }, cert_hashed_as_text[1000] = { 0 };
	int				hashstrlen = 100;


	if (STIR_SHAKEN_STATUS_OK != stir_shaken_do_init(ss, ca_dir, crl_dir)) {
		goto fail;
	}

	switch (command) {

		case COMMAND_KEYS:

			status = stir_shaken_generate_keys(ss, &ca->keys.ec_key, &ca->keys.private_key, &ca->keys.public_key, ca->private_key_name, ca->public_key_name, NULL, NULL);
			if (STIR_SHAKEN_STATUS_OK != status) {
				goto fail;
			}
			break;

		case COMMAND_CERT_CA:

			fprintf(stderr, "Loading keys...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &ca->keys.private_key, &ca->keys.public_key, ca->private_key_name, ca->public_key_name, NULL, NULL)) {
				goto fail;
			}

			fprintf(stderr, "Generating cert...\n");
			ca->cert.x = stir_shaken_generate_x509_self_signed_ca_cert(ss, ca->keys.private_key, ca->keys.public_key, ca->issuer_c, ca->issuer_cn, ca->serial, ca->expiry_days);
			if (!ca->cert.x) {
				goto fail;
			}
			
			fprintf(stderr, "Configuring certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_configure(ss, &ca->cert, ca->cert_name, NULL, NULL)) {
				goto fail;
			}

			fprintf(stderr, "Saving certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, ca->cert.x, ca->cert.name, ca->cert.name_text)) {
				goto fail;
			}

			stir_shaken_hash_cert_name(ss, &ca->cert);
			printf("CA name hash is %lu\n", ca->cert.hash);
			printf("CA hashed file name is %s\n", ca->cert.cert_name_hashed);
			sprintf(cert_hashed_as_text, "%s.text", ca->cert.cert_name_hashed);

			fprintf(stderr, "Saving certificate under hashed name...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, ca->cert.x, ca->cert.cert_name_hashed, cert_hashed_as_text)) {
				goto fail;
			}

			break;

		case COMMAND_CERT_SP:
			break;

		case COMMAND_INSTALL_CERT:
			break;

		case COMMAND_UNKNOWN:
		default:
			goto fail;
	}

	return STIR_SHAKEN_STATUS_OK;

fail:
	return STIR_SHAKEN_STATUS_FALSE;
}
