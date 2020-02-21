#include <stir_shaken_tool.h>


int stirshaken_command_configure(stir_shaken_context_t *ss, const char *command_name, struct ca *ca, struct sp *sp, struct options *options)
{
	if (!command_name || !ca || !sp || !options) {
		return COMMAND_UNKNOWN;
	}

	if (!strcmp(command_name, COMMAND_NAME_KEYS)) {

		return COMMAND_KEYS;

	} else if (!strcmp(command_name, COMMAND_NAME_CERT)) {

		if (COMMAND_CERT_CA == options->command_cert_type) {

			strncpy(ca->cert_name, options->file, STIR_SHAKEN_BUFLEN);
			strncpy(ca->subject_c, options->subject_c, STIR_SHAKEN_BUFLEN);
			strncpy(ca->subject_cn, options->subject_cn, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_c, options->issuer_c, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_cn, options->issuer_cn, STIR_SHAKEN_BUFLEN);
			return COMMAND_CERT_CA;

		} else if (COMMAND_CERT_SP == options->command_cert_type) {

			strncpy(sp->cert_name, options->file, STIR_SHAKEN_BUFLEN);
			return COMMAND_CERT_SP;

		} else {
			stir_shaken_set_error(ss, "Bad --type", STIR_SHAKEN_ERROR_GENERAL);
			return COMMAND_UNKNOWN;
		}

	} else if (!strcmp(command_name, COMMAND_NAME_INSTALL_CERT)) {

		fprintf(stderr, "\n\nConfiguring install CA certificate command...\n\n");
		return COMMAND_INSTALL_CERT;

	} else {

		stir_shaken_set_error(ss, "Unknown command", STIR_SHAKEN_ERROR_GENERAL);
		return COMMAND_UNKNOWN;
	}
}

stir_shaken_status_t stirshaken_command_validate(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, struct options *options)
{
	switch (command) {

		case COMMAND_KEYS:

			if (stir_shaken_zstr(options->private_key_name) && stir_shaken_zstr(options->public_key_name)) {
				goto fail;
			}
			break;

		case COMMAND_CSR:
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

		case COMMAND_CERT:
		case COMMAND_UNKNOWN:
		default:
			goto fail;
	}

	return STIR_SHAKEN_STATUS_OK;

fail:
	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stirshaken_command_execute(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, struct options *options)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
	unsigned long	hash = 0;
	char			hashstr[100] = { 0 }, cert_hashed_as_text[1000] = { 0 };
	int				hashstrlen = 100;


	if (STIR_SHAKEN_STATUS_OK != stir_shaken_do_init(ss, options->ca_dir, options->crl_dir)) {
		goto fail;
	}

	switch (command) {

		case COMMAND_KEYS:

			status = stir_shaken_generate_keys(ss, &options->keys.ec_key, &options->keys.private_key, &options->keys.public_key, options->private_key_name, options->public_key_name, NULL, NULL);
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
