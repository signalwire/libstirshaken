#include <stir_shaken_tool.h>


int stirshaken_command_configure(stir_shaken_context_t *ss, const char *command_name, struct ca *ca, struct pa *pa, struct sp *sp, struct options *options)
{
	if (!command_name || !options) {
		return COMMAND_UNKNOWN;
	}

	if (!strcmp(command_name, COMMAND_NAME_KEYS)) {

		return COMMAND_KEYS;

	} else if (!strcmp(command_name, COMMAND_NAME_CSR)) {

		strncpy(sp->spc, options->spc, STIR_SHAKEN_BUFLEN);
		strncpy(sp->sp.csr_name, options->file, STIR_SHAKEN_BUFLEN);
		strncpy(sp->sp.public_key_name, options->public_key_name, STIR_SHAKEN_BUFLEN);
		strncpy(sp->sp.private_key_name, options->private_key_name, STIR_SHAKEN_BUFLEN);
		strncpy(sp->subject_c, options->subject_c, STIR_SHAKEN_BUFLEN);
		strncpy(sp->subject_cn, options->subject_cn, STIR_SHAKEN_BUFLEN);
		return COMMAND_CSR;

	} else if (!strcmp(command_name, COMMAND_NAME_CERT)) {

		if (COMMAND_CERT_CA == options->command_cert_type) {

			strncpy(ca->ca.cert_name, options->file, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_c, options->issuer_c, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_cn, options->issuer_cn, STIR_SHAKEN_BUFLEN);
			strncpy(ca->ca.public_key_name, options->public_key_name, STIR_SHAKEN_BUFLEN);
			strncpy(ca->ca.private_key_name, options->private_key_name, STIR_SHAKEN_BUFLEN);
			return COMMAND_CERT_CA;

		} else if (COMMAND_CERT_SP == options->command_cert_type) {

			strncpy(ca->ca.public_key_name, options->public_key_name, STIR_SHAKEN_BUFLEN);
			strncpy(ca->ca.private_key_name, options->private_key_name, STIR_SHAKEN_BUFLEN);
			strncpy(sp->sp.csr_name, options->csr_name, STIR_SHAKEN_BUFLEN);
			strncpy(ca->ca.cert_name, options->ca_cert, STIR_SHAKEN_BUFLEN);
			strncpy(sp->sp.cert_name, options->file, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_c, options->issuer_c, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_cn, options->issuer_cn, STIR_SHAKEN_BUFLEN);
			strncpy(ca->ca.tn_auth_list_uri, options->tn_auth_list_uri, STIR_SHAKEN_BUFLEN);
			return COMMAND_CERT_SP;

		} else {
			stir_shaken_set_error(ss, "Bad --type", STIR_SHAKEN_ERROR_GENERAL);
			return COMMAND_UNKNOWN;
		}

	} else if (!strcmp(command_name, COMMAND_NAME_INSTALL_CERT)) {

		fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n\nConfiguring install CA certificate command...\n\n");
		return COMMAND_INSTALL_CERT;

	} else if (!strcmp(command_name, COMMAND_NAME_CA)) {

		ca->ca.port = options->port;
		return COMMAND_CA;

	} else if (!strcmp(command_name, COMMAND_NAME_PA)) {

		pa->pa.port = options->port;
		return COMMAND_PA;

	} else if (!strcmp(command_name, COMMAND_NAME_SP_SPC_REQ)) {

		strncpy(sp->url, options->url, STIR_SHAKEN_BUFLEN);
		return COMMAND_SP_SPC_REQ;

	} else if (!strcmp(command_name, COMMAND_NAME_SP_CERT_REQ)) {

		strncpy(sp->spc, options->spc, STIR_SHAKEN_BUFLEN);
		strncpy(sp->sp.spc_token, options->spc_token, STIR_SHAKEN_BUFLEN);
		strncpy(sp->url, options->url, STIR_SHAKEN_BUFLEN);
		strncpy(sp->sp.public_key_name, options->public_key_name, STIR_SHAKEN_BUFLEN);
		strncpy(sp->sp.private_key_name, options->private_key_name, STIR_SHAKEN_BUFLEN);
		strncpy(sp->sp.csr_name, options->csr_name, STIR_SHAKEN_BUFLEN);
		return COMMAND_SP_CERT_REQ;

	} else {

		stir_shaken_set_error(ss, "Unknown command", STIR_SHAKEN_ERROR_GENERAL);
		return COMMAND_UNKNOWN;
	}
}

stir_shaken_status_t stirshaken_command_validate(stir_shaken_context_t *ss, int command, struct ca *ca, struct pa *pa, struct sp *sp, struct options *options)
{
	unsigned long long helper = 0;
	char *pCh = NULL;

	switch (command) {

		case COMMAND_KEYS:

			if (stir_shaken_zstr(options->private_key_name) && stir_shaken_zstr(options->public_key_name)) {
				goto fail;
			}
			break;

		case COMMAND_CSR:

			if (stir_shaken_zstr(sp->sp.private_key_name) || stir_shaken_zstr(sp->sp.public_key_name)
					|| stir_shaken_zstr(sp->subject_c) || stir_shaken_zstr(sp->subject_cn)
					|| stir_shaken_zstr(sp->spc) || stir_shaken_zstr(sp->sp.csr_name)) {
				goto fail;
			}

			helper = strtoul(sp->spc, &pCh, 10);
			STIR_SHAKEN_CHECK_CONVERSION_EXT
			sp->sp.code = helper;

			break;

		case COMMAND_CERT_CA:

			if (stir_shaken_zstr(ca->ca.cert_name) || stir_shaken_zstr(ca->ca.private_key_name) || stir_shaken_zstr(ca->ca.public_key_name)
					|| stir_shaken_zstr(ca->issuer_c) || stir_shaken_zstr(ca->issuer_cn)) {
				goto fail;
			}
			break;
		
		case COMMAND_CERT_SP:

			if (stir_shaken_zstr(sp->sp.cert_name) || stir_shaken_zstr(ca->ca.private_key_name) || stir_shaken_zstr(ca->ca.public_key_name)
					|| stir_shaken_zstr(sp->sp.csr_name) || stir_shaken_zstr(ca->ca.cert_name)
					|| stir_shaken_zstr(ca->issuer_c) || stir_shaken_zstr(ca->issuer_cn) || stir_shaken_zstr(ca->ca.tn_auth_list_uri)) {
				goto fail;
			}
			break;

		case COMMAND_INSTALL_CERT:
			break;

		case COMMAND_CA:
			break;

		case COMMAND_PA:
			break;

		case COMMAND_SP_SPC_REQ:

			if (stir_shaken_zstr(sp->url)) {
				goto fail;
			}
			break;

		case COMMAND_SP_CERT_REQ:

			if (stir_shaken_zstr(sp->url) || stir_shaken_zstr(sp->sp.private_key_name) || stir_shaken_zstr(sp->sp.public_key_name)
					|| stir_shaken_zstr(sp->spc) || stir_shaken_zstr(sp->sp.spc_token) || stir_shaken_zstr(sp->sp.csr_name)) {
				goto fail;
			}
			helper = strtoul(sp->spc, &pCh, 10);
			STIR_SHAKEN_CHECK_CONVERSION_EXT
			sp->sp.code = helper;
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

stir_shaken_status_t stirshaken_command_execute(stir_shaken_context_t *ss, int command, struct ca *ca, struct pa *pa, struct sp *sp, struct options *options)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
	unsigned long	hash = 0;
	char			hashstr[100] = { 0 }, cert_hashed_as_text[1000] = { 0 };
	int				hashstrlen = 100;


	if (STIR_SHAKEN_STATUS_OK != stir_shaken_do_init(ss, options->ca_dir, options->crl_dir, options->loglevel)) {
		goto fail;
	}

	switch (command) {

		case COMMAND_KEYS:

			status = stir_shaken_generate_keys(ss, &options->keys.ec_key, &options->keys.private_key, &options->keys.public_key, options->private_key_name, options->public_key_name, NULL, NULL);
			if (STIR_SHAKEN_STATUS_OK != status) {
				goto fail;
			}
			break;

		case COMMAND_CSR:

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Loading keys...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &sp->sp.keys.private_key, &sp->sp.keys.public_key, sp->sp.private_key_name, sp->sp.public_key_name, NULL, NULL)) {
				goto fail;
			}
			
			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Generating CSR...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_generate_csr(ss, sp->sp.code, &sp->sp.csr.req, sp->sp.keys.private_key, sp->sp.keys.public_key, sp->subject_c, sp->subject_cn)) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Saving CSR...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_csr_to_disk(ss, sp->sp.csr.req, sp->sp.csr_name)) {
				goto fail;
			}
			break;

		case COMMAND_CERT_CA:

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Loading keys...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &ca->ca.keys.private_key, &ca->ca.keys.public_key, ca->ca.private_key_name, ca->ca.public_key_name, NULL, NULL)) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Generating cert...\n");
			ca->ca.cert.x = stir_shaken_generate_x509_self_signed_ca_cert(ss, ca->ca.keys.private_key, ca->ca.keys.public_key, ca->issuer_c, ca->issuer_cn, ca->serial, ca->expiry_days);
			if (!ca->ca.cert.x) {
				goto fail;
			}
			
			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Configuring certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_configure(ss, &ca->ca.cert, ca->ca.cert_name, NULL, NULL)) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Saving certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, ca->ca.cert.x, ca->ca.cert.name)) {
				goto fail;
			}

			stir_shaken_hash_cert_name(ss, &ca->ca.cert);
			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "CA name hash is %lu\n", ca->ca.cert.hash);
			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "CA hashed file name is %s\n", ca->ca.cert.cert_name_hashed);

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Saving certificate under hashed name...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, ca->ca.cert.x, ca->ca.cert.cert_name_hashed)) {
				goto fail;
			}

			break;

		case COMMAND_CERT_SP:

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Loading keys...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &ca->ca.keys.private_key, &ca->ca.keys.public_key, ca->ca.private_key_name, ca->ca.public_key_name, NULL, NULL)) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Loading CSR...\n");
			sp->sp.csr.req = stir_shaken_load_x509_req_from_file(ss, sp->sp.csr_name);
			if (!sp->sp.csr.req) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Loading CA certificate...\n");
			ca->ca.cert.x = stir_shaken_load_x509_from_file(ss, ca->ca.cert_name);
			if (!ca->ca.cert.x) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Generating cert...\n");
			sp->sp.cert.x = stir_shaken_generate_x509_end_entity_cert_from_csr(ss, ca->ca.cert.x, ca->ca.keys.private_key, ca->issuer_c, ca->issuer_cn, sp->sp.csr.req, ca->serial_sp, ca->expiry_days_sp, ca->ca.tn_auth_list_uri);
			if (!sp->sp.cert.x) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Configuring certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_configure(ss, &sp->sp.cert, sp->sp.cert_name, NULL, NULL)) {
				goto fail;
			}

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Saving certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, sp->sp.cert.x, sp->sp.cert.name)) {
				goto fail;
			}
			break;

		case COMMAND_INSTALL_CERT:
			break;

		case COMMAND_CA:

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Starting CA service...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_run_ca_service(ss, &ca->ca)) {
				goto fail;
			}
			stir_shaken_ca_destroy(&ca->ca);
			break;

		case COMMAND_SP_SPC_REQ:
			break;

		case COMMAND_SP_CERT_REQ:

			{
				stir_shaken_http_req_t http_req = { 0 };
				char *jwt_encoded = NULL;
				char *jwt_decoded = NULL;
				char spc[STIR_SHAKEN_BUFLEN] = { 0 };

				fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Loading keys...\n");
				sp->sp.keys.priv_raw_len = sizeof(sp->sp.keys.priv_raw);
				if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &sp->sp.keys.private_key, &sp->sp.keys.public_key, sp->sp.private_key_name, sp->sp.public_key_name, sp->sp.keys.priv_raw, &sp->sp.keys.priv_raw_len)) {
					goto fail;
				}

				fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Loading CSR...\n");
				sp->sp.csr.req = stir_shaken_load_x509_req_from_file(ss, sp->sp.csr_name);
				if (!sp->sp.csr.req) {
					goto fail;
				}

				fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Requesting STI certificate...\n");
				http_req.url = strdup(sp->url);
				
				// Can do:
				// status = stir_shaken_sp_cert_req_ex(ss, &http_req, sp->sp.kid, sp->sp.nonce, sp->sp.csr.req, sp->sp.nb, sp->sp.na, sp->sp.keys.priv_raw, sp->sp.keys.priv_raw_len, &jwt_decoded, sp->sp.spc_token);
				//
				// or for explicit JWT:

				sprintf(spc, "%d", sp->sp.code);
				jwt_encoded = stir_shaken_acme_generate_cert_req_payload(ss, sp->sp.kid, sp->sp.nonce, http_req.url, sp->sp.csr.req, sp->sp.nb, sp->sp.na, spc, sp->sp.keys.priv_raw, sp->sp.keys.priv_raw_len, &jwt_decoded);
				if (!jwt_encoded || !jwt_decoded) {
					stir_shaken_set_error(ss, "Failed to generate JWT payload", STIR_SHAKEN_ERROR_JWT);
					goto fail;
				}

				fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\nHTTP POSTing JWT:\n%s\n", jwt_decoded);
				stir_shaken_free_jwt_str(jwt_decoded);
				jwt_decoded = NULL;

				if (STIR_SHAKEN_STATUS_OK != stir_shaken_sp_cert_req(ss, &http_req, jwt_encoded, sp->sp.keys.priv_raw, sp->sp.keys.priv_raw_len, sp->sp.spc_token)) {
					stir_shaken_set_error(ss, "SP certificate request failed", STIR_SHAKEN_ERROR_ACME);
					goto fail;
				}
			}

			break;

		case COMMAND_PA:

			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Starting PA service...\n");
			break;

		case COMMAND_UNKNOWN:
		default:
			goto fail;
	}

	return STIR_SHAKEN_STATUS_OK;

fail:
	return STIR_SHAKEN_STATUS_FALSE;
}
