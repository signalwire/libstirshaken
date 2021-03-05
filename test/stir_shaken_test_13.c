#include <stir_shaken.h>


const char *path = "./test/run";

stir_shaken_ca_t ca = { .ss = { .callback = stir_shaken_default_callback }, .cert_name = "test/ref/ca/ca.pem", .private_key_name = "test/ref/ca/ca.priv", .issuer_c = "US", .issuer_cn = "TEST CA", .serial = 1, .expiry_days = 9999, .tn_auth_list_uri = "https://test-ca.com/auth-list-check" };
int polling;
int ca_verifying_spc_token;
const char *pa_pem = "-----BEGIN CERTIFICATE-----\n"
"MIIB+jCCAaCgAwIBAgIBATAKBggqhkjOPQQDAjAuMQswCQYDVQQGEwJVUzEfMB0G\n"
"A1UEAwwWU2lnbmFsV2lyZSBTVEktUEEgVGVzdDAeFw0yMDA4MDEwMDA2NTBaFw00\n"
"NzEyMTcwMDA2NTBaMC4xCzAJBgNVBAYTAlVTMR8wHQYDVQQDDBZTaWduYWxXaXJl\n"
"IFNUSS1QQSBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDjJOep8dsSCN\n"
"5Nx3wek851dXIYhoOXWkeEGvPgnTFvHA98febb7wiR5NoqB04oKMR9Z8vrYfpJoz\n"
"dhZpZEAyMqOBrjCBqzAdBgNVHQ4EFgQUc103mIP3PWbtfyK6nZYCpcTCGRwwHwYD\n"
"VR0jBBgwFoAUc103mIP3PWbtfyK6nZYCpcTCGRwwNQYJYIZIAYb4QgENBCgWJkFs\n"
"d2F5cyBsb29rIG9uIHRoZSBicmlnaHQgc2lkZSBvZiBsaWZlMA8GA1UdEwEB/wQF\n"
"MAMBAf8wDgYDVR0PAQH/BAQDAgEGMBEGCWCGSAGG+EIBAQQEAwICBDAKBggqhkjO\n"
"PQQDAgNIADBFAiB7ZUl2OWFx4CPSxY1jeS2OK9vgeHvVHx6PszwjzN/QTAIhAOhP\n"
"hz/OkvF1o6XD3UWw5nOY63rPMDM0iB/GbpbIz+Jw\n"
"-----END CERTIFICATE-----\n";

stir_shaken_sp_t sp;

#define PRINT_SHAKEN_ERROR_IF_SET \
	if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

/*
 * Mock HTTP transfers in this test.
 */
stir_shaken_status_t stir_shaken_make_http_req_mock(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
	(void) ss;

	printf("\n\nShakening surprise\n\n");
	stir_shaken_assert(http_req != NULL, "http_req is NULL!");

	printf("MOCK HTTP response code to 200 OK\n");
	http_req->response.code = 200;

	if (http_req->response.mem.mem) {
		free(http_req->response.mem.mem);
		http_req->response.mem.mem = NULL;
		http_req->response.mem.size = 0;
	}

	if (ca_verifying_spc_token) {

		int certlen = 0;

		printf("\n\nSTIR_SHAKEN_ACTION_TYPE_CA_CERT_REQ_PA\n\n");

		free(http_req->response.mem.mem);
		certlen = strlen(pa_pem);
		stir_shaken_assert(http_req->response.mem.mem = malloc(certlen + 1), "Malloc failed");
		memset(http_req->response.mem.mem, 0, certlen + 1);
		strncpy(http_req->response.mem.mem, pa_pem, certlen);
		ca_verifying_spc_token = 0;
		return STIR_SHAKEN_STATUS_OK;
	}

	switch (http_req->action) {

		case STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_INIT:

			{
				char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
				char authz_challenge[STIR_SHAKEN_BUFLEN] = { 0 };
				stir_shaken_ca_session_t *session = NULL;
				int authzlen = 0;
				uint8_t use_ssl = 0;


				printf("\n\nSTIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_INIT\n\n");

				stir_shaken_assert(STIR_SHAKEN_STATUS_OK == ca_sp_cert_req_reply_challenge(ss, &ca, (char *) http_req->data, authz_challenge, authz_url, &session, use_ssl), "CA reply to SP cert req failed");
				stir_shaken_assert(!stir_shaken_zstr(authz_challenge), "Authz challenge not created");
				stir_shaken_assert(!stir_shaken_zstr(authz_url), "Authz url not created");
				stir_shaken_assert(session, "CA session not created");

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> (MOCK) Added authorization session to queue\n");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> (MOCK) Sending authorization challenge:\n%s\n", authz_challenge);

				free(http_req->response.mem.mem);
				authzlen = strlen(session->authz_challenge);
				stir_shaken_assert(http_req->response.mem.mem = malloc(authzlen + 1), "Malloc failed");
				memset(http_req->response.mem.mem, 0, authzlen + 1);
				strncpy(http_req->response.mem.mem, authz_challenge, authzlen);
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) HTTP/1.1 201 Created\r\nLocation: %s\r\nContent-Length: %lu\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", authz_url, strlen(authz_challenge), authz_challenge);

				session->state = STI_CA_SESSION_STATE_AUTHZ_SENT;
			}
			break;

		case STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ_DETAILS:

			{
				char spc[STIR_SHAKEN_BUFLEN] = { 0 };
				unsigned long long int sp_code = 0;
				char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
				char *authz_challenge_details = NULL;
				int uri_has_secret = 0;
				unsigned long long secret = 0;
				int authz_secret = 0;
				int authzlen = 0;

				stir_shaken_hash_entry_t *e = NULL;
				stir_shaken_ca_session_t *session = NULL;


				printf("\n\nSTIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ_DETAILS\n\n");

				stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_acme_api_uri_to_spc(ss, http_req->url, STI_CA_ACME_AUTHZ_URL, spc, STIR_SHAKEN_BUFLEN, &sp_code, &uri_has_secret, &secret), "ACME uri to SPC failed");
				stir_shaken_assert(!stir_shaken_zstr(spc), "SPC missing or invalid");

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC (from URI) is: %s\n", spc);

				stir_shaken_assert(e = stir_shaken_hash_entry_find(ca.sessions, STI_CA_SESSIONS_MAX, sp_code), "Session not found");
				stir_shaken_assert(session = e->data, "CA session corrupted");

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Authorization session in progress\n");

				stir_shaken_assert(uri_has_secret <= 0, "Secret should not be set");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Handling authz challenge-details request\n");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC is: %s\n", spc);
				stir_shaken_assert(STI_CA_SESSION_STATE_AUTHZ_SENT == session->state, "Wrong authorization state");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Authorization session challenge was:\n%s\n", session->authz_challenge);

				stir_shaken_assert(STIR_SHAKEN_STATUS_OK == ca_create_session_challenge_details(ss, "pending", spc, authz_url, session), "AUTHZ Failed to produce challenge details");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK)-> Sending challenge details:\n%s\n", session->authz_challenge_details);

				free(http_req->response.mem.mem);
				authzlen = strlen(session->authz_challenge_details);
				stir_shaken_assert(http_req->response.mem.mem = malloc(authzlen + 1), "Malloc failed");
				memset(http_req->response.mem.mem, 0, authzlen + 1);
				strncpy(http_req->response.mem.mem, session->authz_challenge_details, authzlen);
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) HTTP/1.1 200 You are more than welcome. Here is your challenge:\r\nContent-Length: %lu\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", strlen(session->authz_challenge_details), session->authz_challenge_details);

				session->state = STI_CA_SESSION_STATE_AUTHZ_DETAILS_SENT;

			}
			break;

		case STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ:

			{
				char spc[STIR_SHAKEN_BUFLEN] = { 0 };
				char *expires = "never", *validated = "just right now";
				unsigned long long int sp_code = 0;
				int uri_has_secret = 0;
				unsigned long long secret = 0;
				int authz_secret = 0;
				jwt_t *spc_token_jwt = NULL;
				jwt_t *spc_token_verified_jwt = NULL;
				char *token = NULL;
				char *spc_jwt_str = NULL;
				const char *spc_str = NULL;
				const char *spc_token = NULL;
				stir_shaken_cert_t *cert = NULL;
				const char *cert_url = NULL;
				int authzlen = 0;

				stir_shaken_hash_entry_t *e = NULL;
				stir_shaken_ca_session_t *session = NULL;


				printf("\n\nSTIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ\n\n");

				stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_acme_api_uri_to_spc(ss, http_req->url, STI_CA_ACME_AUTHZ_URL, spc, STIR_SHAKEN_BUFLEN, &sp_code, &uri_has_secret, &secret), "ACME uri to SPC failed");
				stir_shaken_assert(!stir_shaken_zstr(spc), "SPC missing or invalid");

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC (from URI) is: %s\n", spc);

				stir_shaken_assert(e = stir_shaken_hash_entry_find(ca.sessions, STI_CA_SESSIONS_MAX, sp_code), "Session not found");
				stir_shaken_assert(session = e->data, "CA session corrupted");

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Authorization session in progress\n");

				if (http_req->type == STIR_SHAKEN_HTTP_REQ_TYPE_GET) {

					if (session->state == STI_CA_SESSION_STATE_POLLING) {

						polling++;

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Handling polling request\n");
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC is: %s\n", spc);

						stir_shaken_assert(!stir_shaken_zstr(session->authz_polling_status), "Oops, no polling status");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Sending polling status...\n");

						free(http_req->response.mem.mem);
						authzlen = strlen(session->authz_polling_status);
						stir_shaken_assert(http_req->response.mem.mem = malloc(authzlen + 1), "Malloc failed");
						memset(http_req->response.mem.mem, 0, authzlen + 1);
						strncpy(http_req->response.mem.mem, session->authz_polling_status, authzlen);
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", strlen(session->authz_polling_status), session->authz_polling_status);

						// continue
						session->state = STI_CA_SESSION_STATE_POLLING;
					} else {

						stir_shaken_assert(0, "Not implemented");
					}

				} else {

					if (polling == 1) {
						// handle STI_CA_SESSION_STATE_AUTHZ_DETAILS_SENT state

						stir_shaken_assert(http_req->type == STIR_SHAKEN_HTTP_REQ_TYPE_POST, "Wrong HTTP req type");
						stir_shaken_assert(uri_has_secret, "Secret missing");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Handling response to authz challenge-details challenge\n");
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC is: %s\n", spc);
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Secret: %llu\n", secret);

						stir_shaken_assert(STI_CA_SESSION_STATE_AUTHZ_DETAILS_SENT == session->state, "Wrong authorization state");
						stir_shaken_assert(secret == session->authz_secret, "Bad secret for this authorization session");
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Secret: OK\n");

						stir_shaken_assert(http_req->data && strlen(http_req->data), "Bad params, empty HTTP body");

						stir_shaken_assert(STIR_SHAKEN_STATUS_OK == ca_session_prepare_polling(ss, http_req->data, spc, expires, validated, session), "AUTHZ request failed, could not produce polling status");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Entering polling state...\n");
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) HTTP/1.1 200 OK, Processing... (you can do polling now)\r\n\r\n");
						session->state = STI_CA_SESSION_STATE_POLLING;
					} else {

						// Checking authotization
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Verifying SPC token...\n");

						ca_verifying_spc_token = 1;

						// Extract SPC token from response token
						stir_shaken_assert(STIR_SHAKEN_STATUS_OK == ca_extract_spc_token_from_authz_response(&ca.ss, http_req->data, &spc_token, &spc_token_jwt), "AUTHZ request failed, authz response has invalid SPC token");
						stir_shaken_assert(spc_token, "Failed to get SPC token");
						stir_shaken_assert(spc_token_jwt, "Failed to get SPC token JWT");

						stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_jwt_verify(&ca.ss, spc_token, &cert, &spc_token_verified_jwt), "SPC token did not pass verification");
						stir_shaken_assert(cert, "Could not get PA cert");
						stir_shaken_destroy_cert(cert);
						free(cert);
						cert = NULL;
						jwt_free(spc_token_jwt);
						spc_token_jwt = NULL;

						stir_shaken_assert(spc_jwt_str = jwt_dump_str(spc_token_verified_jwt, 0), "Cannot dump SPC token JWT");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC token is:\n%s\n", spc_jwt_str);
						jwt_free_str(spc_jwt_str);
						spc_jwt_str = NULL;

						// And just a last check...

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Verifying SPC from token against session...\n");

						stir_shaken_assert(STIR_SHAKEN_STATUS_OK == ca_verify_spc(&ca.ss, spc_token_verified_jwt, session->spc), "SPC from SPC token does not match session SPC");
						fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "(MOCK) -> [+] SP authorized\n");
						session->authorized = 1;
						jwt_free(spc_token_verified_jwt);
						spc_token_verified_jwt = NULL;

authorization_result:

						// Set polling status, keep authorization session life for some time, allowing SP to query polling status and to download cert
						if (session->authz_polling_status) {
							free(session->authz_polling_status);
							session->authz_polling_status = NULL;
						}

						stir_shaken_assert(session->authz_polling_status = stir_shaken_acme_generate_auth_polling_status(&ca.ss, "valid", expires, validated, spc, session->authz_token, session->authz_url), "Failed to set polling status to 'valid'");

						if (!ca.keys.private_key) {

							fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "(MOCK) Loading keys...\n");
							stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_load_keys(ss, &ca.keys.private_key, NULL, ca.private_key_name, NULL, NULL, NULL), "Can't load CA private key");
						}

						if (!ca.cert.x) {
							fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) Loading CA certificate...\n");
							ca.cert.x = stir_shaken_load_x509_from_file(&ca.ss, ca.cert_name);
							stir_shaken_assert(ca.cert.x, "Error loading CA certificate");
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) Issuing STI certificate...\n");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t -> Loading CSR...\n");
						stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_load_x509_req_from_mem(&ca.ss, &session->sp.csr.req, session->sp.csr.pem), "Error loading CSR");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t -> Generating cert...\n");
						stir_shaken_assert(session->sp.cert.x = stir_shaken_generate_x509_end_entity_cert_from_csr(&ca.ss, ca.cert.x, ca.keys.private_key, ca.issuer_c, ca.issuer_cn, session->sp.csr.req, ca.serial, ca.expiry_days, ca.tn_auth_list_uri), "Error creating SP certificate");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t -> Configuring certificate...\n");
						snprintf(session->sp.cert_name, sizeof(session->sp.cert_name), "sp_%s_%llu_%zu.pem", spc, secret, time(NULL));

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t -> Saving certificate (%s)...\n", session->sp.cert_name);
						stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_x509_to_disk(&ca.ss, session->sp.cert.x, session->sp.cert_name), "Error saving SP certificate");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> [++] STI certificate ready for download\n");

						if (spc_token_jwt) {
							jwt_free(spc_token_jwt);
							spc_token_jwt = NULL;
						}

						if (spc_token_verified_jwt) {
							jwt_free(spc_token_verified_jwt);
							spc_token_verified_jwt = NULL;
						}

						session->state = STI_CA_SESSION_STATE_POLLING;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "(MOCK) === OK\n");

				}
			}
			break;

		case STIR_SHAKEN_ACTION_TYPE_SP_CERT_DOWNLOAD:
			{
				char spc[STIR_SHAKEN_BUFLEN] = { 0 };
				unsigned long long int sp_code = 0;
				char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
				char *authz_challenge_details = NULL;
				int uri_has_secret = 0;
				unsigned long long secret = 0;
				int authz_secret = 0;
				char spcbuf[STIR_SHAKEN_BUFLEN] = { 0 };
				unsigned char cert[STIR_SHAKEN_BUFLEN] = { 0 };
				unsigned char cert_b64[STIR_SHAKEN_BUFLEN] = { 0 };
				int certlen = STIR_SHAKEN_BUFLEN;
				int cert_b64_len = STIR_SHAKEN_BUFLEN;

				stir_shaken_hash_entry_t *e = NULL;
				stir_shaken_ca_session_t *session = NULL;


				printf("\n\nSTIR_SHAKEN_ACTION_TYPE_SP_CERT_DOWNLOAD\n\n");

				stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_acme_api_uri_to_spc(ss, http_req->url, STI_CA_ACME_CERT_REQ_URL, spc, STIR_SHAKEN_BUFLEN, &sp_code, &uri_has_secret, &secret), "ACME uri to SPC failed");
				stir_shaken_assert(!stir_shaken_zstr(spc), "SPC missing or invalid");

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC (from URI) is: %s\n", spc);

				stir_shaken_assert(e = stir_shaken_hash_entry_find(ca.sessions, STI_CA_SESSIONS_MAX, sp_code), "Session not found");
				stir_shaken_assert(session = e->data, "CA session corrupted");

				stir_shaken_assert(!uri_has_secret, "Secret should not be set");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Handling authz challenge-details request\n");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> SPC is: %s\n", spc);
				stir_shaken_assert(STI_CA_SESSION_STATE_POLLING == session->state, "Wrong authorization state");

				stir_shaken_assert(session->authorized, "Bad cert request, session is not authorized");

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) -> Authorization session in progress\n");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t-> Replying to STI-SP certificate download request...\n");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t\t-> Loading STI-SP certificate...\n");

				stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_get_x509_raw(&ca.ss, session->sp.cert.x, cert, &certlen), "Error loading SP certificate");
				stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_b64_encode(cert, certlen, cert_b64, cert_b64_len), "Error Base 64 encoding SP certificate");;

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t\t\t-> STI-SP certificate is:\n%s\n", cert);

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) \t\t-> Sending STI-SP certificate...\n");
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", strlen((const char *)cert), cert);

				free(http_req->response.mem.mem);
				certlen = strlen((char *)cert);
				stir_shaken_assert(http_req->response.mem.mem = malloc(certlen + 1), "Malloc failed");
				memset(http_req->response.mem.mem, 0, certlen + 1);
				strncpy(http_req->response.mem.mem, (char *) cert, certlen);

				session->state = STI_CA_SESSION_STATE_DONE;

				stir_shaken_hash_entry_remove(ca.sessions, STI_CA_SESSIONS_MAX, sp_code, STIR_SHAKEN_HASH_TYPE_SHALLOW_AUTOFREE);
			}
			break;

			// etc.

		default:
			printf("\n\nSTIR_SHAKEN_ACTION_TYPE unknown\n\n");
			stir_shaken_assert(0, "Bad action type!");
			return STIR_SHAKEN_STATUS_TERM;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_unit_test_sp_cert_req(void)
{
	EVP_PKEY *pkey = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;

	stir_shaken_http_req_t http_req = { 0 };
	const char *kid = NULL, *nonce = NULL, *nb = NULL, *na = NULL;
	char spc[STIR_SHAKEN_BUFLEN] = { 0 };
	char url[STIR_SHAKEN_BUFLEN] = { 0 };
	char *json = NULL;
	char *spc_token = NULL;


	sprintf(sp.private_key_name, "%s%c%s", path, '/', "all_sp_private_key.pem");
	sprintf(sp.public_key_name, "%s%c%s", path, '/', "all_sp_public_key.pem");
	sprintf(sp.csr_name, "%s%c%s", path, '/', "all_sp_csr.pem");
	sprintf(sp.cert_name, "%s%c%s", path, '/', "all_sp_cert.crt");


	// 1
	// SP obtains SPC and SPC token from PA and can now construct CSR

	printf("SP: Generate SP keys\n");

	// Generate SP keys
	sp.keys.priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	status = stir_shaken_generate_keys(&ss, &sp.keys.ec_key, &sp.keys.private_key, &sp.keys.public_key, sp.private_key_name, sp.public_key_name, sp.keys.priv_raw, &sp.keys.priv_raw_len);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, failed to generate keys...");
	stir_shaken_assert(sp.keys.ec_key != NULL, "Err, failed to generate EC key\n\n");
	stir_shaken_assert(sp.keys.private_key != NULL, "Err, failed to generate private key");
	stir_shaken_assert(sp.keys.public_key != NULL, "Err, failed to generate public key");

	printf("SP: Create CSR\n");
	sp.code = 1;
	sprintf(spc, "%d", sp.code);
	snprintf(sp.subject_c, STIR_SHAKEN_BUFLEN, "US");
	snprintf(sp.subject_cn, STIR_SHAKEN_BUFLEN, "NewSTI-SP Number 1");

	status = stir_shaken_generate_csr(&ss, sp.code, &sp.csr.req, sp.keys.private_key, sp.keys.public_key, sp.subject_c, sp.subject_cn);
	PRINT_SHAKEN_ERROR_IF_SET
		stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Err, generating CSR");

	// Reqeust STI certificate

	kid = NULL;
	nonce = NULL;
	sprintf(url, "https://ca.shaken.signalwire.cloud/sti-ca/acme/cert");
	nb = "01 Apr 2020";
	na = "01 Apr 2021";

	// Set SPC token to this:
	// cat test/ref/sp/spc_token.txt 
	// SPC token encoded:
	// 
	// eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIFRlc3QiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJwYS5zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.l61Y8K1bwZw9APXsrAQPZVPAkx5UIucwNKzRWxn0N5DcdVWaEgA_i5tW65f_aeqA46CTP789l4o6rFpiN7IZUA
	// 
	// SPC token decoded:
	// 
	// 
	// {
	//     "alg": "ES256",
	//     "issuer": "SignalWire STI-PA Test",
	//     "typ": "JWT",
	//     "x5u": "pa.shaken.signalwire.cloud/pa.pem"
	// }
	// .
	// {
	//     "notAfter": "1 year from now",
	//     "notBefore": "today",
	//     "spc": "1",
	//    "type": "spc-token"
	// }


	spc_token = "eyJhbGciOiJFUzI1NiIsImlzc3VlciI6IlNpZ25hbFdpcmUgU1RJLVBBIFRlc3QiLCJ0eXAiOiJKV1QiLCJ4NXUiOiJwYS5zaGFrZW4uc2lnbmFsd2lyZS5jbG91ZC9wYS5wZW0ifQ.eyJub3RBZnRlciI6IjEgeWVhciBmcm9tIG5vdyIsIm5vdEJlZm9yZSI6InRvZGF5Iiwic3BjIjoiMSIsInR5cGUiOiJzcGMtdG9rZW4ifQ.l61Y8K1bwZw9APXsrAQPZVPAkx5UIucwNKzRWxn0N5DcdVWaEgA_i5tW65f_aeqA46CTP789l4o6rFpiN7IZUA";
	http_req.url = strdup(url);
	http_req.remote_port = 8082;

	status = stir_shaken_sp_cert_req_ex(&ss, &http_req, kid, nonce, sp.csr.req, nb, na, spc, sp.keys.priv_raw, sp.keys.priv_raw_len, NULL, spc_token);
	if (status != STIR_SHAKEN_STATUS_OK) {
		printf("STIR-Shaken: Failed to execute cert request\n");
		PRINT_SHAKEN_ERROR_IF_SET
	}
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == status, "Test-it-all cert request failed\n");

	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_load_x509_from_mem(&ss, &sp.cert.x, NULL, http_req.response.mem.mem), "Failed to load X509 from memory");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_x509_to_disk(&ss, sp.cert.x, "test/run/all_sp.pem"), "Failed to save the certificate");


	// SP cleanup	
	stir_shaken_sp_destroy(&sp);
	stir_shaken_destroy_http_request(&http_req);

	return STIR_SHAKEN_STATUS_OK;
}

int main(int argc, char **argv)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_do_init(NULL, NULL, NULL, STIR_SHAKEN_LOGLEVEL_HIGH), "Cannot init lib");

	if (argc == 1) {

		// MOCK http transfers by default
		stir_shaken_make_http_req = stir_shaken_make_http_req_mock;

	} else if (argc > 1 && !stir_shaken_zstr(argv[1]) && !strcmp(argv[1], "nomock")) {

		// do not MOCK
	} else {
		printf("ERR: this program takes no argument or one argument which must be 'nomock'\n");
		exit(EXIT_FAILURE);
	}

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {

			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_sp_cert_req() != STIR_SHAKEN_STATUS_OK) {

		return -2;
	}

	stir_shaken_do_deinit();
	stir_shaken_ca_destroy(&ca);

	printf("OK\n");

	return 0;
}
