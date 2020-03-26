#include "stir_shaken.h"
#include "mongoose.h"


pthread_mutex_t big_fat_lock = PTHREAD_MUTEX_INITIALIZER;

void stir_shaken_ca_destroy(stir_shaken_ca_t *ca)
{
	if (!ca) return;
	stir_shaken_hash_destroy(ca->sessions, STI_CA_SESSIONS_MAX, STIR_SHAKEN_HASH_TYPE_SHALLOW);
	stir_shaken_destroy_keys(&ca->keys);
}

static int ca_http_method(struct http_message *m)
{
	if (!m) return 13;
	if (!strncmp(m->method.p, "GET", 3)) {
		return STIR_SHAKEN_HTTP_REQ_TYPE_GET;
	}
	if (!strncmp(m->method.p, "POST", 4)) {
		return STIR_SHAKEN_HTTP_REQ_TYPE_POST;
	}
	if (!strncmp(m->method.p, "HEAD", 4)) {
		return STIR_SHAKEN_HTTP_REQ_TYPE_HEAD;
	}
	if (!strncmp(m->method.p, "PUT", 3)) {
		return STIR_SHAKEN_HTTP_REQ_TYPE_PUT;
	}
	return 1000;
}

typedef void handler_t(struct mg_connection *nc, int event, void *hm, void *d);

typedef struct event_handler_s {
	char *uri;
	handler_t *f;
	int accepts_params;
} event_handler_t;

#define HANDLERS_N 10
event_handler_t event_handlers[HANDLERS_N];

static stir_shaken_status_t register_uri_handler(const char *uri, void *handler, int accepts_params)
{
	int i = 0;
	event_handler_t *e = NULL;

	while (i < HANDLERS_N) {

		e = &event_handlers[i];
		if (stir_shaken_zstr(e->uri)) {
			e->uri = strdup(uri);
			e->f = handler;
			e->accepts_params = accepts_params;
			return STIR_SHAKEN_STATUS_OK;
		}
		++i;
	}

	return STIR_SHAKEN_STATUS_FALSE;
}

static event_handler_t* handler_registered(struct mg_str *uri)
{
	int i = 0;
	event_handler_t *e = NULL;

	while (i < HANDLERS_N) {

		e = &event_handlers[i];
		if (e->uri) {
			if (e->accepts_params) {
				if (strstr(uri->p, e->uri)) {
					return e;
				}
			} else {
				if (!mg_vcmp(uri, e->uri)) {
					return e;
				}
			}
		}
		++i;
	}

	return NULL;
}

static void unregister_handlers(void)
{
	int i = 0;
	event_handler_t *e = NULL;

	while (i < HANDLERS_N) {

		e = &event_handlers[i];
		if (e->uri) {
			free(e->uri);
			e->uri = NULL;
			memset(e, 0, sizeof(*e));
		}
		++i;
	}
}

static void close_http_connection_with_error(struct mg_connection *nc, struct mbuf *io, const char *error_desc)
{
	if (nc) {
		if (stir_shaken_zstr(error_desc)) {
			mg_printf(nc, "HTTP/1.1 %s Not Found\r\n\r\n", STIR_SHAKEN_HTTP_REQ_404_NOT_FOUND);
		} else {
			char error_phrase[STIR_SHAKEN_BUFLEN] = { 0 };
			stir_shaken_error_desc_to_http_error_phrase(error_desc, error_phrase, STIR_SHAKEN_BUFLEN);
			mg_printf(nc, "HTTP/1.1 %s %s\r\n\r\n", STIR_SHAKEN_HTTP_REQ_404_NOT_FOUND, error_phrase);
		}
	}
	if (nc) mg_send_http_chunk(nc, "", 0);
	if (io) mbuf_remove(io, io->len);
	if (nc) nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void close_http_connection(struct mg_connection *nc, struct mbuf *io)
{
	if (nc) mg_send_http_chunk(nc, "", 0);
	if (io) mbuf_remove(io, io->len);
	if (nc) nc->flags |= MG_F_SEND_AND_CLOSE;
}

static stir_shaken_ca_session_t* stir_shaken_ca_session_create(size_t sp_code, char *authz_challenge, void *csr_pem)
{
	stir_shaken_ca_session_t *session = malloc(sizeof(stir_shaken_ca_session_t));

	if (!session)
		return NULL;

	memset(session, 0, sizeof(*session));
	session->spc = sp_code;
	session->authz_challenge = strdup(authz_challenge);
	session->state = STI_CA_SESSION_STATE_INIT;
	session->sp.csr.pem = strdup(csr_pem);
	session->ts = time(NULL);
	return session;
}

static void stir_shaken_ca_session_dctor(void *o)
{
	stir_shaken_ca_session_t *session = (stir_shaken_ca_session_t *) o;
	if (!session) return;
	if (session->nonce) {
		free(session->nonce);
		session->nonce = NULL;
	}
	if (session->authz_url) {
		free(session->authz_url);
		session->authz_url = NULL;
	}
	if (session->authz_token) {
		free(session->authz_token);
		session->authz_token = NULL;
	}
	if (session->authz_challenge) {
		free(session->authz_challenge);
		session->authz_challenge = NULL;
	}

	stir_shaken_sp_destroy(&session->sp);

	if (session->authz_challenge_details) {
		free(session->authz_challenge_details);
		session->authz_challenge_details = NULL;
	}

	fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "-> Session %zu/%llu deleted ;~\n", session->spc, session->authz_secret);

	memset(session, 0, sizeof(*session));
	return;
}

stir_shaken_status_t ca_session_expired(stir_shaken_ca_session_t *session)
{
	if (!session) return STIR_SHAKEN_STATUS_TERM;
	return (stir_shaken_time_elapsed_s(session->ts, time(NULL)) > STI_CA_SESSION_EXPIRY_SECONDS ? STIR_SHAKEN_STATUS_OK : STIR_SHAKEN_STATUS_FALSE);
}

#define CA_REQUIRE_SESSION_STATE_(required, actual) if ((required) != (actual)) { \
	stir_shaken_set_error(&ca->ss, "Wrong session state", STIR_SHAKEN_ERROR_ACME_SESSION_WRONG_STATE); \
	goto fail; \
}

static void ca_handle_bad_request(struct mg_connection *nc, int event, void *hm, void *d)
{
	fprintif(1, "\n=== Handling: bad request...\n");
	return;
}

static void ca_handle_api_account(struct mg_connection *nc, int event, void *hm, void *d)
{
	struct http_message *m = (struct http_message*) hm;
	stir_shaken_ca_t *ca = (stir_shaken_ca_t*) d;
	int http_method = STIR_SHAKEN_HTTP_REQ_TYPE_POST; 
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n=== Handling API call: %s...\n", STI_CA_ACME_NEW_ACCOUNT_URL);
	if (!m || !nc || !ca) {
		stir_shaken_set_error(&ca->ss, "Bad params, missing HTTP message, connection, and/or ca", STIR_SHAKEN_ERROR_ACME);
		//goto fail;
	}
	http_method = ca_http_method(m);
	if (http_method != STIR_SHAKEN_HTTP_REQ_TYPE_POST) {
		stir_shaken_set_error(&ca->ss, "Bad request, only POST supported for this API", STIR_SHAKEN_ERROR_ACME_BAD_REQUEST);
		//goto fail;
	}
	return;
}

static void ca_handle_api_nonce(struct mg_connection *nc, int event, void *hm, void *d)
{
	struct http_message *m = (struct http_message*) hm;
	struct mbuf *io = NULL;
	stir_shaken_context_t ss = { 0 };
	stir_shaken_ca_t *ca = (stir_shaken_ca_t*) d;
	struct mg_str nonce_api_url = mg_mk_str(STI_CA_ACME_NONCE_REQ_URL);
	uuid_t uuid = { 0 };
	char nonce[STIR_SHAKEN_BUFLEN] = { 0 };
	int http_method = STIR_SHAKEN_HTTP_REQ_TYPE_POST; 
	stir_shaken_error_t error = STIR_SHAKEN_ERROR_GENERAL;
	const char *error_desc = NULL;


	if (!m || !nc || !ca) {
		stir_shaken_set_error(&ca->ss, "Bad params, missing HTTP message, connection, and/or ca", STIR_SHAKEN_ERROR_ACME);
		goto fail;
	}

	http_method = ca_http_method(m);
	io = &nc->recv_mbuf;

	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n=== Handling API [%d] call:\n%s\n", http_method, STI_CA_ACME_NONCE_REQ_URL);
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n=== Message Body:\n%s\n", m->body.p);


	switch (event) {

		case MG_EV_HTTP_REQUEST:

			{
				if (http_method != STIR_SHAKEN_HTTP_REQ_TYPE_HEAD && http_method != STIR_SHAKEN_HTTP_REQ_TYPE_GET) {
					stir_shaken_set_error(&ca->ss, "Bad request, only HEAD or GET supported for this API", STIR_SHAKEN_ERROR_ACME_BAD_REQUEST);
					goto fail;
				}

				uuid_generate_random(uuid);
				uuid_unparse_upper(uuid, nonce);

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Sending nonce:\n%s\n", nonce);

				mg_printf(nc, "HTTP/1.1 200 OK\r\nReplay-Nonce: %s\r\nCache-Control: no-store\r\n\r\n", nonce);


				close_http_connection(nc, io);
				fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "=== OK\n");

				break;

				case MG_EV_RECV:
				break;

				default:
				break;
			}
	}

	stir_shaken_clear_error(&ca->ss);
	return;

fail:

	if (ca && stir_shaken_is_error_set(&ca->ss)) {
		error_desc = stir_shaken_get_error(&ca->ss, &error);
	}
	close_http_connection_with_error(nc, io, error_desc);

	stir_shaken_set_error(&ca->ss, "API NONCE request failed", STIR_SHAKEN_ERROR_ACME);
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "=== FAIL\n");
	return;
}

/*
 * Data posted by SP should be JWT of the form:
 *
 * {
 *	"protected": base64url({
 *		"alg": "ES256",
 *		"kid": " https://sti-ca.com/acme/acct/1",
 *		"nonce": "5XJ1L3lEkMG7tR6pA00clA",
 *		"url": " https://sti-ca.com/acme/new-order"
 *		})
 *	"payload": base64url({
 *		"csr": "5jNudRx6Ye4HzKEqT5...FS6aKdZeGsysoCo4H9P",
 *		"notBefore": "2016-01-01T00:00:00Z",
 *		"notAfter": "2016-01-08T00:00:00Z"
 *		}),
 *	"signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
 * }
*/
static void ca_handle_api_cert(struct mg_connection *nc, int event, void *hm, void *d)
{
	struct http_message *m = (struct http_message*) hm;
	struct mbuf *io = NULL;
	stir_shaken_context_t ss = { 0 };
	stir_shaken_ca_t *ca = (stir_shaken_ca_t*) d;
	cJSON *json = NULL;
	jwt_t *jwt = NULL;
	struct mg_str cert_api_url = mg_mk_str(STI_CA_ACME_CERT_REQ_URL);

	const char *spc = NULL;
	char *pCh = NULL;
	unsigned long long  sp_code;
	const char *csr_b64 = NULL;
	char csr[STIR_SHAKEN_BUFLEN] = { 0 };
	int csr_len = 0;
	char *token = NULL;
	char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
	char *expires = "2029-03-01T14:09:00Z";
	char *nb = "2019-01-01T00:00:00Z";
	char *na = "2029-01-01T00:00:00Z";
	char *authz_challenge = NULL;

	char *nonce = "MYAuvOpaoIiywTezizk5vw";
	X509_REQ *req = NULL;
	stir_shaken_error_t error = STIR_SHAKEN_ERROR_GENERAL;
	const char *error_desc = NULL;
	stir_shaken_hash_entry_t *e = NULL;
	stir_shaken_ca_session_t *session = NULL;
	int http_method = STIR_SHAKEN_HTTP_REQ_TYPE_POST; 


	if (!m || !nc || !ca) {
		stir_shaken_set_error(&ca->ss, "Bad params, missing HTTP message, connection, and/or ca", STIR_SHAKEN_ERROR_ACME);
		goto fail;
	}

	http_method = ca_http_method(m);
	io = &nc->recv_mbuf;

	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n=== Handling API [%d] call:\n%s\n", http_method, STI_CA_ACME_CERT_REQ_URL);
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n=== Message Body:\n%s\n", m->body.p);
	
	
	switch (event) {

		case MG_EV_HTTP_REQUEST:

			{
				if (STIR_SHAKEN_HTTP_REQ_TYPE_POST == http_method) {
					
					if ((EINVAL == jwt_decode(&jwt, m->body.p, NULL, 0)) || !jwt) {
						stir_shaken_set_error(&ca->ss, "Cannot parse message body into JWT", STIR_SHAKEN_ERROR_ACME);
						goto fail;
					}

					csr_b64 = jwt_get_grant(jwt, "csr");
					if (stir_shaken_zstr(csr_b64)) {
						stir_shaken_set_error(&ca->ss, "JWT posted by SP is missing CSR", STIR_SHAKEN_ERROR_ACME);
						goto fail;
					}

					// Read SPC from JWT (ATIS standard doesn't reqire SPC to be set on JWT)
					spc = jwt_get_grant(jwt, "spc");
					if (stir_shaken_zstr(spc)) {
						stir_shaken_set_error(&ca->ss, "Cert request SPC (TNAuthList extension missing?)", STIR_SHAKEN_ERROR_ACME);
						goto fail;
					}

					sp_code = strtoul(spc, &pCh, 10); 
					if (sp_code > 0x10000 - 1) { 
						stir_shaken_set_error(&ca->ss, "SPC number too big", STIR_SHAKEN_ERROR_ACME_SPC_TOO_BIG);
						goto fail; 
					}

					if (*pCh != '\0') { 
						stir_shaken_set_error(&ca->ss, "SPC invalid", STIR_SHAKEN_ERROR_ACME_SPC_INVALID);
						goto fail; 
					}

					if (stir_shaken_b64_decode(csr_b64, csr, sizeof(csr)) < 1 || stir_shaken_zstr(csr)) {
						stir_shaken_set_error(&ca->ss, "Cannot decode CSR from base 64", STIR_SHAKEN_ERROR_ACME);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> CSR is:\n%s\n", csr);
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC is: %s\n", spc);

					req = stir_shaken_load_x509_req_from_pem(&ca->ss, csr);
					if (!req) {
						stir_shaken_set_error(&ca->ss, "Cannot load CSR into SSL", STIR_SHAKEN_ERROR_ACME);
						goto fail;
					}

					// This check probably should be disabled, as it opens possibility of DoS attack
					e = stir_shaken_hash_entry_find(ca->sessions, STI_CA_SESSIONS_MAX, sp_code);
					if (e) {

						session = e->data;
						if (!session) {
							stir_shaken_set_error(&ca->ss, "Oops, session not set", STIR_SHAKEN_ERROR_ACME_SESSION_NOT_SET);
							goto fail;
						}

						if (STIR_SHAKEN_STATUS_OK != ca_session_expired(session)) {
							fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Authorization already in progress...\n");
							stir_shaken_set_error(&ca->ss, "Bad request, authorization already in progress", STIR_SHAKEN_ERROR_ACME_BAD_REQUEST);
							goto fail;
						}

						// expired, remove
						stir_shaken_hash_entry_remove(ca->sessions, STI_CA_SESSIONS_MAX, sp_code, STIR_SHAKEN_HASH_TYPE_SHALLOW_AUTOFREE);
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Requesting authorization...\n");

					// TODO generate 'expires'
					// TODO generate 'nb'
					// TODO generate 'na'
					// TODO generate Replay-Nonce
					snprintf(authz_url, STIR_SHAKEN_BUFLEN, "http://%s%s/%s", STI_CA_ACME_ADDR, STI_CA_ACME_AUTHZ_URL, spc);
					authz_challenge = stir_shaken_acme_generate_auth_challenge(&ca->ss, "pending", expires, csr, nb, na, authz_url);
					if (stir_shaken_zstr(authz_challenge)) {
						stir_shaken_set_error(&ca->ss, "Failed to create authorization challenge", STIR_SHAKEN_ERROR_ACME);
						goto fail;
					}

					// TODO queue challenge task/job
					session = stir_shaken_ca_session_create(sp_code, authz_challenge, csr);
					if (!session) {
						stir_shaken_set_error(&ca->ss, "Cannot create authorization session", STIR_SHAKEN_ERROR_ACME_SESSION_CREATE);
						goto fail;
					}

					e = stir_shaken_hash_entry_add(ca->sessions, STI_CA_SESSIONS_MAX, sp_code, session, sizeof(*session), stir_shaken_ca_session_dctor, STIR_SHAKEN_HASH_TYPE_SHALLOW_AUTOFREE);
					if (!e) {
						stir_shaken_set_error(&ca->ss, "Oops. Failed to queue new session", STIR_SHAKEN_ERROR_ACME_SESSION_ENQUEUE);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Added authorization session to queue\n");
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Sending authorization challenge:\n%s\n", authz_challenge);

					mg_printf(nc, "HTTP/1.1 201 Created\r\nReplay-Nonce: %s\r\nLocation: %s\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", nonce, authz_url, strlen(authz_challenge), authz_challenge);

					session->state = STI_CA_SESSION_STATE_AUTHZ_SENT;

				} else {

					int uri_has_secret = 0;
					unsigned long long secret = 0;
					char spcbuf[STIR_SHAKEN_BUFLEN] = { 0 };
					unsigned char cert[STIR_SHAKEN_BUFLEN] = { 0 };
					unsigned char cert_b64[STIR_SHAKEN_BUFLEN] = { 0 };
					int certlen = STIR_SHAKEN_BUFLEN;
					int cert_b64_len = STIR_SHAKEN_BUFLEN;

					// Handle certificate download request

					if ((STIR_SHAKEN_STATUS_OK != stir_shaken_acme_api_uri_to_spc(&ca->ss, m->uri.p, cert_api_url.p, spcbuf, STIR_SHAKEN_BUFLEN, &uri_has_secret, &secret)) || stir_shaken_zstr(spcbuf)) {
						stir_shaken_set_error(&ca->ss, "Bad cert request, SPC is missing", STIR_SHAKEN_ERROR_ACME_CERT);
						goto fail;
					}

					sp_code = strtoul(spcbuf, &pCh, 10); 
					if (sp_code > 0x10000 - 1) { 
						stir_shaken_set_error(&ca->ss, "SPC number too big", STIR_SHAKEN_ERROR_ACME_SPC_TOO_BIG);
						goto fail; 
					}

					if (*pCh != '\0') { 
						stir_shaken_set_error(&ca->ss, "SPC invalid", STIR_SHAKEN_ERROR_ACME_SPC_INVALID);
						goto fail; 
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC is: %s\n", spcbuf);

					e = stir_shaken_hash_entry_find(ca->sessions, STI_CA_SESSIONS_MAX, sp_code);
					if (!e) {
						stir_shaken_set_error(&ca->ss, "Authorization session for this SPC does not exist", STIR_SHAKEN_ERROR_ACME_SESSION_NOTFOUND);
						goto fail;
					}

					session = e->data;
					if (!session) {
						stir_shaken_set_error(&ca->ss, "Oops. Authorization session not set", STIR_SHAKEN_ERROR_ACME_SESSION_NOT_SET);
						goto fail;
					}
					
					if (STI_CA_SESSION_STATE_POLLING != session->state) {
						stir_shaken_set_error(&ca->ss, "Wrong authorization state", STIR_SHAKEN_ERROR_ACME_SESSION_WRONG_STATE);
						goto fail;
					}
					
					if (!session->authorized) {
						stir_shaken_set_error(&ca->ss, "Bad cert request, session is not authorized", STIR_SHAKEN_ERROR_ACME_SESSION_NOT_AUTHORIZED);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Authorization session in progress\n");
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> Replying to STI-SP certificate download request...\n");
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t\t-> Loading STI-SP certificate...\n");

					if (STIR_SHAKEN_STATUS_OK != stir_shaken_get_x509_raw(&ca->ss, session->sp.cert.x, cert, &certlen)) {
						stir_shaken_set_error(&ca->ss, "Error loading SP certificate", STIR_SHAKEN_ERROR_ACME_CERT);
						goto fail;
					}

					if (STIR_SHAKEN_STATUS_OK != stir_shaken_b64_encode(cert, certlen, cert_b64, cert_b64_len)) {
						stir_shaken_set_error(&ca->ss, "Error Base 64 encoding SP certificate", STIR_SHAKEN_ERROR_ACME_CERT);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t\t\t-> STI-SP certificate is:\n%s\n", cert);

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t\t-> Sending STI-SP certificate...\n");
					mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", strlen(cert), cert);

					session->state = STI_CA_SESSION_STATE_DONE;

					stir_shaken_hash_entry_remove(ca->sessions, STI_CA_SESSIONS_MAX, sp_code, STIR_SHAKEN_HASH_TYPE_SHALLOW_AUTOFREE);

				}

				close_http_connection(nc, io);
				fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "=== OK\n");
			}

			break;
		
		case MG_EV_RECV:
			break;

		default:
			break;
	}

	if (json) {
		cJSON_Delete(json);
		json = NULL;
	}

	if (jwt) {
		jwt_free(jwt);
		jwt = NULL;
	}

	if (authz_challenge) {
		free(authz_challenge);
		authz_challenge = NULL;
	}

	if (req) {
		X509_REQ_free(req);
		req = NULL;
	}

	stir_shaken_clear_error(&ca->ss);
	return;

fail:

	if (ca && stir_shaken_is_error_set(&ca->ss)) {
		error_desc = stir_shaken_get_error(&ca->ss, &error);
	}
	close_http_connection_with_error(nc, io, error_desc);

	if (json) {
		cJSON_Delete(json);
		json = NULL;
	}

	if (authz_challenge) {
		free(authz_challenge);
		authz_challenge = NULL;
	}
	
	if (req) {
		X509_REQ_free(req);
		req = NULL;
	}

	stir_shaken_set_error(&ca->ss, "API CERT request failed", STIR_SHAKEN_ERROR_ACME);
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "=== FAIL\n");
	return;
}

static void ca_handle_api_authz(struct mg_connection *nc, int event, void *hm, void *d)
{
	struct http_message *m = (struct http_message*) hm;
	stir_shaken_ca_t *ca = (stir_shaken_ca_t*) d;
	struct mg_str authz_api_url = mg_mk_str(STI_CA_ACME_AUTHZ_URL);
	struct mbuf *io = NULL;
	
	char spc[STIR_SHAKEN_BUFLEN] = { 0 };
	char *pCh = NULL;
	unsigned long long  sp_code;
	char *token = NULL;
	char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
	char *authz_challenge_details = NULL;
	const char *error_desc = NULL;
	stir_shaken_error_t error = STIR_SHAKEN_ERROR_GENERAL;
	int uri_has_secret = 0;
	unsigned long long secret = 0;
	int authz_secret = 0;
	
	stir_shaken_hash_entry_t *e = NULL;
	stir_shaken_ca_session_t *session = NULL;
	int http_method = STIR_SHAKEN_HTTP_REQ_TYPE_POST;
	
	
	if (!m || !nc || !ca) {
		stir_shaken_set_error(&ca->ss, "Bad params, missing HTTP message, connection, and/or ca", STIR_SHAKEN_ERROR_ACME);
		goto fail;
	}

	http_method = ca_http_method(m);

	io = &nc->recv_mbuf;
	
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n=== Handling API [%d] call: %s...\n", http_method, STI_CA_ACME_AUTHZ_URL);
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "\n=== Message Body:\n%s\n", m->body.p);
	
	switch (event) {

		case MG_EV_HTTP_REQUEST:

			{
				if ((STIR_SHAKEN_STATUS_OK != stir_shaken_acme_api_uri_to_spc(&ca->ss, m->uri.p, authz_api_url.p, spc, STIR_SHAKEN_BUFLEN, &uri_has_secret, &secret)) || stir_shaken_zstr(spc)) {
					stir_shaken_set_error(&ca->ss, "Bad AUTHZ request, SPC is missing", STIR_SHAKEN_ERROR_ACME_AUTHZ_SPC);
					goto fail;
				}
				
				sp_code = strtoul(spc, &pCh, 10); 
				if (sp_code > 0x10000 - 1) { 
					stir_shaken_set_error(&ca->ss, "SPC number too big", STIR_SHAKEN_ERROR_ACME_SPC_TOO_BIG);
					goto fail; 
				}

				if (*pCh != '\0') { 
					stir_shaken_set_error(&ca->ss, "SPC invalid", STIR_SHAKEN_ERROR_ACME_SPC_INVALID);
					goto fail; 
				}

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC is: %s\n", spc);

				e = stir_shaken_hash_entry_find(ca->sessions, STI_CA_SESSIONS_MAX, sp_code);
				if (!e) {
					stir_shaken_set_error(&ca->ss, "Authorization session for this SPC does not exist", STIR_SHAKEN_ERROR_ACME_SESSION_NOTFOUND);
					goto fail;
				}

				session = e->data;
				if (!session) {
					stir_shaken_set_error(&ca->ss, "Oops. Authorization session not set", STIR_SHAKEN_ERROR_ACME_SESSION_NOT_SET);
					goto fail;
				}

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Authorization session in progress\n");

				if (http_method == STIR_SHAKEN_HTTP_REQ_TYPE_GET) {

					if (STI_CA_SESSION_STATE_POLLING == session->state) {

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Handling polling request\n");
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC is: %s\n", spc);

						if (!session->authz_polling_status) {
							stir_shaken_set_error(&ca->ss, "Oops, no polling status", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
							goto fail;
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Sending polling status...\n");

						mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", strlen(session->authz_polling_status), session->authz_polling_status);

						// continue
						session->state = STI_CA_SESSION_STATE_POLLING;

					} else {

						if (uri_has_secret > 0) {
							stir_shaken_set_error(&ca->ss, "Bad request, Secret is set", STIR_SHAKEN_ERROR_ACME_BAD_REQUEST);
							goto fail;
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Handling authz challenge-details request\n");
						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC is: %s\n", spc);

						if (STI_CA_SESSION_STATE_AUTHZ_SENT != session->state) {
							stir_shaken_set_error(&ca->ss, "Wrong authorization state", STIR_SHAKEN_ERROR_ACME_SESSION_WRONG_STATE);
							goto fail;
						}

						e = stir_shaken_hash_entry_find(ca->sessions, STI_CA_SESSIONS_MAX, sp_code);
						if (!e) {
							stir_shaken_set_error(&ca->ss, "Authorization session for this SPC does not exist", STIR_SHAKEN_ERROR_ACME_SESSION_NOTFOUND);
							goto fail;
						}

						session = e->data;
						if (!session) {
							stir_shaken_set_error(&ca->ss, "Oops. Authorization session not set", STIR_SHAKEN_ERROR_ACME_SESSION_NOT_SET);
							goto fail;
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Authorization session challenge was:\n%s\n", session->authz_challenge);

						// TODO generate random token
						token = "DGyRejmCefe7v4NfDGDKfA";


						// TODO process authz secrets
						authz_secret = rand() % (1 << 16);
						snprintf(authz_url, STIR_SHAKEN_BUFLEN, "http://%s%s/%s/%d", STI_CA_ACME_ADDR, STI_CA_ACME_AUTHZ_URL, spc, authz_secret);

						authz_challenge_details = stir_shaken_acme_generate_auth_challenge_details(&ca->ss, "pending", spc, token, authz_url);
						if (stir_shaken_zstr(authz_challenge_details)) {
							stir_shaken_set_error(&ca->ss, "AUTHZ request failed, could not produce challenge details", STIR_SHAKEN_ERROR_ACME_AUTHZ_DETAILS);
							goto fail;
						}
						session->authz_challenge_details = strdup(authz_challenge_details);
						session->authz_secret = authz_secret;
						session->authz_url = strdup(authz_url);
						session->authz_token = strdup(token);

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Sending challenge details:\n%s\n", authz_challenge_details);

						mg_printf(nc, "HTTP/1.1 200 You are more than welcome. Here is your challenge:\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", strlen(authz_challenge_details), authz_challenge_details);

						session->state = STI_CA_SESSION_STATE_AUTHZ_DETAILS_SENT;
					}

				} else {

					jwt_t *jwt = NULL;
					char *token = NULL;
					const char *spc_token = NULL;
					jwt_t *spc_token_jwt = NULL;
					const char *cert_url = NULL;
					char *expires = NULL, *validated = NULL;
					stir_shaken_sp_t sp = { 0 };

					if (!uri_has_secret) {
						stir_shaken_set_error(&ca->ss, "Bad request, Secret is missing", STIR_SHAKEN_ERROR_ACME_SECRET_MISSING);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Handling response to authz challenge-details challenge\n");
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC is: %s\n", spc);
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Secret: %llu\n", secret);

					if (STI_CA_SESSION_STATE_AUTHZ_DETAILS_SENT != session->state) {
						stir_shaken_set_error(&ca->ss, "Wrong authorization state", STIR_SHAKEN_ERROR_ACME_SESSION_WRONG_STATE);
						goto fail;
					}

					if (secret != session->authz_secret) {
						stir_shaken_set_error(&ca->ss, "Bad secret for this authorization session", STIR_SHAKEN_ERROR_ACME_SESSION_BAD_SECRET);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Secret: OK\n");

					if (jwt_new(&jwt) != 0) {
						stir_shaken_set_error(&ca->ss, "Cannot create JWT", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto fail;
					}

					if (0 != jwt_decode(&jwt, m->body.p, NULL, 0)) {
						stir_shaken_set_error(&ca->ss, "Cannot parse JWT", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto fail;
					}

					token = jwt_dump_str(jwt, 0);
					if (!token) {
						stir_shaken_set_error(&ca->ss, "Cannot dump JWT", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Token is:\n%s\n", token);
					jwt_free_str(token);
					token = NULL;

					spc_token = jwt_get_grant(jwt, "keyAuthorization");
					if (stir_shaken_zstr(spc_token)) {
						stir_shaken_set_error(&ca->ss, "JWT is missing SPC token", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto fail;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC token is:\n%s\n", spc_token);
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Entering polling state...\n");
							
					// TODO generate 
					expires = "never";
					validated = "just right now";

					session->authz_polling_status = stir_shaken_acme_generate_auth_polling_status(&ca->ss, "pending", expires, validated, spc, session->authz_token, session->authz_url);
					if (stir_shaken_zstr(session->authz_polling_status)) {
						stir_shaken_set_error(&ca->ss, "AUTHZ request failed, could not produce polling status", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
						goto fail;
					}

					session->state = STI_CA_SESSION_STATE_POLLING;

					mg_printf(nc, "HTTP/1.1 200 OK, Processing... (you can do polling now)\r\n\r\n");
					close_http_connection(nc, io);

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Verifying SPC token...\n");

					if (jwt_new(&spc_token_jwt) != 0) {
						stir_shaken_set_error(&ca->ss, "Cannot create JWT for SPC token", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto authorization_result;
					}

					if (0 != jwt_decode(&spc_token_jwt, spc_token, NULL, 0)) {
						stir_shaken_set_error(&ca->ss, "SPC token is not JWT", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto authorization_result;
					}
					
					token = jwt_dump_str(spc_token_jwt, 0);
					if (!token) {
						stir_shaken_set_error(&ca->ss, "Cannot dump SPC token JWT", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto authorization_result;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> SPC token is:\n%s\n", token);
					jwt_free_str(token);
					token = NULL;

					cert_url = jwt_get_header(spc_token_jwt, "x5u");
					if (stir_shaken_zstr(cert_url)) {
						stir_shaken_set_error(&ca->ss, "SPC token is missing x5u, cannot download certificate", STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE);
						goto authorization_result;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Cert URL (x5u) is:\n%s\n", cert_url);
					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> Verifying SPC token..\n");

                    // TODO  check URL, if it's URL this CA is running, then do not make CURL call, serve from mem
                    if (strstr(cert_url, "localhost") || strstr(cert_url, "190.102.98.199")) {
						stir_shaken_set_error(&ca->ss, "Bad URL for PA cert (localhost and 190.102.98.199 are forbidden)", STIR_SHAKEN_ERROR_ACME_SPC_TOKEN_INVALID);
                        goto authorization_result;
                    }

					if (STIR_SHAKEN_STATUS_OK != stir_shaken_jwt_verify(&ca->ss, spc_token)) {
						stir_shaken_set_error(&ca->ss, "SPC token did not pass verification", STIR_SHAKEN_ERROR_ACME_SPC_TOKEN_INVALID);
						fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "-> [-] SP failed authorization\n");
					} else {
						fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "-> [+] SP authorized\n");
						session->authorized = 1;
					}

authorization_result:

					// Set polling status, keep authorization session life for some time, allowing SP to query polling status and to download cert
					if (session->authz_polling_status) {
						free(session->authz_polling_status);
						session->authz_polling_status = NULL;
					}

					if (session->authorized) {
						session->authz_polling_status = stir_shaken_acme_generate_auth_polling_status(&ca->ss, "valid", expires, validated, spc, session->authz_token, session->authz_url);
					} else {
						// set polling status to 'failed'
						// This is not what draft ATIS-1000080 says, but it seems reasonable (ATIS only says that 'Once successful, the state of the challenge shall be changed from pending to valid' but doesn't say how to signal failed authorization
						session->authz_polling_status = stir_shaken_acme_generate_auth_polling_status(&ca->ss, "failed", expires, validated, spc, session->authz_token, session->authz_url);
					}

					if (stir_shaken_zstr(session->authz_polling_status)) {
						stir_shaken_set_error(&ca->ss, "AUTHZ request failed, could not produce polling status", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
						goto fail;
					}

					if (session->authorized) {

						if (!ca->cert.x) {
							fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "Loading CA certificate...\n");
							ca->cert.x = stir_shaken_load_x509_from_file(&ca->ss, ca->cert_name);
							if (!ca->cert.x) {
								stir_shaken_set_error(&ca->ss, "Error loading CA certificate", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
								goto fail;
							}
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "Issuing STI certificate...\n");

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t -> Loading CSR...\n");
						if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_x509_req_from_mem(&ca->ss, &session->sp.csr.req, session->sp.csr.pem)) {
							stir_shaken_set_error(&ca->ss, "Error loading CSR", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
							goto fail;
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t -> Generating cert...\n");
						session->sp.cert.x = stir_shaken_generate_x509_end_entity_cert_from_csr(&ca->ss, ca->cert.x, ca->keys.private_key, ca->issuer_c, ca->issuer_cn, session->sp.csr.req, ca->serial_sp, ca->expiry_days_sp, ca->tn_auth_list_uri);
						if (!session->sp.cert.x) {
							stir_shaken_set_error(&ca->ss, "Error creating SP certificate", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
							goto fail;
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t -> Configuring certificate...\n");
						snprintf(session->sp.cert_name, sizeof(session->sp.cert_name), "sp_%s_%llu_%zu.pem", spc, secret, time(NULL));
						if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_configure(&ca->ss, &session->sp.cert, session->sp.cert_name, NULL, NULL)) {
							stir_shaken_set_error(&ca->ss, "Error configuring SP certificate", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
							goto fail;
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t ->Saving certificate (%s)...\n", session->sp.cert_name);
						if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(&ca->ss, session->sp.cert.x, session->sp.cert.name)) {
							stir_shaken_set_error(&ca->ss, "Error saving SP certificate", STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING);
							goto fail;
						}

						fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "-> [++] STI certificate ready for download\n");
					}

					if (jwt) {
						jwt_free(jwt);
						jwt = NULL;
					}

					session->state = STI_CA_SESSION_STATE_POLLING;
					goto exit;

				}

				close_http_connection(nc, io);
				fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "=== OK\n");
			}

			break;

		case MG_EV_RECV:
			break;

		default:
			break;
	}

exit:

	if (authz_challenge_details) {
		free(authz_challenge_details);
		authz_challenge_details = NULL;
	}

	return;

fail:

	if (ca && stir_shaken_is_error_set(&ca->ss)) {
		error_desc = stir_shaken_get_error(&ca->ss, &error);
	}
	close_http_connection_with_error(nc, io, error_desc);

	if (authz_challenge_details) {
		free(authz_challenge_details);
		authz_challenge_details = NULL;
	}
	
	stir_shaken_set_error(&ca->ss, "API AUTHZ request failed", STIR_SHAKEN_ERROR_ACME);
	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "=== FAIL\n");
	return;
}

static void ca_event_handler(struct mg_connection *nc, int event, void *hm, void *d)
{
	struct http_message *m = (struct http_message*) hm;
	struct mbuf *io = NULL;
	event_handler_t *evh = NULL;
	stir_shaken_ca_t *ca = (stir_shaken_ca_t*) d;
	stir_shaken_error_t error = STIR_SHAKEN_ERROR_GENERAL;
	const char *error_desc = NULL;
	char err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };
	struct mg_str api_url = mg_mk_str(STI_CA_ACME_API_URL);


	pthread_mutex_lock(&big_fat_lock);
	
	if (!ca) {
		stir_shaken_set_error(&ca->ss, "Bad params", STIR_SHAKEN_ERROR_ACME);
		goto exit;
	}

	fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Event [%d]...\n", event);

	if (nc) {
		io = &nc->recv_mbuf;
	}
	
	switch (event) {

		case MG_EV_ACCEPT:
			{
				char addr[32];
				mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "%p: Connection from %s\r\n", nc, addr);
				break;
			}

		case MG_EV_RECV:
			fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "RECV... \r\n");
			break;

		case MG_EV_HTTP_REQUEST:
			{
				unsigned int port_i = 0;

				fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\n=== +++ Processing HTTP request...\n");

				if (m->uri.p) {

					if (!mg_strstr(m->uri, api_url)) {
						
						if (ca && stir_shaken_is_error_set(&ca->ss)) {
							error_desc = stir_shaken_get_error(&ca->ss, &error);
						}

						close_http_connection_with_error(nc, io, error_desc);
						snprintf(err_buf, STIR_SHAKEN_BUFLEN, "URL (%s) is not handled by ACME API. Closed HTTP connection", m->uri.p);
						stir_shaken_set_error(&ca->ss, err_buf, STIR_SHAKEN_ERROR_ACME);
						break;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\n-> Searching handler for %s...\n", m->uri.p);

					evh = handler_registered(&m->uri);

					if (!evh) {
						
						if (ca && stir_shaken_is_error_set(&ca->ss)) {
							error_desc = stir_shaken_get_error(&ca->ss, &error);
						}

						close_http_connection_with_error(nc, io, error_desc);
						stir_shaken_set_error(&ca->ss, "Handler not found. Closed HTTP connection", STIR_SHAKEN_ERROR_ACME);

						break;
					}

					fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\n-> Handler found\n");
					evh->f(nc, event, hm, d);
				}
				break;
			}

		default:
			break;
	}

exit:
	if (stir_shaken_is_error_set(&ca->ss)) {
		error_desc = stir_shaken_get_error(&ca->ss, &error);
		fprintif(STIR_SHAKEN_LOGLEVEL_BASIC, "Error. %s\n", error_desc);
		stir_shaken_clear_error(&ca->ss);
	}

	pthread_mutex_unlock(&big_fat_lock);

	return;
}

stir_shaken_status_t stir_shaken_run_ca_service(stir_shaken_context_t *ss, stir_shaken_ca_t *ca)
{
	struct mg_mgr mgr = { 0 };
	struct mg_connection *nc = NULL;
	char port[100] = { 0 };
	struct mg_bind_opts bopts = { 0 };
	struct mg_http_endpoint_opts opts = { 0 };

	
	if (!ca)
		return STIR_SHAKEN_STATUS_TERM;
	
	memset(&opts, 0, sizeof(opts));
	opts.user_data = ca;
	bopts.user_data = ca;

	mg_mgr_init(&mgr, NULL);
	
	if (ca->port == 0)
		ca->port = STIR_SHAKEN_DEFAULT_CA_PORT;

	snprintf(port, 100, ":%u", ca->port); 
	nc = mg_bind_opt(&mgr, port, ca_event_handler, ca, bopts);
	if (!nc) {
		stir_shaken_set_error(ss, "Cannnot bind to port", STIR_SHAKEN_ERROR_BIND);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	register_uri_handler(STI_CA_ACME_NEW_ACCOUNT_URL, ca_handle_api_account, 0);
	register_uri_handler(STI_CA_ACME_CERT_REQ_URL, ca_handle_api_cert, 1);
	register_uri_handler(STI_CA_ACME_AUTHZ_URL, ca_handle_api_authz, 1);
	register_uri_handler(STI_CA_ACME_NONCE_REQ_URL, ca_handle_api_nonce, 0);

	mg_set_protocol_http_websocket(nc);

	for (;;) {
		mg_mgr_poll(&mgr, 10000);
	}

	unregister_handlers();
	mg_mgr_free(&mgr);

	return STIR_SHAKEN_STATUS_OK;
}
