#include "stir_shaken.h"
#include "mongoose.h"


typedef void handler_t(struct mg_connection *nc, int event, void *hm, void *d);

typedef struct event_handler_s {
	char *uri;
	handler_t *f;
} event_handler_t;

#define HANDLERS_N 10
event_handler_t event_handlers[HANDLERS_N];

static stir_shaken_status_t register_uri_handler(const char *uri, void *handler)
{
	int i = 0;
	event_handler_t *e = NULL;

	while (i < HANDLERS_N) {

		e = &event_handlers[i];
		if (stir_shaken_zstr(e->uri)) {
			e->uri = strdup(uri);
			e->f = handler;
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
		if (e->uri && (0 == mg_vcmp(uri, e->uri))) {
			return e;
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
		}
		++i;
	}
}

static void ca_handle_bad_request(struct mg_connection *nc, int event, void *hm, void *d)
{
	fprintf(stderr, "\n=== Handling: bad request...\n");
	return;
}

static void ca_handle_api_account(struct mg_connection *nc, int event, void *hm, void *d)
{
	fprintf(stderr, "\n=== Handling: %s...\n", STI_CA_ACME_NEW_ACCOUNT_URL);
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

	if (!m || !nc || !ca) {
		stir_shaken_set_error(&ca->ss, "Bad params, missing HTTP message, connection, and/or ca", STIR_SHAKEN_ERROR_ACME);
		goto fail;
	}

	io = &nc->recv_mbuf;

	fprintf(stderr, "\n=== Handling:\n%s\n", STI_CA_ACME_CERT_REQ_URL);
	fprintf(stderr, "\n=== Message Body:\n%s\n", m->body.p);
	
	
	switch (event) {

		case MG_EV_HTTP_REQUEST:

			{
				char *spc = NULL;
				const char *csr_b64 = NULL;
				char csr[STIR_SHAKEN_BUFLEN] = { 0 };
				int csr_len = 0;
				char *token = NULL;
				char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
				char *auth_details = NULL;


				if ((EINVAL == jwt_decode(&jwt, m->body.p, NULL, 0)) || !jwt) {
					stir_shaken_set_error(&ca->ss, "Cannot parse message body into JWT", STIR_SHAKEN_ERROR_ACME);
					goto fail;
				}

				csr_b64 = jwt_get_grant(jwt, "csr");
				if (stir_shaken_zstr(csr_b64)) {
					stir_shaken_set_error(&ca->ss, "JWT posted by SP is missing CSR", STIR_SHAKEN_ERROR_ACME);
					goto fail;
				}

				if (stir_shaken_b64_decode(csr_b64, csr, sizeof(csr)) < 1 || stir_shaken_zstr(csr)) {
					stir_shaken_set_error(&ca->ss, "Cannot decode CSR from base 64", STIR_SHAKEN_ERROR_ACME);
					goto fail;
				}

				fprintf(stderr, "CSR is:\n%s\n", csr);

				//csr = stir_shaken_acme_cert_req_get_csr(json);
				auth_details = stir_shaken_acme_create_cert_req_auth_challenge_details(&ca->ss, spc, token, authz_url);

				mg_printf(nc, "%s", "HTTP/1.1 200 OK Kind-of\r\nContent-Length: 0\r\n\r\n");

				//mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLink: <https://sti-ca.com/acme/some-directory>;rel=\"index\"\r\n{\r\n\"status\": \"pending\"\r\n}\r\n\r\n");
				// Printf more

				// Send empty chunk, end of response
				mg_send_http_chunk(nc, "", 0);
				mbuf_remove(io, io->len);      // Discard data from recv buffer
				nc->flags |= MG_F_SEND_AND_CLOSE;
				
				fprintf(stderr, "=== OK\n");
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

	stir_shaken_clear_error(&ca->ss);
	return;

fail:
	
	if (nc) mg_printf(nc, "%s", "HTTP/1.1 %s Invalid\r\n\r\n", STIR_SHAKEN_HTTP_REQ_INVALID);
	mg_send_http_chunk(nc, "", 0);
	if (io) mbuf_remove(io, io->len);
	if (nc) nc->flags |= MG_F_SEND_AND_CLOSE;

	if (json) {
		cJSON_Delete(json);
		json = NULL;
	}
	stir_shaken_set_error(&ca->ss, "HTTP Request Failed", STIR_SHAKEN_ERROR_ACME);
	fprintf(stderr, "=== FAIL\n");
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

	// TODO remove
	fprintf(stderr, "Event [%d]...\n", event);
	
	if (!ca) {
		stir_shaken_set_error(&ca->ss, "Bad params", STIR_SHAKEN_ERROR_ACME);
		goto exit;
	}

	if (nc) {
		io = &nc->recv_mbuf;
	}
	
	switch (event) {

		case MG_EV_ACCEPT:
			{
				char addr[32];
				mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
				// TODO remove
				fprintf(stderr, "%p: Connection from %s\r\n", nc, addr);
				break;
			}

		case MG_EV_RECV:
			fprintf(stderr, "RECV... \r\n");
			break;

		case MG_EV_HTTP_REQUEST:
			{
				unsigned int port_i = 0;

				fprintf(stderr, "Handling HTTP request...\n");

				if (m->uri.p) {

					fprintf(stderr, "Searching handler for %s...\n", m->uri.p);

					evh = handler_registered(&m->uri);
					if (evh) {
						fprintf(stderr, "\nHandler found\n");
						evh->f(nc, event, hm, d);
					}
				}
				break;
			}

		default:
			break;
	}

exit:
	if (stir_shaken_is_error_set(&ca->ss)) {
		error_desc = stir_shaken_get_error(&ca->ss, &error);
		fprintf(stderr, "Error. %s\n", error_desc);
		stir_shaken_clear_error(&ca->ss);
	}
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

	register_uri_handler(STI_CA_ACME_NEW_ACCOUNT_URL, ca_handle_api_account);
	register_uri_handler(STI_CA_ACME_CERT_REQ_URL, ca_handle_api_cert);

	mg_set_protocol_http_websocket(nc);

	for (;;) {
		mg_mgr_poll(&mgr, 10000);
	}

	unregister_handlers();
	mg_mgr_free(&mgr);

	return STIR_SHAKEN_STATUS_OK;
}
