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
	fprintf(stderr, "Handling bad request...\n");
	return;
}

static void ca_handle_api_account(struct mg_connection *nc, int event, void *hm, void *d)
{
	fprintf(stderr, "Handling /ca/api/account request...\n");
	return;
}

static void ca_handle_api_cert(struct mg_connection *nc, int event, void *hm, void *d)
{
	struct http_message *m = (struct http_message*) hm;
	struct mbuf *io = &nc->recv_mbuf;

	fprintf(stderr, "Handling /ca/api/cert request...\n");

	if (!nc)
		return;

	switch (event) {

		case MG_EV_HTTP_REQUEST:
			
			mg_printf(nc, "%s", "HTTP/1.1 200 OK Kind-of\r\nContent-Length: 0\r\n\r\n");
			//mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLink: <https://sti-ca.com/acme/some-directory>;rel=\"index\"\r\n{\r\n\"status\": \"pending\"\r\n}\r\n\r\n");
			// Printf more

			// Send empty chunk, end of response
			mg_send_http_chunk(nc, "", 0);
			mbuf_remove(io, io->len);      // Discard data from recv buffer
			nc->flags |= MG_F_SEND_AND_CLOSE;
			break;
		
		case MG_EV_RECV:
			break;

		default:
			break;
	}

	return;
}

static void ca_event_handler(struct mg_connection *nc, int event, void *hm, void *d)
{
	struct http_message *m = (struct http_message*) hm;
	struct mbuf *io = &nc->recv_mbuf;
	event_handler_t *evh = NULL;

	fprintf(stderr, "Handling event...\n");
	
	switch (event) {

		case MG_EV_ACCEPT:
			{
				char addr[32];
				mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
				fprintf(stderr, "%p: Connection from %s\r\n", nc, addr);
				break;
			}

		case MG_EV_RECV:
			fprintf(stderr, "RECV... \r\n");
			break;

		case MG_EV_HTTP_REQUEST:
			{
				struct mg_str *path, *user_info, *host;
				unsigned int port_i = 0;
				struct mg_str scheme, query, fragment;

				fprintf(stderr, "Handling HTTP request...\n");

				if (m->uri.p) {
					fprintf(stderr, "Searching handler for %s...", m->uri.p);
					evh = handler_registered(&m->uri);
					if (evh) {
						fprintf(stderr, "Calling handler...\n");
						evh->f(nc, event, hm, d);
					}
				}
				break;
			}

		default:
			break;
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

	register_uri_handler("/ca/api/account", ca_handle_api_account);
	register_uri_handler("/ca/api/cert", ca_handle_api_cert);

	mg_set_protocol_http_websocket(nc);

	for (;;) {
		mg_mgr_poll(&mgr, 10000);
	}

	unregister_handlers();
	mg_mgr_free(&mgr);

	return STIR_SHAKEN_STATUS_OK;
}
