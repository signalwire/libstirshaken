#include <stir_shaken.h>


stir_shaken_ca_t ca;
stir_shaken_ca_session_t *session;

/*
 * Mock HTTP transfers in this test.
 */
stir_shaken_status_t stir_shaken_make_http_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req)
{
    (void) ss;

    printf("\n\nShakening surprise\n\n");
    stir_shaken_assert(http_req != NULL, "http_req is NULL!");

    printf("MOCK HTTP response code to 200 OK\n");
    http_req->response.code = 200;

    switch (http_req->action) {

        case STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_INIT:

            {
                char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
                char authz_challenge[STIR_SHAKEN_BUFLEN] = { 0 };

                printf("\n\nSTIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_INIT\n\n");

                stir_shaken_assert(STIR_SHAKEN_STATUS_OK == ca_sp_cert_req_reply_challenge(ss, &ca, (char *) http_req->data, authz_challenge, authz_url, &session), "CA reply to SP cert req failed");

                fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> (MOCK) Added authorization session to queue\n");
                fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "\t-> (MOCK) Sending authorization challenge:\n%s\n", authz_challenge);

                free(http_req->response.mem.mem);
                http_req->response.mem.mem = malloc(strlen(authz_challenge) + 1);
                memset(http_req->response.mem.mem, 0, strlen(authz_challenge) + 1);
                strncpy(http_req->response.mem.mem, authz_challenge, strlen(authz_challenge));
                fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) HTTP/1.1 201 Created\r\nLocation: %s\r\nContent-Length: %lu\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", authz_url, strlen(authz_challenge), authz_challenge);

                session->state = STI_CA_SESSION_STATE_AUTHZ_SENT;
            }
            break;

        case STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_CA_REPLY_CHALLENGE:
            //
            printf("\n\nSTIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_CA_REPLY_CHALLENGE\n\n");
            break;

        // etc.

        default:
            printf("\n\nSTIR_SHAKEN_ACTION_TYPE unknown\n\n");
            stir_shaken_assert(0, "Bad action type!");
            return STIR_SHAKEN_STATUS_TERM;
    }

    return STIR_SHAKEN_STATUS_OK;
}
