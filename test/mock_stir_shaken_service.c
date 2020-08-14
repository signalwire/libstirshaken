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
                stir_shaken_assert(!stir_shaken_zstr(authz_challenge), "Authz challenge not created");
                stir_shaken_assert(!stir_shaken_zstr(authz_url), "Authz url not created");
                stir_shaken_assert(session, "CA session not created");

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

        case STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ_DETAILS:

            {
                char spc[STIR_SHAKEN_BUFLEN] = { 0 };
                unsigned long long int sp_code = 0;
                char authz_url[STIR_SHAKEN_BUFLEN] = { 0 };
                char *authz_challenge_details = NULL;
                int uri_has_secret = 0;
                unsigned long long secret = 0;
                int authz_secret = 0;

                stir_shaken_hash_entry_t *e = NULL;
                stir_shaken_ca_session_t *session = NULL;
                int http_method = STIR_SHAKEN_HTTP_REQ_TYPE_POST;

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
                http_req->response.mem.mem = malloc(strlen(session->authz_challenge_details) + 1);
                memset(http_req->response.mem.mem, 0, strlen(session->authz_challenge_details) + 1);
                strncpy(http_req->response.mem.mem, session->authz_challenge_details, strlen(session->authz_challenge_details));
                fprintif(STIR_SHAKEN_LOGLEVEL_MEDIUM, "(MOCK) HTTP/1.1 200 You are more than welcome. Here is your challenge:\r\nContent-Length: %lu\r\nContent-Type: application/json\r\n\r\n%s\r\n\r\n", strlen(session->authz_challenge_details), session->authz_challenge_details);

                session->state = STI_CA_SESSION_STATE_AUTHZ_DETAILS_SENT;

            }
            break;

        case STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ:

            {
                printf("\n\nSTIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ\n\n");

                //session->state = STI_CA_SESSION_STATE_AUTHZ_SENT;
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
