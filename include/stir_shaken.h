#ifndef __STIR_SHAKEN
#define __STIR_SHAKEN

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <cjson/cJSON.h>

// For cert downloading
#include <curl/curl.h>

#define PBUF_LEN 800

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf_api.h>


typedef enum stir_shaken_status {
	STIR_SHAKEN_STATUS_OK,
	STIR_SHAKEN_STATUS_FALSE
} stir_shaken_status_t;

typedef struct mem_chunk_s {
	char    *mem;
	size_t  size;
} mem_chunk_t;


/**
 * https://tools.ietf.org/html/rfc8225, 3. PASSporT Overview
 *
 * The primary value asserted in a PASSporT object is the originating identity representing the identity of the calling
 * party or the initiator of a personal-communications session. The signer of a PASSporT object may or may not correspond to the
 * originating identity. For a given application's use or using protocol of PASSporT, the creation of the PASSporT object is
 * performed by an entity that is authoritative to assert the caller's identity.  This authority is represented by the certificate
 * credentials and the signature, and the PASSporT object is created and initiated to the destination(s) per the application's choice
 * of authoritative point(s) in the network.
 */

/**
 * The Personal Assertion Token, PASSporT: https://tools.ietf.org/html/rfc8225
 *
 * Use stir-shaken_passport_create_json to init the JSON representation.
 */
typedef struct stir_shaken_passport {

    // JSON web token (JWT)
        // JSON JOSE Header (alg, ppt, typ, x5u)
            // alg      This value indicates the encryption algorithm. Must be 'ES256'.
            // ppt      This value indicates the extension used. Must be 'shaken'.
            // typ      This value indicates the token type. Must be 'passport'.
            // x5u      This value indicates the location of the certificate used to sign the token.
        // JWS Payload
            // attest   This value indicates the attestation level. Must be either A, B, or C.
            // dest     This value indicates the called number(s) or called Uniform Resource Identifier(s).
            // iat      This value indicates the timestamp when the token was created. The timestamp is the number of seconds that have passed since the beginning of 00:00:00 UTC 1 January 1970.
            // orig     This value indicates the calling number or calling Uniform Resource Identifier.
            // origid   This value indicates the origination identifier.
        // JWS Signature

    // Parameters
        //Alg
        //Info
        //PPT

    cJSON *json;        // PASSport JSON (JWT + Parameters)
    cJSON *info;        // Additional info (payload/header intermediate signatures used to generate @jwt->signature)
} stir_shaken_passport_t;

/*
 * Parameters needed by STIR-Shaken to create PASSporT and sign the call.
 * These are call params in context of STIR-Shaken's PASSporT.
 * 
 * @x5u - This value indicates the location of the certificate used to sign the token.
 * @attest - Attestation level (trust), string: A, B or C (may be NULL, attest is not added then)
 * @desttn_key - "uri" if dest should be in array format, otherwise it will be in telephone number format
 * @desttn_val - value of dest JSON field
 * @iat - "issued at" timestamp
 * @origtn_key - "uri" if orig should be in array format, otherwise it will be in telephone number format
 * @origtn_val - value of orig JSON field
 * @origid - can be NULL if should not be included
 * @ppt_ignore - true if ppt field should not be included
 */ 
typedef struct stir_shaken_passport_params_s {
    const char  *x5u;
    const char  *attest;
    const char  *desttn_key;
    const char  *desttn_val;
    int         iat;
    const char  *origtn_key;
    const char  *origtn_val;
    const char  *origid;
    uint8_t     ppt_ignore;     // Should skip ppt field?
} stir_shaken_passport_params_t;

typedef struct stir_shaken_stisp_s {
    uint32_t	sp_code;
	char		*install_path;
	char		*install_url;
} stir_shaken_stisp_t;

typedef struct stir_shaken_stica_s {
    const char *hostname;
    uint16_t port;
    uint8_t self_trusted;               /* 1 if STI-CA can be accessed locally, by _acquire_cert_from_local_storage */
    const char *local_storage_path;     /* If STI-CA is self-trusted this tells where is the local storage where the cert is stored. */ 
} stir_shaken_stica_t;

typedef struct stir_shaken_csr_s {
    X509_REQ    *req;
    const char  *body;
    EC_KEY              *ec_key;
    EVP_PKEY            *pkey;
} stir_shaken_csr_t;

typedef struct stir_shaken_cert_s {
    X509        *x;
    char        *body;
	size_t		len;
    uint8_t     is_fresh;
	char		*full_name;
	char		*name;
	char		*install_path;				// folder, where cert must be put to be accessible with @install_url for other SPs
	char		*install_url;				// URL access to cert, this is put into PASSporT as @x5u and @params.info
	char		*access;
    EC_KEY              *ec_key;
    EVP_PKEY            *pkey;
} stir_shaken_cert_t;

typedef struct stir_shaken_settings_s {
    const char *path;
    const char *ssl_private_key_name;
    const char *ssl_private_key_full_name;
    const char *ssl_public_key_name;
    const char *ssl_public_key_full_name;
    const char *ssl_csr_name;
    const char *ssl_csr_full_name;
    const char *ssl_csr_text_full_name;
    const char *ssl_cert_name;
    const char *ssl_cert_full_name;
    const char *ssl_cert_text_full_name;
    const char *ssl_template_file_name;
    const char *ssl_template_file_full_name;
    uint8_t stisp_configured;
    uint8_t stica_configured;
    stir_shaken_stisp_t stisp;
    stir_shaken_stica_t stica;
} stir_shaken_settings_t;

// TEST

static stir_shaken_status_t stir_shaken_test_die(const char *reason, const char *file, int line);

/* Exit from calling location if test fails. */
#define stir_shaken_assert(x, m, s) if (!(x)) return stir_shaken_test_die((m), __FILE__, __LINE__);

stir_shaken_status_t stir_shaken_unit_test_sign_verify_data_file(void);

#endif // __STIR_SHAKEN
