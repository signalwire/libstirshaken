#ifndef __STIR_SHAKEN
#define __STIR_SHAKEN

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>

#include <cjson/cJSON.h>

// For cert downloading
#include <curl/curl.h>

#include <pthread.h>

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
	STIR_SHAKEN_STATUS_FALSE,
	STIR_SHAKEN_STATUS_RESTART,
	STIR_SHAKEN_STATUS_NOOP
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

/* Global Values */
typedef struct stir_shaken_globals_s {

	pthread_mutexattr_t		attr;	
	pthread_mutex_t			mutex;	
	stir_shaken_settings_t	settings;
	uint8_t					initialised;

	/** SSL */
	const SSL_METHOD    *ssl_method;
	SSL_CTX             *ssl_ctx;
	SSL                 *ssl;

	stir_shaken_csr_t     csr;                      // CSR
	stir_shaken_cert_t    cert;                     // Certificate
	int                 curve_nid;                  // id of the curve in OpenSSL
} switch_stir_shaken_globals_t;

extern switch_stir_shaken_globals_t stir_shaken_globals;

/**
 * Main entry point.
 *
 * This is called on library load.
 */
static void stir_shaken_init(void) __attribute__ ((constructor));

/**
 * Main exit point.
 *
 * This is called on library unload.
 */
static void stir_shaken_deinit(void) __attribute__ ((destructor));


// SSL

/**
 * Using @digest_name and @pkey create a signature for @data and save it in @out.
 * Return @out and lenght of it in @outlen.
 */ 
stir_shaken_status_t stir_shaken_do_sign_data_with_digest(const char *digest_name, EVP_PKEY *pkey, const char *data, size_t datalen, unsigned char *out, size_t *outlen);

/**
 * Generate new keys. Always removes old files.
 */
stir_shaken_status_t stir_shaken_generate_keys(EC_KEY **eck, EVP_PKEY **priv, EVP_PKEY **pub, const char *private_key_full_name, const char *public_key_full_name);

/**
 * 
 * Generate CSR needed by STI-CA to issue new cert.
 * 
 * @sp_code - (in) Service Provider code
 * @csr - (out) result
 */
stir_shaken_status_t stir_shaken_generate_csr(uint32_t sp_code, X509_REQ **csr_req, EVP_PKEY *private_key, EVP_PKEY *public_key, const char *csr_full_name, const char *csr_text_full_name);

/**
 * Generate self signed X509 certificate from csr @req.
 *
 * @sp_code - (in) Service Provider code
 * @req - (in) X509 certificate sign request
 */
X509 * stir_shaken_generate_x509_self_sign(uint32_t sp_code, X509_REQ *req, EVP_PKEY *private_key);

/**
 * Get the cert locally. Get it from disk or create and sign. 
 * 
 * @cert - (out) result certificate
 *
 * Return value:
 * STIR_SHAKEN_STATUS_FALSE: failed creating cert for self-trusted STI-CA
 * STIR_SHAKEN_STATUS_NOOP: reusing old cert for self-trusted STI-CA from RAM
 * STIR_SHAKEN_STATUS_RESTART: reusing old cert for self-trusted STI-CA from disk
 * STIR_SHAKEN_STATUS_SUCCESS: generated and signed new new cert
 */
stir_shaken_status_t stir_shaken_generate_cert_from_csr(uint32_t sp_code, stir_shaken_cert_t *cert, stir_shaken_csr_t *csr, EVP_PKEY *private_key, const char *cert_full_name, const char *cert_text_full_name);

stir_shaken_status_t stir_shaken_download_cert(const char *url, mem_chunk_t *chunk);
stir_shaken_status_t stir_shaken_download_cert_to_file(const char *url, const char *file);
stir_shaken_status_t stir_shaken_install_cert(stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_load_cert_from_mem(X509 **x, void *mem, size_t n);
stir_shaken_status_t stir_shaken_load_cert_from_mem_through_file(X509 **x, void *mem, size_t n);
stir_shaken_status_t stir_shaken_load_cert_from_file(X509 **x, const char *cert_tmp_name);
stir_shaken_status_t stir_shaken_init_ssl(void);
void stir_shaken_free_ssl(void);


// Verification service

int stir_shaken_verify_data(const char *data, const char *signature, size_t siglen, EVP_PKEY *pkey);
int stir_shaken_do_verify_data_file(const char *data_filename, const char *signature_filename, EVP_PKEY *public_key);
int stir_shaken_do_verify_data(const void *data, size_t datalen, const unsigned char *sig, size_t siglen, EVP_PKEY *public_key);

/**
 * Verify (check/authenticate) call identity.
 *
 * @sdp - (in) SDP call description
 */
stir_shaken_status_t stir_shaken_verify_with_cert(const char *identity_header, stir_shaken_cert_t *cert);

/**
 * Perform STIR-Shaken verification of the @identity_header.
 *
 * This will attempt to obtain certificate referenced by SIP @identity_header
 * and if successfull then will verify signature from that header against data from PASSporT
 * (where the challenge is header and payload [base 64]) using public key from cert.
 */
stir_shaken_status_t stir_shaken_verify(const char *sih, const char *cert_url);


// Authorization service

/**
 * Create JSON token from call @pparams.
 */
cJSON* stir_shaken_passport_create_json(stir_shaken_passport_params_t *pparams);

/**
 * Create signatures in @jwt and save intermediate results in @info.
 */
stir_shaken_status_t stir_shaken_passport_finalise_json(stir_shaken_passport_t *passport, EVP_PKEY *pkey);

/**
 * Initialise PASSporT pointed to by @passport using call @params and sign it with @pkey.
 */
stir_shaken_status_t stir_shaken_passport_create(stir_shaken_passport_t *passport, stir_shaken_passport_params_t *params, EVP_PKEY *pkey);

/**
 * Authorize (assert/sign) call with SIP Identity Header for Service Provider identified by @sp_code.
 *
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 * @sp_code - (in) Service Provider Code which uniquely identifies Service Provider within their STI-CA (Cert Authority)
 * @stica - (in) STI-CA description (this can be configured from dialplan config / channel variables, or by consulting other lookup service)
 * @params - call params in terms of STIR Shaken's PASSporT
 */
stir_shaken_status_t stir_shaken_authorize(char **sih, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_cert_t *cert);

/**
 * Authorize the call and keep PASSporT if the @keep_pasport is true.
 */
stir_shaken_status_t stir_shaken_authorize_keep_passport(char **sih, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport, uint8_t keep_passport, EVP_PKEY *pkey, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_authorize_self_trusted(char **sih, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_cert_t *cert);

/**
 * High level interface to authorization (main entry point).
 */
stir_shaken_status_t stir_shaken_stisp_perform_authorization(EVP_PKEY *pkey, stir_shaken_cert_t *cert);

/*
 * Sign PASSporT with @pkey (generate signature in Jason Web Token).
 * Sign the call data with the @pkey. 
 * Local PASSporT object is created and destroyed. Only SIP Identity header is returned.
 *
 * External parameters that must be given to this method to be able to sign the SDP:
 * X means "needed"
 *
 *      // JSON web token (JWT)
 *          // JSON JOSE Header (alg, ppt, typ, x5u)
 *              // alg      This value indicates the encryption algorithm. Must be 'ES256'.
 *              // ppt      This value indicates the extension used. Must be 'shaken'.
 *              // typ      This value indicates the token type. Must be 'passport'.
 * X            // x5u      This value indicates the location of the certificate used to sign the token.
 *          // JWS Payload
 * X            // attest   This value indicates the attestation level. Must be either A, B, or C.
 * X            // dest     This value indicates the called number(s) or called Uniform Resource Identifier(s).
 *              // iat      This value indicates the timestamp when the token was created. The timestamp is the number of seconds that have passed since the beginning of 00:00:00 UTC 1 January 1970.
 * X            // orig     This value indicates the calling number or calling Uniform Resource Identifier.
 * X            // origid   This value indicates the origination identifier.
 *          // JWS Signature
 *
 *      // Parameters
 *          //Alg
 * (==x5u)	//Info	(X [needed], but implicitely copied from @x5u)
 *          //PPT
 */ 
char* stir_shaken_do_sign(stir_shaken_passport_params_t *params, EVP_PKEY *pkey);

char* stir_shaken_sip_identity_create(stir_shaken_passport_t *passport);

/*
 * Sign the call data with the @pkey, and keep pointer to created PASSporT if @keep_passport is true. 
 * SIP Identity header is returned and PASSporT.
 * @passport - (out) will point to created PASSporT
 */
char * stir_shaken_do_sign_keep_passport(stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_passport_t **passport, uint8_t keep_passport);


// Authorization service
cJSON* stir_shaken_passport_create_json(stir_shaken_passport_params_t *pparams);
stir_shaken_status_t stir_shaken_passport_finalise_json(stir_shaken_passport_t *passport, EVP_PKEY *pkey);
stir_shaken_status_t stir_shaken_passport_create(stir_shaken_passport_t *passport, stir_shaken_passport_params_t *params, EVP_PKEY *pkey);
void stir_shaken_passport_destroy(stir_shaken_passport_t *passport);


// Utility

stir_shaken_status_t stir_shaken_dir_exists(const char *path);
stir_shaken_status_t stir_shaken_dir_create(const char *path);
stir_shaken_status_t stir_shaken_dir_create_recursive(const char *path);
stir_shaken_status_t stir_shaken_b64_encode(unsigned char *in, size_t ilen, unsigned char *out, size_t olen);
size_t stir_shaken_b64_decode(const char *in, char *out, size_t olen);


// TEST

stir_shaken_status_t stir_shaken_test_die(const char *reason, const char *file, int line);

/* Exit from calling location if test fails. */
#define stir_shaken_assert(x, m) if (!(x)) return stir_shaken_test_die((m), __FILE__, __LINE__);

// Test 1
stir_shaken_status_t stir_shaken_unit_test_sign_verify_data(void);

// Test 2
stir_shaken_status_t stir_shaken_unit_test_passport_create(void);

// Test 3
stir_shaken_status_t stir_shaken_unit_test_passport_create_verify_signature(void);

// Test 4
stir_shaken_status_t stir_shaken_unit_test_sip_identity_header(void);

// Test 5
stir_shaken_status_t stir_shaken_unit_test_sip_identity_header_keep_passport(void);

// Test 6
stir_shaken_status_t stir_shaken_unit_test_authorize(void);

// Test 7
stir_shaken_status_t stir_shaken_unit_test_authorize_keep_passport(void);

// Test 8
stir_shaken_status_t stir_shaken_unit_test_verify(void);

// Test 9
stir_shaken_status_t stir_shaken_unit_test_verify_spoofed(void);

#endif // __STIR_SHAKEN
