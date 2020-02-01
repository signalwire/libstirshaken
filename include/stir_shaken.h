#ifndef __STIR_SHAKEN
#define __STIR_SHAKEN

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <string.h>

#include <cjson/cJSON.h>

// For cert downloading
#include <curl/curl.h>

// For JSON Web Token, used to implement PASSporT
#include <jwt.h>

#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf_api.h>
#include <libgen.h>


#define PBUF_LEN 1000
#define STIR_SHAKEN_ERROR_BUF_LEN 1000
#define STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN 2000
#define STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN 2000
#define ASN1_DATE_LEN 128
#define STIR_SHAKEN_SSL_BUF_LEN 1000

#define TN_AUTH_LIST_OID "1.3.6.1.5.5.7.1.26"
#define TN_AUTH_LIST_LN "TNAuthorizationList"
#define TN_AUTH_LIST_SN "TNAuthList"

#define STIR_SHAKEN_MOC_VERIFY_CERT_ROOT_CHAIN 1


typedef enum stir_shaken_status {
	STIR_SHAKEN_STATUS_OK,
	STIR_SHAKEN_STATUS_FALSE,
	STIR_SHAKEN_STATUS_ERR,
	STIR_SHAKEN_STATUS_RESTART,
	STIR_SHAKEN_STATUS_NOOP,
	STIR_SHAKEN_STATUS_TERM
} stir_shaken_status_t;

typedef struct stir_shaken_csr_s {
	X509_REQ    *req;
	const char  *body;
	EC_KEY              *ec_key;
	EVP_PKEY            *pkey;
} stir_shaken_csr_t;

// Note:
//
// if X509 gets destroyed then notBefore_ASN1 and notAfter_ASN1
// must be NULLED as those are internal pointers to SSL.
//
// serialDec and serialHex must be freed with OPENSSL_free
typedef struct stir_shaken_cert_s {
	X509			*x;						// X509 end-entity Certificate
	STACK_OF(X509)	*xchain;				// Certificate chain
	X509_STORE		*store;					// Container for CA list (list of approved CAs from STI-PA) and CRL (revocation list)
	X509_STORE_CTX	*verify_ctx;			// Verification SSL context using @store to validate cert with chain and revocation list
	char        *body;
	size_t		len;
	uint8_t     is_fresh;
	char		*full_name;
	char		*name;						// name of the certificate, also used in file part of the publicly accessible URL
    char        *original_name;             // name as input into stir_shaken_cert_configure    (strdup)
    char        *basename;                  // canonical name of @original_name                 (strdup)
	char		*install_dir;				// folder, where cert must be put to be accessible with @public_url for other SPs
	char		*install_url;				// directory part of the publicly accessible URL
	char		*public_url;				// publicly accessible URL which can be used to download the certificate, this is concatenated from @install_url and cert's @name and is put into PASSporT as @x5u and @params.info
	EC_KEY              *ec_key;
	EVP_PKEY            *private_key;

	// Cert info retrieved with stir_shaken_read_cert
	char *serialHex;
	char *serialDec;
	ASN1_TIME *notBefore_ASN1;
	ASN1_TIME *notAfter_ASN1;
	char notBefore[ASN1_DATE_LEN];
	char notAfter[ASN1_DATE_LEN];
	char issuer[STIR_SHAKEN_SSL_BUF_LEN];
	char subject[STIR_SHAKEN_SSL_BUF_LEN];
	int version;

} stir_shaken_cert_t;

// ACME credentials
typedef struct stir_shaken_ssl_keys {
    EC_KEY		*ec_key;
    EVP_PKEY	*private_key;
    EVP_PKEY	*public_key;
	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN];
	uint32_t		priv_raw_len;
} stir_shaken_ssl_keys_t;

typedef struct curl_slist curl_slist_t;

// 5.3.2 Verification Error Conditions
// If the authentication service functions correctly, and the certificate is valid and available to the verification service,
// the SIP message can be delivered successfully. However, if these conditions are not satisfied, errors can be
// generated as defined draft-ietf-stir-rfc4474bis. This section identifies important error conditions and specifies
// procedurally what should happen if they occur. Error handling procedures should consider how best to always
// deliver the call per current regulatory requirements 2 while providing diagnostic information back to the signer.
// There are five main procedural errors defined in draft-ietf-stir-rfc4474bis that can identify issues with the validation
// of the Identity header field. The error conditions and their associated response codes and reason phrases are as
// follows:
// 
// 403 - 'Stale Date' - Sent when the verification service receives a request with a Date header field value
// that is older than the local policy for freshness permits. The same response may be used when the "iat"
// has a value older than the local policy for freshness permits.
// 
// 428 - 'Use Identity Header' - A 428 response will be sent (per Section 6.2) when an Identity header
// field is required but no Identity header field without a "ppt"
// parameter or with a supported "ppt" value has been received. [RFC 8224]
//
// 'Use Identity Header' is not recommended for SHAKEN until a point where all calls on the VoIP
// network are mandated to be signed either by local or global policy.
//
// 436 - The 436 "Bad Identity Info" response code indicates an inability to
// acquire the credentials needed by the verification service for
// validating the signature in an Identity header field. Again, given
// the potential presence of multiple Identity header fields, this
// response code should only be sent when the verification service is
// unable to dereference the URIs and/or acquire the credentials
// associated with all Identity header fields in the request. This
// failure code could be repairable if the authentication service
// resends the request with an "info" parameter pointing to a credential
// that the verification service can access. [RFC 8224]
//
// 'Bad-Identity-Info' - The URI in the info parameter cannot be dereferenced (i.e., the request times
// out or receives a 4xx or 5xx error).
//
// 437 - The 437 "Unsupported Credential" response (previously
// "Unsupported Certificate"; see Section 13.2) is sent when a
// verification service can acquire, or already holds, the credential
// represented by the "info" parameter of at least one Identity header
// field in the request but does not support said credential(s), for
// reasons such as failing to trust the issuing certification authority
// (CA) or failing to support the algorithm with which the credential
// was signed. [RFC 8224]
//
// 'Unsupported credential' - This error occurs when a credential is supplied by the info parameter
// but the verifier doesnt support it or it doesnt contain the proper certificate chain in order to trust the
// credentials.
//
// 438 - The 438 "Invalid Identity Header" response indicates that of the set
// of Identity header fields in a request, no header field with a valid
// and supported PASSporT object has been received. Like the 428
// response, this is sent by a verification service when its local
// policy dictates that a broken signature in an Identity header field
// is grounds for rejecting a request. Note that in some cases, an
// Identity header field may be broken for other reasons than that an
// originator is attempting to spoof an identity: for example, when a
// transit network alters the Date header field of the request. Sending
// a full-form PASSporT can repair some of these conditions (see
// Section 6.2.4), so the recommended way to attempt to repair this
// failure is to retry the request with the full form of PASSporT if it
// had originally been sent with the compact form. The alternative
// reason phrase "Invalid PASSporT" can be used when an extended
// full-form PASSporT lacks required headers or claims, or when an
// extended full-form PASSporT signaled with the "ppt" parameter lacks
// required claims for that extension. Sending a string along these
// lines will help humans debugging the sending system. [RFC 8224]
//
// 'Invalid Identity Header' - This occurs if the signature verification fails (for any reason).
// In this STIR-Shaken implementation this happens when jwt_deocde fails.
//
// If any of the above error conditions are detected, the terminating network shall convey the response code and
// reason phrase back to the originating network, indicating which one of the five error scenarios has occurred. How
// this error information is signaled to the originating network depends on the disposition of the call as a result of the
// error. If local policy dictates that the call should not proceed due to the error, then the terminating network shall
// include the error response code and reason phrase in the status line of a final 4xx error response sent to the
// originating network. On the other hand, if local policy dictates that the call should continue, then the terminating
// network shall include the error response code and reason phrase in a Reason header field (defined in [RFC
// 3326]) in the next provisional or final response sent to the originating network as a result of normal terminating
// call processing.
// Example of Reason header field:
// Reason: SIP ;cause=436 ;text="Bad Identity Info"
// In addition, if any of the base claims or SHAKEN extension claims are missing from the PASSporT token claims,
// the verification service shall treat this as a 438 'Invalid Identity Header' error and proceed as defined above.
typedef enum stir_shaken_error {
	STIR_SHAKEN_ERROR_GENERAL,
	STIR_SHAKEN_ERROR_CJSON,
	STIR_SHAKEN_ERROR_CURL,
	STIR_SHAKEN_ERROR_STICA_NOT_APPROVED,
	STIR_SHAKEN_ERROR_SSL,
	STIR_SHAKEN_ERROR_SIP_403_STALE_DATE,
	STIR_SHAKEN_ERROR_SIP_428_USE_IDENTITY_HEADER,
	STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO,
	STIR_SHAKEN_ERROR_SIP_437_UNSUPPORTED_CREDENTIAL,
	STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER,
	STIR_SHAKEN_ERROR_HTTP_403_FORBIDDEN,
	STIR_SHAKEN_ERROR_HTTP_404_INVALID,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID
} stir_shaken_error_t;

typedef enum stir_shaken_http_req_type {
	STIR_SHAKEN_HTTP_REQ_TYPE_GET,
	STIR_SHAKEN_HTTP_REQ_TYPE_POST,
	STIR_SHAKEN_HTTP_REQ_TYPE_PUT,
	STIR_SHAKEN_HTTP_REQ_TYPE_HEAD
} stir_shaken_http_req_type_t;

typedef struct stir_shaken_context_s {
	char err_buf[1500];
	stir_shaken_error_t error;
	uint8_t got_error;
} stir_shaken_context_t;

typedef struct mem_chunk_s {
	char    *mem;
	size_t  size;
	stir_shaken_context_t	*ss;
} mem_chunk_t;

// HTTP

typedef enum stir_shaken_http_req_content_type {
	STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_JSON,
	STIR_SHAKEN_HTTP_REQ_CONTENT_TYPE_URLENCODED
} stir_shaken_http_req_content_type_t;

typedef struct stir_shaken_http_response_s {
	long			code;
	mem_chunk_t		mem;
	curl_slist_t	*headers;
} stir_shaken_http_response_t;

typedef struct stir_shaken_http_req_s {
	const char					*url;
	stir_shaken_http_req_type_t	type;
	const char					*data;
	curl_slist_t				*tx_headers;
	curl_slist_t				*rx_headers;
	stir_shaken_http_req_content_type_t content_type;
	stir_shaken_http_response_t	response;
} stir_shaken_http_req_t;


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

/**
 * The Personal Assertion Token, PASSporT: https://tools.ietf.org/html/rfc8225.
 * PASSporT implementation wrapping @jwt.
 *
 * JSON web token (JWT)
 *		JSON JOSE Header (alg, ppt, typ, x5u)
 *			alg      This value indicates the encryption algorithm. Must be 'ES256'.
 *			ppt      This value indicates the extension used. Must be 'shaken'.
 *			typ      This value indicates the token type. Must be 'passport'.
 *			x5u      This value indicates the location of the certificate used to sign the token.
 *		JWS Payload
 *			attest   This value indicates the attestation level. Must be either A, B, or C. (This is Shaken extension to PASSporT)
 *			dest     This value indicates the called number(s) or called Uniform Resource Identifier(s).
 *			iat      This value indicates the timestamp when the token was created. The timestamp is the number of seconds that have passed since the beginning of 00:00:00 UTC 1 January 1970.
 *			orig     This value indicates the calling number or calling Uniform Resource Identifier.
 *			origid   This value indicates the origination identifier. (This is Shaken extension to PASSporT)
 *		JWS Signature (when encoded, in signed form)
 *
 * Example:
 * {
 *	"alg": "ES256",
 *	"ppt": "shaken",
 *	"typ": "passport",
 *	"x5u": "http://192.168.1.4/stir-shaken/fs_stir_shaken.crt"
 * }
 * .
 * {
 *	"attest": "B",
 *	"dest": "{\"tn\":\"shaken\"}",
 *	"iat": 1234567890,
 *	"orig": "{\"tn\":\"9005551212\"}",
 *	"origid": "986279842-79894328-45254-42543525243"
 * }
 */
typedef struct stir_shaken_passport {
	jwt_t *jwt;			// PASSport JSON Web Token
} stir_shaken_passport_t;

stir_shaken_status_t		stir_shaken_passport_jwt_init(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen);
jwt_t*						stir_shaken_passport_jwt_create_new(stir_shaken_context_t *ss);
stir_shaken_status_t		stir_shaken_passport_init(stir_shaken_context_t *ss, stir_shaken_passport_t *where, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen);
stir_shaken_status_t		stir_shaken_passport_jwt_init_from_json(stir_shaken_context_t *ss, jwt_t *jwt, const char *headers_json, const char *grants_json, unsigned char *key, uint32_t keylen);
stir_shaken_passport_t*	stir_shaken_passport_create_new(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen);
void						stir_shaken_passport_destroy(stir_shaken_passport_t *passport);
stir_shaken_status_t		stir_shaken_passport_sign(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, unsigned char *key, uint32_t keylen, char **out);
const char*					stir_shaken_passport_get_header(stir_shaken_passport_t *passport, const char* key);
const char*					stir_shaken_passport_get_headers_json(stir_shaken_passport_t *passport, const char* key);
const char*					stir_shaken_passport_get_grant(stir_shaken_passport_t *passport, const char* key);
long int					stir_shaken_passport_get_grant_int(stir_shaken_passport_t *passport, const char* key);
char*						stir_shaken_passport_get_identity(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, int *is_tn);
void						stir_shaken_http_add_header(stir_shaken_http_req_t *http_req, const char *h);

/**
 * Validate that the PASSporT includes all of the baseline claims.
 */
stir_shaken_status_t stir_shaken_passport_validate_headers(stir_shaken_context_t *ss, stir_shaken_passport_t *passport);

/**
 * Validate that the PASSporT includes the SHAKEN extension claims.
 */
stir_shaken_status_t stir_shaken_passport_validate_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport);

/**
 * Validate that the PASSporT includes all of the baseline claims, as well as the SHAKEN extension claims.
 */
stir_shaken_status_t stir_shaken_passport_validate(stir_shaken_context_t *ss, stir_shaken_passport_t *passport);

/*
 * Sign the call with @passport and @key.
 * Creates JWT from @passport, signs it with @key and creates SIP Identity Header from that.
 * 
 * Returns: SIP Identity Header
 *
 * @ss - (in) context to set error if any
 * @key - (in) EC raw key used to sign the JWT token 
 * @keylen - (in) length of the EC raw key used to sign the JWT token 
 * @passport - (in) PASSporT to be used for SIP Identity Header
 *
 * NOTE: caller must free SIP Identity Header.
 */
char* stir_shaken_jwt_sip_identity_create(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, unsigned char *key, uint32_t keylen);

/*
 * Authorize the call, and return used/created PASSporT.
 * Authorize (assert/sign) call identity with cert of Service Provider.
 * Creates JWT PASSporT from @params, signs it with @key
 * and creates SIP Identity Header from that.
 *
 * Returns: SIP Identity Header and PASSporT
 * 
 * @ss - (in) context to set error if any
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 * @params - (in) describe PASSporT content
 * @key - (in) EC raw key used to sign the JWT token 
 * @keylen - (in) length of the EC raw key used to sign the JWT token 
 * @passport - (out) result PASSporT 
 *
 * NOTE: caller must free SIP Identity Header and destroy the PASSporT.
 */
stir_shaken_status_t stir_shaken_jwt_authenticate_keep_passport(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen, stir_shaken_passport_t *passport);

/*
 * Authorize the call, forget PASSporT (local PASSporT used and destroyed).
 * Authorize (assert/sign) call identity with cert of Service Provider.
 * Creates local JWT PASSporT from @params, signs it with @key
 * and creates SIP Identity Header from that, destroys JWT/PASSporT.
 *
 * Returns: SIP Identity Header
 * 
 * @ss - (in) context to set error if any
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 * @params - (in) describe PASSporT content
 * @key - (in) EC raw key used to sign the JWT token 
 * @keylen - (in) length of the EC raw key used to sign the JWT token 
 *
 * NOTE: caller must free SIP Identity Header.
 */
stir_shaken_status_t stir_shaken_jwt_authenticate(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen);

char* stir_shaken_passport_dump_str(stir_shaken_passport_t *passport, uint8_t pretty);
void stir_shaken_free_jwt_str(char *s);
void stir_shaken_jwt_move_to_passport(jwt_t *jwt, stir_shaken_passport_t *passport);

/* Global Values */
typedef struct stir_shaken_globals_s {

	pthread_mutexattr_t		attr;	
	pthread_mutex_t			mutex;	
	uint8_t					initialised;

	/** SSL */
	const SSL_METHOD    *ssl_method;
	SSL_CTX             *ssl_ctx;
	SSL                 *ssl;
	int                 curve_nid;                  // id of the curve in OpenSSL
	int					tn_authlist_nid;			// OID for ext-tnAuthList
} stir_shaken_globals_t;

extern stir_shaken_globals_t stir_shaken_globals;

/**
 * Main entry point.
 *
 * This is called on library load.
 */
//static void stir_shaken_init(void) __attribute__ ((constructor));
stir_shaken_status_t stir_shaken_do_init(stir_shaken_context_t *ss);

/**
 * Main exit point.
 *
 * This is called on library unload.
 */
//static void stir_shaken_deinit(void) __attribute__ ((destructor));
void stir_shaken_do_deinit(void);


// SSL

/**
 * Using @digest_name and @pkey create a signature for @data and save it in @out.
 * Return @out and length of it in @outlen.
 */ 
stir_shaken_status_t stir_shaken_do_sign_data_with_digest(stir_shaken_context_t *ss, const char *digest_name, EVP_PKEY *pkey, const char *data, size_t datalen, unsigned char *out, size_t *outlen);

/**
 * Generate new keys. Always removes old files.
 */
stir_shaken_status_t stir_shaken_generate_keys(stir_shaken_context_t *ss, EC_KEY **eck, EVP_PKEY **priv, EVP_PKEY **pub, const char *private_key_full_name, const char *public_key_full_name, unsigned char *priv_raw, uint32_t *priv_raw_len);

/**
 * Call SSL destructors and release memory used for SSL keys.
 */
void stir_shaken_destroy_keys(EC_KEY **eck, EVP_PKEY **priv, EVP_PKEY **pub);

/**
 * 
 * Generate CSR needed by STI-CA to issue new cert.
 * 
 * @sp_code - (in) Service Provider code
 * @csr - (out) result
 */
stir_shaken_status_t stir_shaken_generate_csr(stir_shaken_context_t *ss, uint32_t sp_code, X509_REQ **csr_req, EVP_PKEY *private_key, EVP_PKEY *public_key, const char *csr_full_name, const char *csr_text_full_name);
void stir_shaken_destroy_csr(X509_REQ **csr_req);

/**
 * Generate self signed X509 certificate from csr @req.
 *
 * @sp_code - (in) Service Provider code
 * @req - (in) X509 certificate sign request
 */
X509 * stir_shaken_generate_x509_self_sign(stir_shaken_context_t *ss, uint32_t sp_code, X509_REQ *req, EVP_PKEY *private_key, int expiry_days);

/**
 * @buf - (out) will contain fingerprint, must be of size at least 3*EVP_MAX_MD_SIZE bytes
 * @buflen - (out) will contain string len including '\0'
 */
stir_shaken_status_t stir_shaken_extract_fingerprint(stir_shaken_context_t *ss, X509* x509, const char *digest_name, char *buf, int *buflen);

X509* stir_shaken_make_cert_from_public_key(stir_shaken_context_t *ss, EVP_PKEY *pkey);

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
stir_shaken_status_t stir_shaken_generate_cert_from_csr(stir_shaken_context_t *ss, uint32_t sp_code, stir_shaken_cert_t *cert, stir_shaken_csr_t *csr, EVP_PKEY *private_key, EVP_PKEY *public_key, const char *cert_full_name, const char *cert_text_full_name, int expiry_days);
void stir_shaken_destroy_cert_fields(stir_shaken_cert_t *cert);
void stir_shaken_destroy_cert(stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_read_cert_fields(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
void stir_shaken_cert_validation_cleanup(stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_cert_init_validation(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, char *ca_list, char *ca_dir, char *crl_list, char *crl_dir);
stir_shaken_status_t stir_shaken_verify_cert_root(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_verify_cert_tn_authlist_extension(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_verify_cert(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_serialHex(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_serialDec(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_notBefore(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_notAfter(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_issuer(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_subject(stir_shaken_cert_t *cert);
int stir_shaken_cert_get_version(stir_shaken_cert_t *cert);

stir_shaken_status_t stir_shaken_load_cert_from_mem(stir_shaken_context_t *ss, X509 **x, STACK_OF(X509) **xchain, void *mem, size_t n);
stir_shaken_status_t stir_shaken_load_cert_from_mem_through_file(stir_shaken_context_t *ss, X509 **x, void *mem, size_t n);
stir_shaken_status_t stir_shaken_load_cert_from_file(stir_shaken_context_t *ss, X509 **x, const char *cert_tmp_name);
stir_shaken_status_t stir_shaken_load_cert_and_key(stir_shaken_context_t *ss, const char *cert_name, stir_shaken_cert_t *cert, const char *private_key_name, EVP_PKEY **pkey, unsigned char *priv_raw, uint32_t *priv_raw_len);
stir_shaken_status_t stir_shaken_get_csr_raw(stir_shaken_context_t *ss, X509_REQ *req, unsigned char *body, int *body_len);
stir_shaken_status_t stir_shaken_get_cert_raw(stir_shaken_context_t *ss, X509 *x, unsigned char *raw, int *raw_len);
stir_shaken_status_t stir_shaken_evp_key_to_raw(stir_shaken_context_t *ss, EVP_PKEY *evp_key, unsigned char *key, int *key_len);
stir_shaken_status_t stir_shaken_get_pubkey_raw_from_cert(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, unsigned char *key, int *key_len);
stir_shaken_status_t stir_shaken_create_jwk(stir_shaken_context_t *ss, EC_KEY *ec_key, const char *kid, cJSON **jwk);
stir_shaken_status_t stir_shaken_init_ssl(stir_shaken_context_t *ss);
void stir_shaken_deinit_ssl(void);


// Verification service

stir_shaken_status_t stir_shaken_stisp_verify_stica(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, cJSON *array);
int stir_shaken_verify_data(stir_shaken_context_t *ss, const char *data, const char *signature, size_t siglen, EVP_PKEY *pkey);
int stir_shaken_do_verify_data_file(stir_shaken_context_t *ss, const char *data_filename, const char *signature_filename, EVP_PKEY *public_key);
int stir_shaken_do_verify_data(stir_shaken_context_t *ss, const void *data, size_t datalen, const unsigned char *sig, size_t siglen, EVP_PKEY *public_key);

stir_shaken_status_t stir_shaken_download_cert(stir_shaken_context_t *ss, const char *url, mem_chunk_t *chunk);
stir_shaken_status_t stir_shaken_download_cert_to_file(const char *url, const char *file);

/**
 * Verify (check/authenticate) call identity.
 *
 * @sdp - (in) SDP call description
 */
stir_shaken_status_t stir_shaken_verify_with_cert(stir_shaken_context_t *ss, const char *identity_header, stir_shaken_cert_t *cert);

/**
 * Perform STIR-Shaken verification of the @identity_header.
 *
 * This will first process @identity_header into JWT token and parameters including cert URL.
 * This will then attempt to obtain certificate referenced by SIP @identity_header
 * and if successful then will verify JWT against public key from cert.
 * If successful retrieved PASSporT is returned via @passport and STI cert via @cert.
 *
 * NOTE: @passport should point to allocated memory big enough to create PASSporT, @cert may be NULL (will be malloced then and it is caller's responsibility to free it).
 */
stir_shaken_status_t stir_shaken_verify(stir_shaken_context_t *ss, const char *sih, const char *cert_url, stir_shaken_passport_t *passport, cJSON *stica_array, stir_shaken_cert_t **cert);

/* PASSporT verification.
 *
 * @passport - (in/out) should point to memory prepared for new PASSporT,
 *				on exit retrieved and verified PASSporT JWT is moved into that @passport
 * @stica_array - if not NULL then validate the root of the digital signature in the STI certificate
 *				by determining whether the STI-CA that issued the STI certificate is in the list of approved STI-CAs
 */ 
stir_shaken_status_t stir_shaken_jwt_verify_with_cert(stir_shaken_context_t *ss, const char *identity_header, stir_shaken_cert_t *cert, stir_shaken_passport_t *passport, cJSON *stica_array);


// Authorization service

/**
 * Create JSON token from call @pparams.
 */
cJSON* stir_shaken_passport_create_json(stir_shaken_context_t *ss, stir_shaken_passport_params_t *pparams);
void stir_shaken_passport_destroy(stir_shaken_passport_t *passport);

/**
 * Create signatures in @jwt and save intermediate results in @info.
 */
stir_shaken_status_t stir_shaken_passport_finalise_json(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, EVP_PKEY *pkey);

/**
 * Initialise PASSporT pointed to by @passport using call @params and sign it with @pkey.
 */
stir_shaken_status_t stir_shaken_passport_create(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, stir_shaken_passport_params_t *params, EVP_PKEY *pkey);

/**
 * @name - physiacall location (complete name)
 * @install_dir - directory where the cert will be placed under name of (basename(@name))
 * @install_url - directory part of publicly accessible URL that will be embedded as @x5u in PASSporT (complete URL in @x5u will be set to @public_url = @install_url + @name)
 */
stir_shaken_status_t stir_shaken_cert_configure(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, const char *name, const char *install_dir, const char *install_url);
stir_shaken_status_t stir_shaken_install_cert(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);

/**
 * Authorize the call and keep PASSporT if the @keep_pasport is true.
 */
stir_shaken_status_t stir_shaken_authorize_keep_passport(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport, uint8_t keep_passport, EVP_PKEY *pkey, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_authorize_self_trusted(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_cert_t *cert);

/**
 * Authorize (assert/sign) call with SIP Identity Header for Service Provider identified by @sp_code.
 *
 * @sih - (out) on success points to SIP Identity Header which is authentication of the call
 * @sp_code - (in) Service Provider Code which uniquely identifies Service Provider within their STI-CA (Cert Authority)
 * @stica - (in) STI-CA description (this can be configured from dialplan config / channel variables, or by consulting other lookup service)
 * @params - call params in terms of STIR Shaken's PASSporT
 */
stir_shaken_status_t stir_shaken_authorize(stir_shaken_context_t *ss, char **sih, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_cert_t *cert);

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
 * X            // attest   This value indicates the attestation level. Must be either A, B, or C. (This is Shaken extension to PASSporT)
 * X            // dest     This value indicates the called number(s) or called Uniform Resource Identifier(s).
 *              // iat      This value indicates the timestamp when the token was created. The timestamp is the number of seconds that have passed since the beginning of 00:00:00 UTC 1 January 1970.
 * X            // orig     This value indicates the calling number or calling Uniform Resource Identifier.
 * X            // origid   This value indicates the origination identifier. (This is Shaken extension to PASSporT)
 *          // JWS Signature
 *
 *      // Parameters
 *          //Alg
 * (==x5u)	//Info	(X [needed], but implicitely copied from @x5u)
 *          //PPT
 */ 
char* stir_shaken_do_sign(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, EVP_PKEY *pkey);

char* stir_shaken_sip_identity_create(stir_shaken_context_t *ss, stir_shaken_passport_t *passport);

/*
 * Sign the call data with the @pkey, and keep pointer to created PASSporT if @keep_passport is true. 
 * SIP Identity header is returned and PASSporT.
 * @passport - (out) will point to created PASSporT
 */
char * stir_shaken_do_sign_keep_passport(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, EVP_PKEY *pkey, stir_shaken_passport_t **passport, uint8_t keep_passport);


// Service

char*					stir_shaken_stisp_acme_generate_cert_req_payload(stir_shaken_context_t *ss, const char *kid, const char *nonce, const char *url, X509_REQ *req, const char *nb, const char *na, unsigned char *key, uint32_t keylen, char **json);
char*					stir_shaken_stisp_acme_generate_auth_challenge_token(stir_shaken_context_t *ss, char *kid, char *nonce, char *url, char *sp_code_token, unsigned char *key, uint32_t keylen, char **json);
char*					stir_shaken_stisp_acme_generate_new_account_req_payload(stir_shaken_context_t *ss, char *jwk, char *nonce, char *url, char *contact_mail, char *contact_tel, unsigned char *key, uint32_t keylen, char **json);
stir_shaken_status_t	stir_shaken_make_http_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
void					stir_shaken_destroy_http_request(stir_shaken_http_req_t *http_req);

/**
 * @http_req - (out) will contain HTTP response
 */
stir_shaken_status_t stir_shaken_stisp_make_code_token_request(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, const char *fingerprint);

/**
 * The STI-PA manages an active, secure list of approved STI-CAs in the form of their public key certificates.
 * The STI-PA provides this list of approved STI-CAs to the service providers via a Hypertext Transfer Protocol
 * Secure (HTTPS) interface. The SHAKEN-defined Secure Telephone Identity Verification Service (STI-VS) can then use
 * a public key certificate to validate the root of the digital signature in the STI certificate by determining
 * whether the STI-CA that issued the STI certificate is in the list of approved STI-CAs. Note that the details
 * associated with the structure and management of this list require further specification.
 */
stir_shaken_status_t stir_shaken_stisp_make_stica_list_request(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url);

stir_shaken_status_t	stir_shaken_make_http_get_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url);
stir_shaken_status_t	stir_shaken_make_http_post_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, char *data, uint8_t json);
stir_shaken_status_t	stir_shaken_make_http_head_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, char *data, uint8_t is_json);
char*					stir_shaken_get_http_header(stir_shaken_http_req_t *http_req, char *name);

// Utility

stir_shaken_status_t stir_shaken_dir_exists(const char *path);
stir_shaken_status_t stir_shaken_dir_create(const char *path);
stir_shaken_status_t stir_shaken_dir_create_recursive(const char *path);
stir_shaken_status_t stir_shaken_file_exists(const char *path);
stir_shaken_status_t stir_shaken_file_remove(const char *path);
stir_shaken_status_t stir_shaken_b64_encode(unsigned char *in, size_t ilen, unsigned char *out, size_t olen);
size_t stir_shaken_b64_decode(const char *in, char *out, size_t olen);
char* stir_shaken_remove_multiple_adjacent(char *in, char what);
char* stir_shaken_get_dir_path(const char *path);
char* stir_shaken_make_complete_path(char *buf, int buflen, const char *dir, const char *file, const char *path_separator);

void stir_shaken_do_set_error(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line);
void stir_shaken_do_set_error_if_clear(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line);
void stir_shaken_clear_error(stir_shaken_context_t *ss);
uint8_t stir_shaken_is_error_set(stir_shaken_context_t *ss);
const char* stir_shaken_get_error(stir_shaken_context_t *ss, stir_shaken_error_t *error);

#define stir_shaken_set_error(ss, description, error) stir_shaken_do_set_error(ss, description, error, __FILE__, __LINE__)
#define stir_shaken_set_error_if_clear(ss, description, error) stir_shaken_do_set_error_if_clear(ss, description, error, __FILE__, __LINE__)


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

// Test 10
stir_shaken_status_t stir_shaken_unit_test_verify_response(void);

#endif // __STIR_SHAKEN
