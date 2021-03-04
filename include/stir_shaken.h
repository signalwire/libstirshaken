#ifndef __STIR_SHAKEN
#define __STIR_SHAKEN

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include <libks/ks.h>

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

#define stir_shaken_min(x, y) ((x) < (y)? (x) : (y))

#define STIR_SHAKEN_VERSION "1.0"

#define PBUF_LEN 1000
#define STIR_SHAKEN_ERROR_BUF_LEN 1000
#define STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN 2000
#define STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN 2000
#define ASN1_DATE_LEN 128
#define STIR_SHAKEN_SSL_BUF_LEN 1000
#define STIR_SHAKEN_BUFLEN 1000

#define TN_AUTH_LIST_OID "1.3.6.1.5.5.7.1.26"
#define TN_AUTH_LIST_LN "TNAuthorizationList"
#define TN_AUTH_LIST_SN "TNAuthList"

#define STIR_SHAKEN_DIGEST_NAME "sha256"

#define STIR_SHAKEN_MOCK_VERIFY_CERT_CHAIN 0
#define STIR_SHAKEN_LOAD_CA_FROM_DEFAULT_OS_PATHS 0
#define STIR_SHAKEN_CERT_ADD_SIGNALWIRE_EXTENSION 1
#define STIR_SHAKEN_DEFAULT_CA_PORT 80

#define STIR_SHAKEN_MOCK_ACME_NONCE_REQ 0
#define STIR_SHAKEN_NONCE_FRESHNESS 999999
#define STIR_SHAKEN_CHECK_AUTHORITY_OVER_NUMBER 0

#define STIR_SHAKEN_LOGLEVEL_NOTHING 0
#define STIR_SHAKEN_LOGLEVEL_BASIC 1
#define STIR_SHAKEN_LOGLEVEL_MEDIUM 2
#define STIR_SHAKEN_LOGLEVEL_HIGH 3

#define STIR_SHAKEN_HTTPS_SKIP_PEER_VERIFICATION 0
#define STIR_SHAKEN_HTTPS_SKIP_HOSTNAME_VERIFICATION 0

typedef struct stir_shaken_acme_nonce_s {
	size_t	timestamp;
	char	*response;
} stir_shaken_acme_nonce_t;


typedef enum stir_shaken_cert_type {
	STIR_SHAKEN_CERT_TYPE_ROOT,
	STIR_SHAKEN_CERT_TYPE_CA,
	STIR_SHAKEN_CERT_TYPE_SELF_SIGNED,
} stir_shaken_cert_type_t;


typedef enum stir_shaken_status {
	STIR_SHAKEN_STATUS_OK,
	STIR_SHAKEN_STATUS_FALSE,
	STIR_SHAKEN_STATUS_ERR,
	STIR_SHAKEN_STATUS_RESTART,
	STIR_SHAKEN_STATUS_NOOP,
	STIR_SHAKEN_STATUS_TERM,
	STIR_SHAKEN_STATUS_HANDLED,
	STIR_SHAKEN_STATUS_NOT_HANDLED,
} stir_shaken_status_t;

typedef enum stir_shaken_http_response_status {
	STIR_SHAKEN_HTTP_RESPONSE_STATUS_COULDNT_RESOLVE_PROXY = 5,
	STIR_SHAKEN_HTTP_RESPONSE_STATUS_COULDNT_RESOLVE_HOST = 6,
	STIR_SHAKEN_HTTP_RESPONSE_STATUS_COULDNT_CONNECT = 7,
	STIR_SHAKEN_HTTP_RESPONSE_STATUS_REMOTE_ACCESS_DENIED = 9
} stir_shaken_http_response_status_t;

typedef struct stir_shaken_csr_s {
	X509_REQ    *req;
	char		*pem;
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
	X509_STORE_CTX	*verify_ctx;			// Verification SSL context using @store to validate cert chain against CA list and CRL
	char        *body;
	uint8_t     is_fresh;
	char		install_dir[STIR_SHAKEN_BUFLEN];			// folder, where cert must be put to be accessible with @public_url for other SPs
	char		install_url[STIR_SHAKEN_BUFLEN];			// directory part of the publicly accessible URL
	char		public_url[STIR_SHAKEN_BUFLEN];				// publicly accessible URL which can be used to download the certificate, this is concatenated from @install_url and cert's @name and is put into PASSporT as @x5u and @params.info
	EC_KEY              *ec_key;
	EVP_PKEY            *private_key;

	unsigned long	hash;							// hash of cert name
	char			hashstr[STIR_SHAKEN_BUFLEN];	// hashed name as string
	char			cert_name_hashed[STIR_SHAKEN_BUFLEN];	// hashed name with .0 appended - ready to save in CA dir for usage with X509 cert path validation check

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
	unsigned char	pub_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN];
	uint32_t		pub_raw_len;
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
	STIR_SHAKEN_ERROR_BASIC_INIT,
	STIR_SHAKEN_ERROR_INIT_SSL,
	STIR_SHAKEN_ERROR_BASIC_AND_SSL_INIT,
	STIR_SHAKEN_ERROR_CREATE_CA_DIR,
	STIR_SHAKEN_ERROR_CA_DIR_DSNT_EXIST_1,
	STIR_SHAKEN_ERROR_CA_DIR_DSNT_EXIST_2,
	STIR_SHAKEN_ERROR_CRL_DIR_DSNT_EXIST_1,
	STIR_SHAKEN_ERROR_CRL_DIR_DSNT_EXIST_2,
	STIR_SHAKEN_ERROR_LOAD_CA_1,
	STIR_SHAKEN_ERROR_LOAD_CA_2,
	STIR_SHAKEN_ERROR_LOAD_CRL_1,
	STIR_SHAKEN_ERROR_LOAD_CRL_2,
	STIR_SHAKEN_ERROR_SET_DEFAULT_PATHS_1,
	STIR_SHAKEN_ERROR_SET_DEFAULT_PATHS_2,
	STIR_SHAKEN_ERROR_CREATE_CRL_DIR,
	STIR_SHAKEN_ERROR_LIB_NOT_INITIALISED,
	STIR_SHAKEN_ERROR_LIB_ALREADY_INITIALISED,
	STIR_SHAKEN_ERROR_GET_CSR_RAW,
	STIR_SHAKEN_ERROR_BASE64_ENCODE,
	STIR_SHAKEN_ERROR_EC_KEY_SET,
	STIR_SHAKEN_ERROR_PUBKEY_SET,
	STIR_SHAKEN_ERROR_PRIVKEY_SET,
	STIR_SHAKEN_ERROR_BAD_PARAMS_1,
	STIR_SHAKEN_ERROR_BAD_PARAMS_2,
	STIR_SHAKEN_ERROR_BAD_PARAMS_3,
	STIR_SHAKEN_ERROR_BAD_PARAMS_4,
	STIR_SHAKEN_ERROR_BAD_PARAMS_5,
	STIR_SHAKEN_ERROR_BAD_PARAMS_6,
	STIR_SHAKEN_ERROR_BAD_PARAMS_7,
	STIR_SHAKEN_ERROR_BAD_PARAMS_8,
	STIR_SHAKEN_ERROR_BAD_PARAMS_9,
	STIR_SHAKEN_ERROR_BAD_PARAMS_10,
	STIR_SHAKEN_ERROR_BAD_PARAMS_11,
	STIR_SHAKEN_ERROR_BAD_PARAMS_12,
	STIR_SHAKEN_ERROR_BAD_PARAMS_13,
	STIR_SHAKEN_ERROR_BAD_PARAMS_14,
	STIR_SHAKEN_ERROR_BAD_PARAMS_15,
	STIR_SHAKEN_ERROR_BAD_PARAMS_16,
	STIR_SHAKEN_ERROR_BAD_PARAMS_17,
	STIR_SHAKEN_ERROR_BAD_PARAMS_18,
	STIR_SHAKEN_ERROR_BAD_PARAMS_19,
	STIR_SHAKEN_ERROR_BAD_PARAMS_20,
	STIR_SHAKEN_ERROR_BAD_PARAMS_21,
	STIR_SHAKEN_ERROR_BAD_PARAMS_22,
	STIR_SHAKEN_ERROR_BAD_PARAMS_23,
	STIR_SHAKEN_ERROR_BAD_PARAMS_24,
	STIR_SHAKEN_ERROR_SIH_TO_JWT_1,
	STIR_SHAKEN_ERROR_SIH_TO_JWT_2,
	STIR_SHAKEN_ERROR_KSJSON,
	STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_1,
	STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_2,
	STIR_SHAKEN_ERROR_KSJSON_ADD_IAT,
	STIR_SHAKEN_ERROR_KSJSON_ADD_ATTEST,
	STIR_SHAKEN_ERROR_KSJSON_ADD_ORIGID,
	STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_ORIG,
	STIR_SHAKEN_ERROR_KSJSON_CREATE_ARRAY_ORIG,
	STIR_SHAKEN_ERROR_KSJSON_ADD_ORIG_TO_ARRAY,
	STIR_SHAKEN_ERROR_KSJSON_ADD_ORIG_ARRAY,
	STIR_SHAKEN_ERROR_KSJSON_ADD_TN,
	STIR_SHAKEN_ERROR_KSJSON_ADD_ORIG,
	STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_DEST,
	STIR_SHAKEN_ERROR_KSJSON_CREATE_ARRAY_DEST,
	STIR_SHAKEN_ERROR_KSJSON_ADD_DEST_TO_ARRAY,
	STIR_SHAKEN_ERROR_KSJSON_ADD_DEST_ARRAY,
	STIR_SHAKEN_ERROR_KSJSON_ADD_DEST,
	STIR_SHAKEN_ERROR_CURL,
	STIR_SHAKEN_ERROR_STICA_NOT_APPROVED,
	STIR_SHAKEN_ERROR_SSL_1,
	STIR_SHAKEN_ERROR_SSL_2,
	STIR_SHAKEN_ERROR_SSL_3,
	STIR_SHAKEN_ERROR_SSL_4,
	STIR_SHAKEN_ERROR_SSL_5,
	STIR_SHAKEN_ERROR_SSL_6,
	STIR_SHAKEN_ERROR_SSL_7,
	STIR_SHAKEN_ERROR_SSL_BIO_NEW_MEM_BUF_1,
	STIR_SHAKEN_ERROR_SSL_BIO_NEW_MEM_BUF_2,
	STIR_SHAKEN_ERROR_SSL_BIO_NEW_FILE_1,
	STIR_SHAKEN_ERROR_SSL_BIO_NEW_FILE_2,
	STIR_SHAKEN_ERROR_SSL_BIO_NEW_FILE_3,
	STIR_SHAKEN_ERROR_SSL_BIO_READ_FILE_1,
	STIR_SHAKEN_ERROR_SSL_BIO_READ_FILE_2,
	STIR_SHAKEN_ERROR_SSL_BIO_READ_MEM_1,
	STIR_SHAKEN_ERROR_SSL_BIO_READ_MEM_2,
	STIR_SHAKEN_ERROR_SSL_BIO_READ_MEM_3,
	STIR_SHAKEN_ERROR_SSL_BIO_READ_MEM_4,
	STIR_SHAKEN_ERROR_SSL_PEM_READ_BIO_PUBKEY_1,
	STIR_SHAKEN_ERROR_SSL_PEM_READ_BIO_PRIVKEY_1,
	STIR_SHAKEN_ERROR_SSL_PEM_WRITE_BIO_PUBKEY_1,
	STIR_SHAKEN_ERROR_SSL_PEM_WRITE_BIO_PRIVKEY_1,
	STIR_SHAKEN_ERROR_SSL_PEM_READ_BIO_X509_1,
	STIR_SHAKEN_ERROR_SSL_PEM_READ_BIO_X509_2,
	STIR_SHAKEN_ERROR_SSL_LOAD_PUBKEY_FROM_FILE_1,
	STIR_SHAKEN_ERROR_SSL_LOAD_PUBKEY_FROM_FILE_2,
	STIR_SHAKEN_ERROR_SSL_LOAD_PRIVKEY_FROM_FILE_1,
	STIR_SHAKEN_ERROR_SSL_LOAD_PRIVKEY_FROM_FILE_2,
	STIR_SHAKEN_ERROR_SSL_LOAD_PRIVKEY_FROM_FILE_3,
	STIR_SHAKEN_ERROR_SSL_LOAD_KEY_RAW_1,
	STIR_SHAKEN_ERROR_SSL_LOAD_KEY_RAW_2,
	STIR_SHAKEN_ERROR_SSL_LOAD_KEY_RAW_3,
	STIR_SHAKEN_ERROR_SSL_MDCTX_CREATE_1,
	STIR_SHAKEN_ERROR_SSL_MDCTX_CREATE_2,
	STIR_SHAKEN_ERROR_SSL_MDCTX_INIT_1,
	STIR_SHAKEN_ERROR_SSL_MDCTX_INIT_2,
	STIR_SHAKEN_ERROR_SSL_MDCTX_UPDATE_1,
	STIR_SHAKEN_ERROR_SSL_MDCTX_UPDATE_2,
	STIR_SHAKEN_ERROR_SSL_MDCTX_SIGN_1,
	STIR_SHAKEN_ERROR_SSL_MDCTX_SIGN_2,
	STIR_SHAKEN_ERROR_SSL_MDCTX_ERROR,
	STIR_SHAKEN_ERROR_SSL_BN_NUM_BYTES,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_NEW_BY_CURVE_NAME,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_GENERATE,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_CHECK,
	STIR_SHAKEN_ERROR_SSL_KEY_TYPE_1,
	STIR_SHAKEN_ERROR_SSL_KEY_TYPE_2,
	STIR_SHAKEN_ERROR_SSL_GET_DIGEST_BY_NAME_1,
	STIR_SHAKEN_ERROR_SSL_GET_DIGEST_BY_NAME_2,
	STIR_SHAKEN_ERROR_SSL_GET_EC_KEY_1,
	STIR_SHAKEN_ERROR_SSL_GET_EC_KEY_2,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_GET_GROUP_1,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_GET_GROUP_2,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_GET_GROUP_3,
	STIR_SHAKEN_ERROR_SSL_EC_POINT_COORDINATE,
	STIR_SHAKEN_ERROR_SSL_D2I_ECDSA_SIGNATURE,
	STIR_SHAKEN_ERROR_SSL_ECDSA_SIG_NEW,
	STIR_SHAKEN_ERROR_SSL_EC_SIG_1,
	STIR_SHAKEN_ERROR_SSL_EC_SIG_2,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_GET_PUBKEY_1,
	STIR_SHAKEN_ERROR_SSL_EC_KEY_GET_PUBKEY_2,
	STIR_SHAKEN_ERROR_SSL_GROUP_DEGREE,
	STIR_SHAKEN_ERROR_SSL_METHOD,
	STIR_SHAKEN_ERROR_SSL_NEW,
	STIR_SHAKEN_ERROR_SSL_GET_CURVES,
	STIR_SHAKEN_ERROR_SSL_X962SECG_CURVE,
	STIR_SHAKEN_ERROR_SSL_ALLOCA_1,
	STIR_SHAKEN_ERROR_SSL_ALLOCA_2,
	STIR_SHAKEN_ERROR_CERT_NOT_SET,
	STIR_SHAKEN_ERROR_CERT_INIT,
	STIR_SHAKEN_ERROR_CERT_INVALID,
	STIR_SHAKEN_ERROR_CERT_STORE_1,
	STIR_SHAKEN_ERROR_CERT_STORE_2,
	STIR_SHAKEN_ERROR_CERT_VERSION,
	STIR_SHAKEN_ERROR_CERT_NOT_VALID_YET,
	STIR_SHAKEN_ERROR_CERT_EXPIRED,
	STIR_SHAKEN_ERROR_CERT_DOWNLOAD,
	STIR_SHAKEN_ERROR_CERT_FETCH_OR_DOWNLOAD,
	STIR_SHAKEN_ERROR_CERT_COPY,
	STIR_SHAKEN_ERROR_PUBKEY_GET,
	STIR_SHAKEN_ERROR_PRIVKEY_MISSING_1,
	STIR_SHAKEN_ERROR_PRIVKEY_MISSING_2,
	STIR_SHAKEN_ERROR_PRIVKEY_MISSING_3,
	STIR_SHAKEN_ERROR_DIGEST_GET,
	STIR_SHAKEN_ERROR_SIP_403_STALE_DATE,
	STIR_SHAKEN_ERROR_SIP_428_USE_IDENTITY_HEADER,
	STIR_SHAKEN_ERROR_SIP_436_BAD_IDENTITY_INFO,
	STIR_SHAKEN_ERROR_SIP_437_UNSUPPORTED_CREDENTIAL,
	STIR_SHAKEN_ERROR_SIP_438_INVALID_IDENTITY_HEADER,
	STIR_SHAKEN_ERROR_AUTHORITY_CHECK,
	STIR_SHAKEN_ERROR_HTTP_400_BAD_REQUEST,
	STIR_SHAKEN_ERROR_HTTP_403_FORBIDDEN,
	STIR_SHAKEN_ERROR_HTTP_404_INVALID,
	STIR_SHAKEN_ERROR_HTTP_404_NOT_FOUND,
	STIR_SHAKEN_ERROR_HTTP_GENERAL,
	STIR_SHAKEN_ERROR_HTTP_PARAMS,
	STIR_SHAKEN_ERROR_HTTPS_CERT,
	STIR_SHAKEN_ERROR_HTTPS_KEY,
	STIR_SHAKEN_ERROR_JWT,
	STIR_SHAKEN_ERROR_JWT_VERIFY_1,
	STIR_SHAKEN_ERROR_JWT_VERIFY_2,
	STIR_SHAKEN_ERROR_JWT_CERT_MALFORMED_1,
	STIR_SHAKEN_ERROR_JWT_CERT_MALFORMED_2,
	STIR_SHAKEN_ERROR_JWT_CERT_INVALID_1,
	STIR_SHAKEN_ERROR_JWT_CERT_INVALID_2,
	STIR_SHAKEN_ERROR_JWT_CERT_X509_PATH_INVALID_1,
	STIR_SHAKEN_ERROR_JWT_CERT_X509_PATH_INVALID_2,
	STIR_SHAKEN_ERROR_JWT_DECODE,
	STIR_SHAKEN_ERROR_JWT_VERIFY_AND_CHECK_X509_CERT_PATH_1,
	STIR_SHAKEN_ERROR_JWT_VERIFY_AND_CHECK_X509_CERT_PATH_2,
	STIR_SHAKEN_ERROR_JWT_ADD_HDR_PPT,
	STIR_SHAKEN_ERROR_JWT_ADD_HDR_TYP,
	STIR_SHAKEN_ERROR_JWT_ADD_HDR_X5U,
	STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_1,
	STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_2,
	STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_3,
	STIR_SHAKEN_ERROR_JWT_ADD_HEADERS_JSON,
	STIR_SHAKEN_ERROR_JWT_ADD_GRANTS_JSON,
	STIR_SHAKEN_ERROR_JWT_ENCODE,
	STIR_SHAKEN_ERROR_JSON,
	STIR_SHAKEN_ERROR_ACME,
	STIR_SHAKEN_ERROR_ACME_URI,
	STIR_SHAKEN_ERROR_ACME_SPC_TOO_BIG,
	STIR_SHAKEN_ERROR_ACME_SPC_INVALID,
	STIR_SHAKEN_ERROR_ACME_SPC_TOKEN_INVALID,
	STIR_SHAKEN_ERROR_ACME_SPC_TOKEN_INVALID_PA,
	STIR_SHAKEN_ERROR_ACME_SECRET_TOO_BIG,
	STIR_SHAKEN_ERROR_ACME_SECRET_INVALID,
	STIR_SHAKEN_ERROR_ACME_SESSION_EXISTS,
	STIR_SHAKEN_ERROR_ACME_SESSION_NOTFOUND,
	STIR_SHAKEN_ERROR_ACME_SESSION_BAD_SECRET,
	STIR_SHAKEN_ERROR_ACME_SESSION_NOT_SET,
	STIR_SHAKEN_ERROR_ACME_SESSION_CREATE,
	STIR_SHAKEN_ERROR_ACME_SESSION_ENQUEUE,
	STIR_SHAKEN_ERROR_ACME_SESSION_WRONG_STATE,
	STIR_SHAKEN_ERROR_ACME_SESSION_NOT_AUTHORIZED,
	STIR_SHAKEN_ERROR_ACME_EMPTY_CA_RESPONSE,
	STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_CHALLENGE_RESPONSE,
	STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_CHALLENGE_DETAILS,
	STIR_SHAKEN_ERROR_ACME_EMPTY_CA_AUTH_DETAILS_RESPONSE,
	STIR_SHAKEN_ERROR_ACME_AUTHZ_SPC,
	STIR_SHAKEN_ERROR_ACME_AUTHZ_DETAILS,
	STIR_SHAKEN_ERROR_ACME_AUTHZ_URI,
	STIR_SHAKEN_ERROR_ACME_AUTHZ_POLLING,
	STIR_SHAKEN_ERROR_ACME_AUTHZ_UNSUCCESSFUL,
	STIR_SHAKEN_ERROR_ACME_CERT,
	STIR_SHAKEN_ERROR_ACME_CERT_SPC,
	STIR_SHAKEN_ERROR_ACME_SECRET_MISSING,
	STIR_SHAKEN_ERROR_ACME_BAD_REQUEST,
	STIR_SHAKEN_ERROR_ACME_BAD_AUTHZ_POLLING_STATUS,
	STIR_SHAKEN_ERROR_ACME_BAD_MESSAGE,
	STIR_SHAKEN_ERROR_PASSPORT_SIGN,
	STIR_SHAKEN_ERROR_SIH_MEM,
	STIR_SHAKEN_ERROR_SIH_JWT_MOVE_TO_PASSPORT_1,
	STIR_SHAKEN_ERROR_SIH_JWT_MOVE_TO_PASSPORT_2,
	STIR_SHAKEN_ERROR_SIH_JWT_MOVE_TO_PASSPORT_3,
	STIR_SHAKEN_ERROR_TNAUTHLIST_1,
	STIR_SHAKEN_ERROR_TNAUTHLIST_2,
	STIR_SHAKEN_ERROR_X509_NEW_1,
	STIR_SHAKEN_ERROR_X509_NEW_2,
	STIR_SHAKEN_ERROR_SSL_X509_SK,
	STIR_SHAKEN_ERROR_X509_CERT_PATH_INVALID,
	STIR_SHAKEN_ERROR_X509_TNAUTHLIST_ADD,
	STIR_SHAKEN_ERROR_X509_TNAUTHLIST_GET,
	STIR_SHAKEN_ERROR_X509_TNAUTHLIST_INVALID,
	STIR_SHAKEN_ERROR_X509_TNAUTHLIST_REGISTER,
	STIR_SHAKEN_ERROR_X509_DIGEST,
	STIR_SHAKEN_ERROR_X509_MISSING_1,
	STIR_SHAKEN_ERROR_X509_MISSING_2,
	STIR_SHAKEN_ERROR_X509_MISSING_3,
	STIR_SHAKEN_ERROR_X509_MISSING_4,
	STIR_SHAKEN_ERROR_X509_MISSING_5,
	STIR_SHAKEN_ERROR_X509_MISSING_6,
	STIR_SHAKEN_ERROR_X509_MISSING_7,
	STIR_SHAKEN_ERROR_X509_SUBJECT_C_MISSING,
	STIR_SHAKEN_ERROR_X509_SUBJECT_CN_MISSING,
	STIR_SHAKEN_ERROR_X509_ISSUER_C_MISSING,
	STIR_SHAKEN_ERROR_X509_ISSUER_CN_MISSING,
	STIR_SHAKEN_ERROR_X509_SUBJECT_CERT_MISSING_1,
	STIR_SHAKEN_ERROR_X509_SUBJECT_CERT_MISSING_2,
	STIR_SHAKEN_ERROR_X509_SUBJECT_CERT_MISSING_3,
	STIR_SHAKEN_ERROR_X509_SUBJECT_CERT_MISSING_4,
	STIR_SHAKEN_ERROR_X509_ISSUER_CERT_MISSING_1,
	STIR_SHAKEN_ERROR_X509_ISSUER_CERT_MISSING_2,
	STIR_SHAKEN_ERROR_X509_ISSUER_CERT_MISSING_3,
	STIR_SHAKEN_ERROR_X509_ISSUER_CERT_MISSING_4,
	STIR_SHAKEN_ERROR_X509_TNAUTHLIST_URI_MISSING,
	STIR_SHAKEN_ERROR_X509_SET_VERSION,
	STIR_SHAKEN_ERROR_X509_SET_PUBKEY,
	STIR_SHAKEN_ERROR_X509_SET_PRIVKEY,
	STIR_SHAKEN_ERROR_X509_SET_SERIAL,
	STIR_SHAKEN_ERROR_X509_SET_ISSUER_C,
	STIR_SHAKEN_ERROR_X509_SET_ISSUER_CN,
	STIR_SHAKEN_ERROR_X509_SET_ISSUER_NAME,
	STIR_SHAKEN_ERROR_X509_SET_SUBJECT_C,
	STIR_SHAKEN_ERROR_X509_SET_SUBJECT_CN,
	STIR_SHAKEN_ERROR_X509_SET_SUBJECT_NAME,
	STIR_SHAKEN_ERROR_X509_SUBJECT_C_CN,
	STIR_SHAKEN_ERROR_X509_ADD_SUBJECT_KEYID_EXT,
	STIR_SHAKEN_ERROR_X509_ADD_AUTHORITY_KEYID_EXT,
	STIR_SHAKEN_ERROR_X509_ADD_COMMENT_EXT,
	STIR_SHAKEN_ERROR_X509_ADD_CA_EXT,
	STIR_SHAKEN_ERROR_X509_ADD_CA_USAGE_EXT,
	STIR_SHAKEN_ERROR_X509_ADD_CERT_TYPE_EXT,
	STIR_SHAKEN_ERROR_X509_ADD_SIGNALWIRE_EXT,
	STIR_SHAKEN_ERROR_X509_ADD_STANDARD_EXT_1,
	STIR_SHAKEN_ERROR_X509_ADD_STANDARD_EXT_2,
	STIR_SHAKEN_ERROR_X509_ADD_STANDARD_EXT_3,
	STIR_SHAKEN_ERROR_X509_ADD_STANDARD_EXT_4,
	STIR_SHAKEN_ERROR_X509_ADD_CA_EXT_1,
	STIR_SHAKEN_ERROR_X509_ADD_CA_EXT_2,
	STIR_SHAKEN_ERROR_X509_EXT_NUMBER_RANGE,	
	STIR_SHAKEN_ERROR_X509_GET_SUBJECT_NAME,
	STIR_SHAKEN_ERROR_X509_GET_ISSUER_NAME,
	STIR_SHAKEN_ERROR_X509_GET_SERIAL,
	STIR_SHAKEN_ERROR_X509_CERT_MISSING_1,
	STIR_SHAKEN_ERROR_X509_CERT_MISSING_2,
	STIR_SHAKEN_ERROR_X509_CERT_MISSING_3,
	STIR_SHAKEN_ERROR_X509_CERT_MISSING_4,
	STIR_SHAKEN_ERROR_X509_CERT_MISSING_5,
	STIR_SHAKEN_ERROR_X509_CERT_NAME_MISSING_1,
	STIR_SHAKEN_ERROR_X509_CERT_NAME_MISSING_2,
	STIR_SHAKEN_ERROR_X509_CERT_NAME_MISSING_3,
	STIR_SHAKEN_ERROR_X509_SIGN_1,
	STIR_SHAKEN_ERROR_X509_SIGN_2,
	STIR_SHAKEN_ERROR_X509_SIGN_3,
	STIR_SHAKEN_ERROR_X509_SIGN_4,
	STIR_SHAKEN_ERROR_X509_SIGN_5,
	STIR_SHAKEN_ERROR_X509_ISSUER_SUBJECT_1,
	STIR_SHAKEN_ERROR_X509_ISSUER_SUBJECT_2,
	STIR_SHAKEN_ERROR_X509_GENERATE_CERT_1,
	STIR_SHAKEN_ERROR_X509_GENERATE_CERT_2,
	STIR_SHAKEN_ERROR_X509_GENERATE_CERT_3,
	STIR_SHAKEN_ERROR_X509_GENERATE_CERT_4,
	STIR_SHAKEN_ERROR_X509_GENERATE_CERT_FROM_CSR_1,
	STIR_SHAKEN_ERROR_X509_BIO_NEW_1,
	STIR_SHAKEN_ERROR_X509_READ_BIO,
	STIR_SHAKEN_ERROR_X509_READ_FROM_FILE,
	STIR_SHAKEN_ERROR_X509_STORE_MISSING_1,
	STIR_SHAKEN_ERROR_X509_STORE_MISSING_2,
	STIR_SHAKEN_ERROR_X509_STORE_MISSING_3,
	STIR_SHAKEN_ERROR_SSL_X509_PEM_WRITE_BIO_1,
	STIR_SHAKEN_ERROR_SSL_X509_PEM_WRITE_BIO_2,
	STIR_SHAKEN_ERROR_X509_STORE,
	STIR_SHAKEN_ERROR_X509_STORE_CTX_NEW,
	STIR_SHAKEN_ERROR_X509_CERT_STORE_CTX_INIT,
	STIR_SHAKEN_ERROR_X509_CERT_STORE_INIT,
	STIR_SHAKEN_ERROR_X509_REQ_NEW,
	STIR_SHAKEN_ERROR_X509_REQ_MISSING_1,
	STIR_SHAKEN_ERROR_X509_REQ_MISSING_2,
	STIR_SHAKEN_ERROR_X509_REQ_MISSING_3,
	STIR_SHAKEN_ERROR_X509_REQ_MISSING_4,
	STIR_SHAKEN_ERROR_X509_REQ_REQ_MISSING,
	STIR_SHAKEN_ERROR_X509_REQ_PRIVKEY_MISSING,
	STIR_SHAKEN_ERROR_X509_REQ_ISSUER_MISSING_1,
	STIR_SHAKEN_ERROR_X509_REQ_SUBJECT_C_MISSING,
	STIR_SHAKEN_ERROR_X509_REQ_SUBJECT_CN_MISSING,
	STIR_SHAKEN_ERROR_X509_REQ_SIGN_1,
	STIR_SHAKEN_ERROR_X509_REQ_SIGN_2,
	STIR_SHAKEN_ERROR_X509_REQ_GET_PUBKEY_1,
	STIR_SHAKEN_ERROR_X509_REQ_GET_DIGEST,
	STIR_SHAKEN_ERROR_X509_REQ_READ_FROM_FILE,
	STIR_SHAKEN_ERROR_X509_REQ_SET_VERSION,
	STIR_SHAKEN_ERROR_X509_REQ_GET_SUBJECT,
	STIR_SHAKEN_ERROR_X509_REQ_SET_SUBJECT_C,
	STIR_SHAKEN_ERROR_X509_REQ_SET_SUBJECT_CN,
	STIR_SHAKEN_ERROR_X509_REQ_SET_SUBJECT,
	STIR_SHAKEN_ERROR_X509_REQ_SET_PUBKEY,
	STIR_SHAKEN_ERROR_X509_REQ_ADD_TNAUTHLIST_SPC,
	STIR_SHAKEN_ERROR_X509_REQ_ADD_TNAUTHLIST_URI_1,
	STIR_SHAKEN_ERROR_X509_REQ_ADD_TNAUTHLIST_URI_2,
	STIR_SHAKEN_ERROR_X509_REQ_GENERATE,
	STIR_SHAKEN_ERROR_X509_REQ_PEM_WRITE,
	STIR_SHAKEN_ERROR_X509_LOAD_FROM_FILE_1,
	STIR_SHAKEN_ERROR_X509_GET_PUBKEY_1,
	STIR_SHAKEN_ERROR_LOAD_CA,
	STIR_SHAKEN_ERROR_LOAD_CRL,
	STIR_SHAKEN_ERROR_LOAD_X509,
	STIR_SHAKEN_ERROR_LOAD_EVP_PKEY,
	STIR_SHAKEN_ERROR_PA_NOT_TRUSTED,
	STIR_SHAKEN_ERROR_PA_ADD,
	STIR_SHAKEN_ERROR_SET_DEFAULT_PATHS,
	STIR_SHAKEN_ERROR_PASSPORT_INIT_1,
	STIR_SHAKEN_ERROR_PASSPORT_INIT_2,
	STIR_SHAKEN_ERROR_PASSPORT_HEADERS_INVALID,
	STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_ALG,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_PPT,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_TYP,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_X5U,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_ORIGID,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_ATTEST,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_ORIG,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST,
	STIR_SHAKEN_ERROR_PASSPORT_VALIDATE,
	STIR_SHAKEN_ERROR_PASSPORT_EXPIRED,
	STIR_SHAKEN_ERROR_PASSPORT_MISSING_1,
	STIR_SHAKEN_ERROR_PASSPORT_MISSING_2,
	STIR_SHAKEN_ERROR_PASSPORT_MISSING_3,
	STIR_SHAKEN_ERROR_PASSPORT_MALFORMED,
	STIR_SHAKEN_ERROR_PASSPORT_JWT_FROM_JSON,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_FORM,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_MISSING,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_PARSE,
	STIR_SHAKEN_ERROR_PASSPORT_ARRAY_ITEM,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_TN,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_URI,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_TYPE,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_TN_URI_TYPE,
	STIR_SHAKEN_ERROR_PASSPORT_ATTEST_MISSING,
	STIR_SHAKEN_ERROR_PASSPORT_ATTEST_VALUE,
	STIR_SHAKEN_ERROR_PASSPORT_ORIGID_MISSING,
	STIR_SHAKEN_ERROR_PASSPORT_ORIG_TN_MISSING,
	STIR_SHAKEN_ERROR_PASSPORT_DEST_TN_MISSING,
	STIR_SHAKEN_ERROR_PASSPORT_JWT_PRINT_JSON,
	STIR_SHAKEN_ERROR_PASSPORT_JWT_ADD_GRANTS_JSON,
	STIR_SHAKEN_ERROR_PASSPORT_JWT_CREATE_1,
	STIR_SHAKEN_ERROR_PASSPORT_JWT_CREATE_2,
	STIR_SHAKEN_ERROR_PASSPORT_JWT_INIT,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_FUTURE,
	STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT_VALUE_EXPIRED,
	STIR_SHAKEN_ERROR_PASSPORT_X5U,
	STIR_SHAKEN_ERROR_PASSPORT_ALG,
	STIR_SHAKEN_ERROR_PASSPORT_PPT,
	STIR_SHAKEN_ERROR_SIH_CREATE,
	STIR_SHAKEN_ERROR_BIND,
	STIR_SHAKEN_ERROR_FILE_OPEN,
	STIR_SHAKEN_ERROR_FILE_READ,
	STIR_SHAKEN_ERROR_FILE_WRITE_1,
	STIR_SHAKEN_ERROR_FILE_WRITE_2,
	STIR_SHAKEN_ERROR_FILE_WRITE_3,
	STIR_SHAKEN_ERROR_FILE_WRITE_4,
	STIR_SHAKEN_ERROR_FILE_NAME_MISSING_1,
	STIR_SHAKEN_ERROR_FILE_NAME_MISSING_2,
	STIR_SHAKEN_ERROR_FILE_NAME_MISSING_3,
	STIR_SHAKEN_ERROR_FILE_DSNT_EXIST_1,
	STIR_SHAKEN_ERROR_FILE_DSNT_EXIST_2,
	STIR_SHAKEN_ERROR_FILE_DSNT_EXIST_3,
	STIR_SHAKEN_ERROR_FOPEN_1,
	STIR_SHAKEN_ERROR_FOPEN_2,
	STIR_SHAKEN_ERROR_FOPEN_3,
	STIR_SHAKEN_ERROR_FOPEN_4,
	STIR_SHAKEN_ERROR_FOPEN_5,
	STIR_SHAKEN_ERROR_FREAD,
	STIR_SHAKEN_ERROR_BUFFER_1,
	STIR_SHAKEN_ERROR_BUFFER_2,
	STIR_SHAKEN_ERROR_BUFFER_3,
	STIR_SHAKEN_ERROR_BUFFER_4,
	STIR_SHAKEN_ERROR_EVP_PKEY_TO_RAW,
	STIR_SHAKEN_ERROR_CALLBACK_NOT_SET,
	STIR_SHAKEN_ERROR_CALLBACK_ACTION_CERT_FETCH_ENQUIRY,
	STIR_SHAKEN_ERROR_MEM_REALLOC,
	STIR_SHAKEN_ERROR_MEM_SIH,
	STIR_SHAKEN_ERROR_MEM_PASSPORT,
	STIR_SHAKEN_ERROR_MEM_ID,
	STIR_SHAKEN_ERROR_MEM_CURVES,
	STIR_SHAKEN_ERROR_NID,
	STIR_SHAKEN_ERROR_NID_ATTR,
	STIR_SHAKEN_ERROR_EXT_BY_NID,
	STIR_SHAKEN_ERROR_AS_MEM,
	STIR_SHAKEN_ERROR_AS_MISSING_1,
	STIR_SHAKEN_ERROR_AS_MISSING_2,
	STIR_SHAKEN_ERROR_AS_MISSING_3,
	STIR_SHAKEN_ERROR_AS_MISSING_4,
	STIR_SHAKEN_ERROR_AS_MISSING_5,
	STIR_SHAKEN_ERROR_AS_DIR_DOES_NOT_EXIST,
	STIR_SHAKEN_ERROR_AS_PRIVKEY_DOES_NOT_EXIST,
	STIR_SHAKEN_ERROR_AS_CERTIFICATE_DOES_NOT_EXIST,
	STIR_SHAKEN_ERROR_AS_CERTIFICATE_INSTALL_DIR_DOES_NOT_EXIST,
	STIR_SHAKEN_ERROR_AS_CERTIFICATE_PUBLIC_URL_EMPTY,
	STIR_SHAKEN_ERROR_AS_PRIVKEY_FULL_NAME,
	STIR_SHAKEN_ERROR_AS_CERT_FULL_NAME,
	STIR_SHAKEN_ERROR_AS_CERT_INSTALL_FULL_NAME,
	STIR_SHAKEN_ERROR_AS_LOAD_PRIVKEY,
	STIR_SHAKEN_ERROR_AS_LOAD_CERT,
	STIR_SHAKEN_ERROR_AS_CREATE_PASSPORT_1,
	STIR_SHAKEN_ERROR_AS_CREATE_PASSPORT_2,
	STIR_SHAKEN_ERROR_AS_CREATE_SIH,
	STIR_SHAKEN_ERROR_AS_SIGN_PASSPORT,
	STIR_SHAKEN_ERROR_VS_MISSING_1,
	STIR_SHAKEN_ERROR_VS_MISSING_2,
	STIR_SHAKEN_ERROR_VS_MISSING_3,
	STIR_SHAKEN_ERROR_VS_MISSING_4,
	STIR_SHAKEN_ERROR_VS_MEM,
	STIR_SHAKEN_ERROR_UNKNOWN_1,
	STIR_SHAKEN_ERROR_UNKNOWN_2,
} stir_shaken_error_t;

#define STIR_SHAKEN_HTTP_REQ_404_INVALID "404"
#define STIR_SHAKEN_HTTP_REQ_404_NOT_FOUND "404"

typedef enum stir_shaken_http_req_type {
	STIR_SHAKEN_HTTP_REQ_TYPE_GET,
	STIR_SHAKEN_HTTP_REQ_TYPE_POST,
	STIR_SHAKEN_HTTP_REQ_TYPE_PUT,
	STIR_SHAKEN_HTTP_REQ_TYPE_HEAD
} stir_shaken_http_req_type_t;

typedef enum stir_shaken_callback_action {
	STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY,
} stir_shaken_callback_action_t;

typedef struct stir_shaken_callback_arg_s {
	stir_shaken_callback_action_t	action;
	stir_shaken_cert_t				cert;
} stir_shaken_callback_arg_t;

void stir_shaken_destroy_callback_arg(stir_shaken_callback_arg_t *callback_arg);

typedef stir_shaken_status_t (*stir_shaken_callback_t)(stir_shaken_callback_arg_t *);
stir_shaken_status_t stir_shaken_default_callback(stir_shaken_callback_arg_t *arg);

typedef struct stir_shaken_context_error_s {
	char err_buf0[STIR_SHAKEN_ERROR_BUF_LEN];
	char err_buf1[STIR_SHAKEN_ERROR_BUF_LEN];
	char err_buf2[STIR_SHAKEN_ERROR_BUF_LEN];
	char err_buf3[STIR_SHAKEN_ERROR_BUF_LEN];
	char err_buf4[STIR_SHAKEN_ERROR_BUF_LEN];
	char err_buf5[STIR_SHAKEN_ERROR_BUF_LEN];
	char err[6*STIR_SHAKEN_ERROR_BUF_LEN];
	stir_shaken_error_t error;
	uint8_t got_error;
} stir_shaken_context_error_t;

typedef struct stir_shaken_context_s {
	stir_shaken_context_error_t	e;
	stir_shaken_callback_t		callback;
	stir_shaken_callback_arg_t	callback_arg;
} stir_shaken_context_t;

void stir_shaken_destroy_context(stir_shaken_context_t *ss);

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
	char			error[STIR_SHAKEN_BUFLEN];
	mem_chunk_t		mem;
	curl_slist_t	*headers;
} stir_shaken_http_response_t;

#define STIR_SHAKEN_HTTP_DEFAULT_REMOTE_PORT 80u
#define STIR_SHAKEN_HTTP_DEFAULT_REMOTE_PORT_HTTPS 443u

typedef enum stir_shaken_action_type {
	STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_INIT,
	STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_CA_REPLY_CHALLENGE,
	STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ_DETAILS,
	STIR_SHAKEN_ACTION_TYPE_SP_CERT_REQ_SP_REQ_AUTHZ,
	STIR_SHAKEN_ACTION_TYPE_SP_CERT_DOWNLOAD
		// etc.
} stir_shaken_action_type_t;

typedef struct stir_shaken_http_req_s {
	const char					*url;
	uint16_t                    remote_port;
	stir_shaken_http_req_type_t	type;
	const char					*data;
	curl_slist_t				*tx_headers;
	stir_shaken_http_req_content_type_t content_type;
	stir_shaken_http_response_t	response;
	stir_shaken_action_type_t   action;
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

void stir_shaken_passport_params_destroy(stir_shaken_passport_params_t *params);

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
stir_shaken_passport_t*	stir_shaken_passport_create(stir_shaken_context_t *ss, stir_shaken_passport_params_t *params, unsigned char *key, uint32_t keylen);
void						stir_shaken_passport_destroy(stir_shaken_passport_t *passport);
stir_shaken_status_t		stir_shaken_passport_sign(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, unsigned char *key, uint32_t keylen, char **out);
const char*					stir_shaken_passport_get_header(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key);

// Returns headers in JSON. Must be freed by caller.
char*						stir_shaken_passport_get_headers_json(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key);

const char*					stir_shaken_passport_get_grant(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key);
long int					stir_shaken_passport_get_grant_int(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key);

// Returns grants in JSON. Must be freed by caller.
char*						stir_shaken_passport_get_grants_json(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char* key);

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
stir_shaken_status_t stir_shaken_passport_validate_headers_and_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport);

/**
 * Validate that the PASSporT is fresh (has not expired yet, according to it's value of @iat and local policy for @iat_freshenss).
 */
stir_shaken_status_t stir_shaken_passport_validate_iat_against_freshness(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, time_t iat_freshness);

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
 * Authenticate the call, and return used/created PASSporT.
 * Autenticate (assert/sign) call identity with cert of Service Provider.
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
 * Authenticate the call, forget PASSporT (local PASSporT used and destroyed).
 * Authenticate (assert/sign) call identity with cert of Service Provider.
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

char* stir_shaken_passport_dump_str(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, uint8_t pretty);
void stir_shaken_free_jwt_str(char *s);
jwt_t* stir_shaken_jwt_move_to_passport(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_passport_t *passport);

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
	//ASN1_OBJECT				*tn_authlist_obj;

// DEPRECATED
	X509_STORE			*store;						// Container for CA list (list of approved CAs from STI-PA) and CRL (revocation list)

	int					loglevel;
} stir_shaken_globals_t;

extern stir_shaken_globals_t stir_shaken_globals;

stir_shaken_status_t stir_shaken_init(stir_shaken_context_t *ss, int loglevel);

stir_shaken_status_t stir_shaken_init_basic_and_ssl(stir_shaken_context_t *ss, int loglevel);

// DEPRECATED
// Only for backward compatibility
stir_shaken_status_t stir_shaken_do_init(stir_shaken_context_t *ss, const char *ca_dir, const char *crl_dir, int loglevel);

void stir_shaken_deinit(void);
void stir_shaken_do_deinit(void);


// SSL

// Using @digest_name and @pkey create a signature for @data and save it in @out.
// Return @out and length of it in @outlen. 
stir_shaken_status_t stir_shaken_do_sign_data_with_digest(stir_shaken_context_t *ss, const char *digest_name, EVP_PKEY *pkey, const char *data, size_t datalen, unsigned char *out, size_t *outlen);

// Generate new keys. Always removes old files.
stir_shaken_status_t stir_shaken_generate_keys(stir_shaken_context_t *ss, EC_KEY **eck, EVP_PKEY **priv, EVP_PKEY **pub, const char *private_key_full_name, const char *public_key_full_name, unsigned char *priv_raw, uint32_t *priv_raw_len);

// Call SSL destructors and release memory used for SSL keys.
void stir_shaken_destroy_keys_ex(EC_KEY **eck, EVP_PKEY **priv, EVP_PKEY **pub);
void stir_shaken_destroy_keys(stir_shaken_ssl_keys_t *keys);

X509_REQ* stir_shaken_load_x509_req_from_file(stir_shaken_context_t *ss, const char *name);
X509_REQ* stir_shaken_generate_x509_req(stir_shaken_context_t *ss, const char *subject_c, const char *subject_cn);
X509_REQ* stir_shaken_load_x509_req_from_pem(stir_shaken_context_t *ss, char *pem);
stir_shaken_status_t stir_shaken_sign_x509_req(stir_shaken_context_t *ss, X509_REQ *req, EVP_PKEY *private_key);
stir_shaken_status_t stir_shaken_generate_csr(stir_shaken_context_t *ss, uint32_t sp_code, X509_REQ **csr_req, EVP_PKEY *private_key, EVP_PKEY *public_key, const char *subject_c, const char *subject_cn);
stir_shaken_status_t stir_shaken_csr_to_disk(stir_shaken_context_t *ss, X509_REQ *csr_req, const char *csr_full_name);
void stir_shaken_destroy_csr_req(X509_REQ **csr_req);
void stir_shaken_destroy_csr(stir_shaken_csr_t *csr);
void*					stir_shaken_x509_req_get_tn_authlist_extension(stir_shaken_context_t *ss, X509_REQ *req);
const unsigned char*	stir_shaken_x509_req_get_tn_authlist_extension_value(stir_shaken_context_t *ss, X509_REQ *req);

// Functions used for cert construction
X509* stir_shaken_generate_x509_cert(stir_shaken_context_t *ss, EVP_PKEY *public_key, const char* issuer_c, const char *issuer_cn, const char *subject_c, const char *subject_cn, int64_t serial, long expiry_days);
stir_shaken_status_t stir_shaken_sign_x509_cert(stir_shaken_context_t *ss, X509 *x, EVP_PKEY *private_key);
stir_shaken_status_t stir_shaken_x509_add_standard_extensions(stir_shaken_context_t *ss, X509 *ca_x, X509 *x);
stir_shaken_status_t stir_shaken_x509_add_ca_extensions(stir_shaken_context_t *ss, X509 *ca_x, X509 *x);
stir_shaken_status_t stir_shaken_x509_add_signalwire_extensions(stir_shaken_context_t *ss, X509 *ca_x, X509 *x, const char *number_start, const char *number_end);
stir_shaken_status_t stir_shaken_x509_req_add_tnauthlist_extension_spc(stir_shaken_context_t *ss, X509_REQ *req, unsigned long long int spc);
stir_shaken_status_t stir_shaken_x509_add_tnauthlist_extension_uri(stir_shaken_context_t *ss, X509 *ca_x, X509 *x, char *uri);

// Create CA cross-certificate, where issuer and subject are different entities. Cross certificates describe a trust relationship between CAs.
X509* stir_shaken_generate_x509_cross_ca_cert(stir_shaken_context_t *ss, X509 *ca_x, EVP_PKEY *private_key, EVP_PKEY *public_key, const char* issuer_c, const char *issuer_cn, const char *subject_c, const char *subject_cn, int64_t serial, long expiry_days);

// Create CA self-issued certificate, where issuer and the subject are same entity. Self-issued certs describe a change in policy or operation.
X509* stir_shaken_generate_x509_self_issued_ca_cert(stir_shaken_context_t *ss, EVP_PKEY *private_key, EVP_PKEY *public_key, const char* issuer_c, const char *issuer_cn, int64_t serial, long expiry_days);

// Create CA self-signed certificate, which is self-issued certificate where the digital signature may be verified by the public key bound into the certificate.
X509* stir_shaken_generate_x509_self_signed_ca_cert(stir_shaken_context_t *ss, EVP_PKEY *private_key, EVP_PKEY *public_key, const char* issuer_c, const char *issuer_cn, int64_t serial, long expiry_days);

// Create SP certificate.
X509* stir_shaken_generate_x509_end_entity_cert(stir_shaken_context_t *ss, X509 *ca_x, EVP_PKEY *private_key, EVP_PKEY *public_key, const char* issuer_c, const char *issuer_cn, const char *subject_c, const char *subject_cn, int64_t serial, long expiry_days, char *tn_auth_list_uri);
X509* stir_shaken_generate_x509_end_entity_cert_from_csr(stir_shaken_context_t *ss, X509 *ca_x, EVP_PKEY *private_key, const char* issuer_c, const char *issuer_cn, X509_REQ *req, int64_t serial, long expiry_days, char *tn_auth_list_uri);

/**
 * @buf - (out) will contain fingerprint, must be of size at least 3*EVP_MAX_MD_SIZE bytes
 * @buflen - (out) will contain string len including '\0'
 */
stir_shaken_status_t stir_shaken_extract_fingerprint(stir_shaken_context_t *ss, X509* x509, const char *digest_name, char *buf, unsigned int *buflen);

X509* stir_shaken_make_cert_from_public_key(stir_shaken_context_t *ss, EVP_PKEY *pkey);

stir_shaken_status_t stir_shaken_x509_to_disk(stir_shaken_context_t *ss, X509 *x, const char *cert_full_name);
X509* stir_shaken_generate_x509_cert_from_csr(stir_shaken_context_t *ss, const char* issuer_c, const char *issuer_cn, X509_REQ *req, int64_t serial, long expiry_days, char *tn_auth_list_uri);
void stir_shaken_destroy_cert_fields(stir_shaken_cert_t *cert);
void stir_shaken_destroy_cert(stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_read_cert_fields(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_cert_init_validation(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, char *ca_list, char *ca_dir, char *crl_list, char *crl_dir);
unsigned long stir_shaken_get_cert_name_hashed(stir_shaken_context_t *ss, X509 *x);
void stir_shaken_cert_name_hashed_2_string(unsigned long hash, char *buf, int buflen);
void stir_shaken_hash_cert_name(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
// DEPRECATED
stir_shaken_status_t stir_shaken_init_cert_store(stir_shaken_context_t *ss, const char *ca_list, const char *ca_dir, const char *crl_list, const char *crl_dir);
// DEPRECATED
void stir_shaken_cert_store_cleanup(void);
stir_shaken_status_t stir_shaken_register_tnauthlist_extension(stir_shaken_context_t *ss, int *nidp);
stir_shaken_status_t stir_shaken_verify_cert_tn_authlist_extension(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
// DEPRECATED
stir_shaken_status_t stir_shaken_verify_cert_path(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_verify_cert(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);

stir_shaken_status_t stir_shaken_x509_init_cert_store(stir_shaken_context_t *ss, X509_STORE **store);
stir_shaken_status_t stir_shaken_x509_load_ca(stir_shaken_context_t *ss, X509_STORE *store, const char *ca_list, const char *ca_dir);
stir_shaken_status_t stir_shaken_x509_load_crl(stir_shaken_context_t *ss, X509_STORE *store, const char *crl_list, const char *crl_dir);
void stir_shaken_x509_cert_store_cleanup(X509_STORE **store);
stir_shaken_status_t stir_shaken_x509_verify_cert_path(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, X509_STORE *store);

char* stir_shaken_cert_get_serialHex(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_serialDec(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_notBefore(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_notAfter(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_issuer(stir_shaken_cert_t *cert);
char* stir_shaken_cert_get_subject(stir_shaken_cert_t *cert);
int stir_shaken_cert_get_version(stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_cert_copy(stir_shaken_context_t *ss, stir_shaken_cert_t *dst, stir_shaken_cert_t *src);

EVP_PKEY* stir_shaken_load_pubkey_from_file(stir_shaken_context_t *ss, const char *file);
EVP_PKEY* stir_shaken_load_privkey_from_file(stir_shaken_context_t *ss, const char *file);
stir_shaken_status_t stir_shaken_load_x509_from_mem(stir_shaken_context_t *ss, X509 **x, STACK_OF(X509) **xchain, void *mem);
X509* stir_shaken_load_x509_from_file(stir_shaken_context_t *ss, const char *name);
stir_shaken_status_t stir_shaken_load_x509_req_from_mem(stir_shaken_context_t *ss, X509_REQ **req, void *mem);
EVP_PKEY* stir_shaken_load_pubkey_from_file(stir_shaken_context_t *ss, const char *file);
EVP_PKEY* stir_shaken_load_privkey_from_file(stir_shaken_context_t *ss, const char *file);
stir_shaken_status_t stir_shaken_load_key_raw(stir_shaken_context_t *ss, const char *file, unsigned char *key_raw, uint32_t *key_raw_len);
stir_shaken_status_t stir_shaken_load_x509_and_privkey(stir_shaken_context_t *ss, const char *cert_name, stir_shaken_cert_t *cert, const char *private_key_name, EVP_PKEY **pkey, unsigned char *priv_raw, uint32_t *priv_raw_len);
stir_shaken_status_t stir_shaken_load_keys(stir_shaken_context_t *ss, EVP_PKEY **priv, EVP_PKEY **pub, const char *private_key_full_name, const char *public_key_full_name, unsigned char *priv_raw, uint32_t *priv_raw_len);
stir_shaken_status_t stir_shaken_get_csr_raw(stir_shaken_context_t *ss, X509_REQ *req, unsigned char *body, int *body_len);
stir_shaken_status_t stir_shaken_get_x509_raw(stir_shaken_context_t *ss, X509 *x, unsigned char *raw, int *raw_len);
stir_shaken_status_t stir_shaken_pubkey_to_raw(stir_shaken_context_t *ss, EVP_PKEY *evp_key, unsigned char *key, int *key_len);
stir_shaken_status_t stir_shaken_privkey_to_raw(stir_shaken_context_t *ss, EVP_PKEY *evp_key, unsigned char *key, int *key_len);
stir_shaken_status_t stir_shaken_get_pubkey_raw_from_cert(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, unsigned char *key, int *key_len);
stir_shaken_status_t stir_shaken_create_jwk(stir_shaken_context_t *ss, EC_KEY *ec_key, const char *kid, ks_json_t **jwk);
void stir_shaken_print_cert_fields(FILE *file, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_init_ssl(stir_shaken_context_t *ss);
void stir_shaken_deinit_ssl(void);
stir_shaken_status_t stir_shaken_cert_to_authority_check_url(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, char *authority_check_url, int buflen);

// Verification service

stir_shaken_status_t stir_shaken_basic_cert_check(stir_shaken_context_t *ss, stir_shaken_cert_t *cert);
stir_shaken_status_t stir_shaken_vs_verify_stica(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, ks_json_t *array);
stir_shaken_status_t stir_shaken_make_authority_over_number_check_req(stir_shaken_context_t *ss, const char *url, const char *origin_identity);
int stir_shaken_verify_data(stir_shaken_context_t *ss, const char *data, const char *signature, size_t siglen, EVP_PKEY *pkey);
int stir_shaken_do_verify_data_file(stir_shaken_context_t *ss, const char *data_filename, const char *signature_filename, EVP_PKEY *public_key);
int stir_shaken_do_verify_data(stir_shaken_context_t *ss, const void *data, size_t datalen, const unsigned char *sig, size_t siglen, EVP_PKEY *public_key);

stir_shaken_status_t stir_shaken_download_cert(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
stir_shaken_status_t stir_shaken_jwt_fetch_or_download_cert(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out);

stir_shaken_status_t stir_shaken_check_authority_over_number(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, stir_shaken_passport_t *passport);
stir_shaken_status_t stir_shaken_sih_verify_with_cert(stir_shaken_context_t *ss, const char *identity_header, stir_shaken_cert_t *cert, stir_shaken_passport_t *passport);

/**
 * Verify JWT token by a public key from certificate referenced in x5u header of this JWT. Involves HTTP GET call for a certificate.
 * This will then attempt to obtain certificate referenced by x5u header, and if successful then will verify JWT's signature against public key from cert.
 * Optionally get cert and/or JWT out of the method.
 */
stir_shaken_status_t stir_shaken_jwt_verify(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out);

/**
 * This will call stir_shaken_jwt_verify and will also perform X509 cert path verification on the cert.
 * Optionally get cert and/or JWT out of the method.
 */
stir_shaken_status_t stir_shaken_jwt_verify_and_check_x509_cert_path(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out);
stir_shaken_status_t stir_shaken_x509_verify_jwt_and_check_x509_cert_path(stir_shaken_context_t *ss, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out, X509_STORE *store);

/**
 * Perform STIR-Shaken verification of the SIP @identity_header.
 *
 * This will first process @identity_header into JWT token and parameters including cert URL.
 * This will then call stir_shaken_jwt_verify_and_check_x509_cert_path().
 * If successful retrieved PASSporT is returned via @passport and (optionally) STI cert via *@cert_out (if @cert_out is not NULL).
 *
 * NOTE: @passport should point to allocated memory big enough to create PASSporT, *@cert_out may be NULL (will be malloced then and it is caller's responsibility to free it).
 */
stir_shaken_status_t stir_shaken_sih_verify(stir_shaken_context_t *ss, const char *sih, stir_shaken_passport_t *passport, stir_shaken_cert_t **cert_out, time_t iat_freshness);
stir_shaken_status_t stir_shaken_x509_sih_verify(stir_shaken_context_t *ss, const char *sih, stir_shaken_passport_t *passport, stir_shaken_cert_t **cert_out, time_t iat_freshness, X509_STORE *store);

/**
 * Check PASSporT is technically correct and validate it's expiry.
 */
stir_shaken_status_t stir_shaken_passport_validate(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, time_t iat_freshness);


// Authentication service

/**
 * Create JSON token from call @pparams.
 */
ks_json_t* stir_shaken_passport_create_json(stir_shaken_context_t *ss, stir_shaken_passport_params_t *pparams);
void stir_shaken_passport_destroy(stir_shaken_passport_t *passport);

/**
 * Create signatures in @jwt and save intermediate results in @info.
 */
stir_shaken_status_t stir_shaken_passport_finalise_json(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, EVP_PKEY *pkey);

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
stir_shaken_status_t stir_shaken_as_perform_authorization(EVP_PKEY *pkey, stir_shaken_cert_t *cert);

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
 * (==x5u)	//Info	(X [needed], but implicitly copied from @x5u)
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

char*					stir_shaken_acme_generate_cert_req_payload(stir_shaken_context_t *ss, const char *kid, const char *nonce, const char *url, X509_REQ *req, const char *nb, const char *na, const char *spc, unsigned char *key, uint32_t keylen, char **json);
char*					stir_shaken_acme_generate_auth_challenge(stir_shaken_context_t *ss, char *status, char *expires, char *csr, char *nb, char *na, char *authz_url);
char*					stir_shaken_acme_generate_auth_challenge_response(stir_shaken_context_t *ss, char *kid, char *nonce, char *url, char *spc_token, unsigned char *key, uint32_t keylen, char **json);
char*					stir_shaken_acme_generate_auth_challenge_details(stir_shaken_context_t *ss, char *status, const char *spc, const char *token, const char *authz_url);
char*					stir_shaken_acme_generate_auth_polling_status(stir_shaken_context_t *ss, char *status, char *expires, char *validated, const char *spc, const char *token, const char *authz_url);
char*					stir_shaken_acme_generate_new_account_req_payload(stir_shaken_context_t *ss, char *jwk, char *nonce, char *url, char *contact_mail, char *contact_tel, unsigned char *key, uint32_t keylen, char **json);
stir_shaken_status_t stir_shaken_acme_api_uri_to_spc(stir_shaken_context_t *ss, const char *uri_request, const char *api_url, char *buf, int buflen, unsigned long long int *sp_code, int *uri_has_secret, unsigned long long *secret);
stir_shaken_status_t	stir_shaken_acme_api_uri_parse(stir_shaken_context_t *ss, const char *uri_request, const char *api_url, char *arg1, int arg1_len, char *arg2, int arg2_len, int *args_n);
char*					stir_shaken_acme_generate_spc_token(stir_shaken_context_t *ss, char *issuer, char *url, char *nb, char *na, char *spc, unsigned char *key, uint32_t keylen, char **json);

stir_shaken_status_t	stir_shaken_acme_nonce_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
stir_shaken_status_t	stir_shaken_acme_retrieve_auth_challenge_details(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
stir_shaken_status_t	stir_shaken_acme_respond_to_challenge(stir_shaken_context_t *ss, void *data, char *spc_token, unsigned char *key, uint32_t keylen, char **polling_url, uint16_t remote_port);
stir_shaken_status_t	stir_shaken_acme_poll(stir_shaken_context_t *ss, void *data, const char *url, uint16_t remote_port);
stir_shaken_status_t	stir_shaken_acme_perform_authorization(stir_shaken_context_t *ss, void *data, char *spc_token, unsigned char *key, uint32_t keylen, uint16_t remote_port);

const char* stir_shaken_http_req_type_2_str(stir_shaken_http_req_type_t type);
extern stir_shaken_status_t	(*stir_shaken_make_http_req)(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
stir_shaken_status_t    stir_shaken_make_http_req_real(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
extern stir_shaken_status_t    stir_shaken_make_http_req_mock(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
void					stir_shaken_destroy_http_request(stir_shaken_http_req_t *http_req);

/**
 * @http_req - (out) will contain HTTP response
 */
stir_shaken_status_t stir_shaken_as_make_code_token_request(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url, const char *fingerprint);

/**
 * The STI-PA manages an active, secure list of approved STI-CAs in the form of their public key certificates.
 * The STI-PA provides this list of approved STI-CAs to the service providers via a Hypertext Transfer Protocol
 * Secure (HTTPS) interface. The SHAKEN-defined Secure Telephone Identity Verification Service (STI-VS) can then use
 * a public key certificate to validate the root of the digital signature in the STI certificate by determining
 * whether the STI-CA that issued the STI certificate is in the list of approved STI-CAs. Note that the details
 * associated with the structure and management of this list require further specification.
 */
stir_shaken_status_t stir_shaken_as_make_stica_list_request(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *url);

stir_shaken_status_t	stir_shaken_make_http_get_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req);
stir_shaken_status_t	stir_shaken_make_http_post_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, char *data, uint8_t json);
stir_shaken_status_t	stir_shaken_make_http_head_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, char *data, uint8_t is_json);
char*					stir_shaken_get_http_header(stir_shaken_http_req_t *http_req, char *name);
void					stir_shaken_error_desc_to_http_error_phrase(const char *error_desc, char *error_phrase, int buflen);

stir_shaken_status_t stir_shaken_sp_cert_req(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, char *jwt, unsigned char *key, uint32_t keylen, const char *spc, char *spc_token);
stir_shaken_status_t stir_shaken_sp_cert_req_ex(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req, const char *kid, const char *nonce, X509_REQ *req, const char *nb, const char *na, const char *spc, unsigned char *key, uint32_t keylen, char **json, char *spc_token);

// Services

// Authentication service

typedef struct stir_shaken_as_settings_s {
	// from user
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char cert_name[STIR_SHAKEN_BUFLEN];
} stir_shaken_as_settings_t;

typedef struct stir_shaken_as_s {
	stir_shaken_ssl_keys_t			keys;
	stir_shaken_cert_t				cert;
	stir_shaken_as_settings_t		settings;
} stir_shaken_as_t;

stir_shaken_as_t* stir_shaken_as_create(struct stir_shaken_context_s *ss);
void stir_shaken_as_destroy(stir_shaken_as_t *as);
stir_shaken_status_t stir_shaken_as_load_private_key(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, const char *private_key_name);
stir_shaken_status_t stir_shaken_as_load_cert(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, const char *cert_name);
char* stir_shaken_authenticate_to_passport_with_key(struct stir_shaken_context_s *ss, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport_out, unsigned char *key, uint32_t keylen);
char* stir_shaken_as_authenticate_to_passport(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport_out);
char* stir_shaken_authenticate_to_sih_with_key(struct stir_shaken_context_s *ss, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport_out, unsigned char *key, uint32_t keylen);
char* stir_shaken_as_authenticate_to_sih(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, stir_shaken_passport_params_t *params, stir_shaken_passport_t **passport_out);
stir_shaken_status_t stir_shaken_as_install_cert(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, const char *where);

// Verification service

typedef struct stir_shaken_vs_settings_s {
	char ca_dir[STIR_SHAKEN_BUFLEN];
	char crl_dir[STIR_SHAKEN_BUFLEN];

	// SIP section
	time_t		sip_date_header_freshness_seconds;
	uint8_t		sip_date_header_mandatory;

	// PASSporT checks
	time_t		iat_freshness_seconds;
	uint8_t 	identity_check;
} stir_shaken_vs_settings_t;

typedef struct stir_shaken_vs_s {
	X509_STORE						*store;						// Container for CA list (list of approved CAs from STI-PA) and CRL (revocation list)
	stir_shaken_vs_settings_t		settings;
} stir_shaken_vs_t;

stir_shaken_vs_t* stir_shaken_vs_create(struct stir_shaken_context_s *ss);
void stir_shaken_vs_destroy(stir_shaken_vs_t *vs);
stir_shaken_status_t stir_shaken_vs_load_ca_dir(struct stir_shaken_context_s *ss, stir_shaken_vs_t *vs, const char *ca_dir);
stir_shaken_status_t stir_shaken_vs_load_crl_dir(struct stir_shaken_context_s *ss, stir_shaken_vs_t *vs, const char *crl_dir);
stir_shaken_status_t stir_shaken_vs_jwt_verify_and_check_x509_cert_path(stir_shaken_context_t *ss, stir_shaken_vs_t *vs, const char *token, stir_shaken_cert_t **cert_out, jwt_t **jwt_out);
stir_shaken_status_t stir_shaken_vs_sih_verify(stir_shaken_context_t *ss, stir_shaken_vs_t *vs, const char *sih, stir_shaken_passport_t *passport, stir_shaken_cert_t **cert_out, time_t iat_freshness);

// @arg - PASSporT params
stir_shaken_status_t stir_shaken_as_authenticate(struct stir_shaken_context_s *ss, stir_shaken_as_t *as, stir_shaken_passport_params_t *params);

// Verify SIP Identity Header
stir_shaken_status_t stir_shaken_vs_verify_sih(struct stir_shaken_context_s *ss, stir_shaken_vs_t *vs, const char *sih);

// Verify PASSporT
stir_shaken_status_t stir_shaken_vs_verify_passport(struct stir_shaken_context_s *ss, stir_shaken_vs_t *vs, const char *passport);

// Utility

stir_shaken_status_t stir_shaken_dir_exists(const char *path);
stir_shaken_status_t stir_shaken_dir_create(const char *path);
stir_shaken_status_t stir_shaken_dir_create_recursive(const char *path);
stir_shaken_status_t stir_shaken_file_exists(const char *path);
stir_shaken_status_t stir_shaken_file_remove(const char *path);
stir_shaken_status_t stir_shaken_save_to_file(stir_shaken_context_t *ss, const char *data, const char *name);
stir_shaken_status_t stir_shaken_append_to_file(stir_shaken_context_t *ss, const char *data, const char *name);
stir_shaken_status_t stir_shaken_b64_encode(unsigned char *in, size_t ilen, unsigned char *out, size_t olen);
size_t stir_shaken_b64_decode(const char *in, char *out, size_t olen);
char* stir_shaken_remove_multiple_adjacent(char *in, char what);
char* stir_shaken_get_dir_path(const char *path);
char* stir_shaken_make_complete_path(char *buf, int buflen, const char *dir, const char *file, const char *path_separator);
const char* stir_shaken_path_to_base_file_name(const char *path);
int stir_shaken_zstr(const char *str);

stir_shaken_error_t stir_shaken_get_error_code(stir_shaken_context_t *ss) __attribute__((nonnull(1)));
void stir_shaken_do_set_error(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line);
void stir_shaken_do_set_error_if_clear(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line);
void stir_shaken_clear_error(stir_shaken_context_t *ss);
uint8_t stir_shaken_is_error_set(stir_shaken_context_t *ss);
const char* stir_shaken_get_error(stir_shaken_context_t *ss, stir_shaken_error_t *error);

#define stir_shaken_set_error(ss, description, error) stir_shaken_do_set_error(ss, description, error, __FILE__, __LINE__)
#define stir_shaken_set_error_if_clear(ss, description, error) stir_shaken_do_set_error_if_clear(ss, description, error, __FILE__, __LINE__)

#define fprintif(level, fmt, ...)		\
	if (stir_shaken_globals.loglevel >= level) {							\
		fprintf(stderr, (fmt), ##__VA_ARGS__);	\
	}

#define STIR_SHAKEN_HASH_TYPE_SHALLOW			0
#define STIR_SHAKEN_HASH_TYPE_DEEP				1
#define STIR_SHAKEN_HASH_TYPE_SHALLOW_AUTOFREE	2

typedef void (*stir_shaken_hash_entry_destructor)(void*);

typedef struct stir_shaken_hash_entry_s {
	size_t key;
	void *data;
	stir_shaken_hash_entry_destructor dctor;
	struct stir_shaken_hash_entry_s *next;
} stir_shaken_hash_entry_t;

size_t stir_shaken_hash_hash(size_t hashsize, size_t key);
stir_shaken_hash_entry_t* stir_shaken_hash_entry_find(stir_shaken_hash_entry_t **hash, size_t hashsize, size_t key);
stir_shaken_hash_entry_t* stir_shaken_hash_entry_create(size_t key, void *data, int datalen, void *dctor, int hash_copy_type);
void stir_shaken_hash_entry_destroy(stir_shaken_hash_entry_t *e, int hash_copy_type);
stir_shaken_hash_entry_t* stir_shaken_hash_entry_add(stir_shaken_hash_entry_t **hash, size_t hashsize, size_t key, void *data, int datalen, stir_shaken_hash_entry_destructor dctor, int hash_copy_type);
stir_shaken_status_t stir_shaken_hash_entry_remove(stir_shaken_hash_entry_t **hash, size_t hashsize, size_t key, int hash_copy_type);
void stir_shaken_hash_destroy_branch(stir_shaken_hash_entry_t *entry, int hash_copy_type);
void stir_shaken_hash_destroy(stir_shaken_hash_entry_t **hash, size_t hashsize, int hash_copy_type);

#define STI_CA_SESSION_EXPIRY_SECONDS 30

time_t stir_shaken_time_elapsed_s(time_t ts, time_t now);

#define STI_CA_SESSIONS_MAX 1000
#define STI_CA_TRUSTED_PA_KEYS_MAX 100

#define STI_CA_SESSION_STATE_INIT				0
#define STI_CA_SESSION_STATE_AUTHZ_SENT			1
#define STI_CA_SESSION_STATE_AUTHZ_DETAILS_SENT	2
#define STI_CA_SESSION_STATE_POLLING			3
#define STI_CA_SESSION_STATE_DONE				4

#define STI_CA_HTTP_GET		0
#define STI_CA_HTTP_POST	1

typedef struct stir_shaken_sp_s {
	char subject_c[STIR_SHAKEN_BUFLEN];
	char subject_cn[STIR_SHAKEN_BUFLEN];
	uint32_t code;
	char *kid;
	char *nonce;
	stir_shaken_csr_t csr;
	stir_shaken_cert_t cert;
	char *nb;
	char *na;
	stir_shaken_ssl_keys_t keys;
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char public_key_name[STIR_SHAKEN_BUFLEN];
	char csr_name[STIR_SHAKEN_BUFLEN];
	char cert_name[STIR_SHAKEN_BUFLEN];
	char spc_token[STIR_SHAKEN_BUFLEN];
	uint16_t port;
	stir_shaken_passport_params_t passport_params;
} stir_shaken_sp_t;

typedef struct stir_shaken_ca_session_s {
	int state;
	unsigned long long int spc;
	unsigned long long authz_secret;
	char *nonce;
	char *authz_url;
	char *authz_token;
	char *authz_challenge;
	char *authz_challenge_details;
	char *authz_polling_status;
	int	authorized;
	stir_shaken_sp_t sp;
	size_t ts;
	uint8_t use_ssl;
} stir_shaken_ca_session_t;

typedef struct stir_shaken_ca_s {
	stir_shaken_context_t ss;
	stir_shaken_ssl_keys_t keys;
	stir_shaken_cert_t cert;
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char public_key_name[STIR_SHAKEN_BUFLEN];
	char cert_name[STIR_SHAKEN_BUFLEN];
	char cert_name_hashed[STIR_SHAKEN_BUFLEN];
	char tn_auth_list_uri[STIR_SHAKEN_BUFLEN];
	char issuer_c[STIR_SHAKEN_BUFLEN];
	char issuer_cn[STIR_SHAKEN_BUFLEN];
	char subject_c[STIR_SHAKEN_BUFLEN];
	char subject_cn[STIR_SHAKEN_BUFLEN];
	int64_t serial;
	long expiry_days;
	uint16_t port;
	stir_shaken_hash_entry_t* sessions[STI_CA_SESSIONS_MAX];
	uint8_t use_ssl;
	char ssl_cert_name[STIR_SHAKEN_BUFLEN];
	char ssl_key_name[STIR_SHAKEN_BUFLEN];
	char trusted_pa_cert_name[STIR_SHAKEN_BUFLEN];
	stir_shaken_hash_entry_t* trusted_pa_keys[STI_CA_TRUSTED_PA_KEYS_MAX];
	uint8_t use_trusted_pa_hash;
	char pa_dir_name[STIR_SHAKEN_BUFLEN];
	uint8_t use_pa_dir;
} stir_shaken_ca_t;

typedef struct stir_shaken_pa_s {
	stir_shaken_ssl_keys_t keys;
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char public_key_name[STIR_SHAKEN_BUFLEN];
	uint16_t port;
} stir_shaken_pa_t;

stir_shaken_status_t stir_shaken_is_key_trusted(stir_shaken_context_t *ss, EVP_PKEY *pkey, stir_shaken_hash_entry_t **trusted_pa_keys, size_t hashsize);
stir_shaken_status_t stir_shaken_is_cert_trusted(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, stir_shaken_hash_entry_t **trusted_pa_keys, size_t hashsize);
void stir_shaken_evp_pkey_hash_entry_dctor(void *o);
stir_shaken_status_t stir_shaken_add_cert_trusted(stir_shaken_context_t *ss, X509 *x, stir_shaken_hash_entry_t **trusted_pa_keys, size_t hashsize);
stir_shaken_status_t stir_shaken_add_cert_trusted_from_file(stir_shaken_context_t *ss, char *file_name, stir_shaken_hash_entry_t **trusted_pa_keys, size_t hashsize);

stir_shaken_status_t ca_sp_cert_req_reply_challenge(stir_shaken_context_t *ss, stir_shaken_ca_t *ca, char *msg, char *authz_challenge, char *authz_url, stir_shaken_ca_session_t **session_out, uint8_t use_ssl);
stir_shaken_status_t ca_create_session_challenge_details(stir_shaken_context_t *ss, char *status, const char *spc, char *authz_url, stir_shaken_ca_session_t *session);
stir_shaken_status_t ca_session_prepare_polling(stir_shaken_context_t *ss, const char *msg, char *spc, char *expires, char *validated, stir_shaken_ca_session_t *session);
stir_shaken_status_t ca_extract_spc_token_from_authz_response(stir_shaken_context_t *ss, const char *msg, const char **spc_token, jwt_t **spc_token_jwt);
stir_shaken_status_t ca_verify_spc(stir_shaken_context_t *ss, jwt_t *spc_jwt, unsigned long long int spc);
stir_shaken_status_t ca_verify_pa_cert(stir_shaken_context_t *ss, stir_shaken_ca_t *ca, stir_shaken_cert_t *cert);
void stir_shaken_ca_destroy(stir_shaken_ca_t *ca);
stir_shaken_status_t stir_shaken_run_ca_service(stir_shaken_context_t *ss, stir_shaken_ca_t *ca);
stir_shaken_status_t stir_shaken_run_pa_service(stir_shaken_context_t *ss, stir_shaken_pa_t *pa);

void stir_shaken_sp_destroy(stir_shaken_sp_t *sp);

#define STI_CA_ACME_ADDR				"ca.shaken.signalwire.cloud"
#define STI_CA_API_URL					"/sti-ca/"
#define STI_CA_ACME_API_URL				"/sti-ca/acme"
#define STI_CA_ACME_CERT_REQ_URL		"/sti-ca/acme/cert"
#define STI_CA_ACME_AUTHZ_URL			"/sti-ca/acme/authz"
#define STI_CA_ACME_NONCE_REQ_URL		"/sti-ca/acme/nonce"
#define STI_CA_ACME_NEW_ACCOUNT_URL		"/sti-ca/acme/account"
#define STI_CA_AUTHORITY_CHECK_URL		"/sti-ca/authority-over-the-number-check"

// TEST

stir_shaken_status_t stir_shaken_test_die(const char *reason, const char *file, int line);

/* Exit from calling location if test fails. */
#define stir_shaken_assert(x, m) if (!(x)) return stir_shaken_test_die((m), __FILE__, __LINE__);

#endif // __STIR_SHAKEN
