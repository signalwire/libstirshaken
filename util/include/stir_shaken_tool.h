#include <stir_shaken.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <getopt.h>
#include <ctype.h>


#define STIR_SHAKEN_BUFLEN 1000

#define COMMAND_KEYS			0
#define COMMAND_CSR				1
#define COMMAND_CERT			2
#define COMMAND_CERT_CA			3
#define COMMAND_CERT_SP			4
#define COMMAND_HASH_CERT	    5
#define COMMAND_SPC_TOKEN		6
#define COMMAND_JWT_CHECK		7
#define COMMAND_JWT_DUMP		8
#define COMMAND_CA				9
#define COMMAND_PA				10
#define COMMAND_SP_SPC_REQ		11
#define COMMAND_SP_CERT_REQ		12
#define COMMAND_PASSPORT_CREATE	13
#define COMMAND_UNKNOWN			100

#define COMMAND_NAME_KEYS			"keys"
#define COMMAND_NAME_CSR			"csr"
#define COMMAND_NAME_CERT			"cert"
#define COMMAND_NAME_CERT_CA		"cert (CA)"
#define COMMAND_NAME_CERT_SP		"cert (SP)"
#define COMMAND_NAME_HASH_CERT	    "hash"
#define COMMAND_NAME_SPC_TOKEN		"spc-token"
#define COMMAND_NAME_JWT_CHECK		"jwt-check"
#define COMMAND_NAME_JWT_DUMP		"jwt-dump"
#define COMMAND_NAME_CA				"ca"
#define COMMAND_NAME_PA				"pa"
#define COMMAND_NAME_SP_SPC_REQ		"sp-spc-req"
#define COMMAND_NAME_SP_CERT_REQ	"sp-cert-req"
#define COMMAND_NAME_PASSPORT_CREATE	"passport-create"
#define COMMAND_NAME_UNKNOWN		"unknown"

#define OPTION_PUBKEY		1
#define OPTION_PRIVKEY		2
#define OPTION_ISSUER_C		3
#define OPTION_ISSUER_CN	4
#define OPTION_SERIAL		5
#define OPTION_EXPIRY		6
#define OPTION_TYPE			7
#define OPTION_HELP			8
#define OPTION_SUBJECT_C	9
#define OPTION_SUBJECT_CN	10
#define OPTION_SPC			11
#define OPTION_SPC_TOKEN	12
#define OPTION_CA_CERT		13
#define OPTION_CSR			14
#define OPTION_TN_AUTH_LIST_URI	15
#define OPTION_PORT			16
#define OPTION_URL			17
#define OPTION_JWT          18
#define OPTION_SSL          19
#define OPTION_SSL_CERT     20
#define OPTION_SSL_KEY      21
#define OPTION_V			22
#define OPTION_VV			23
#define OPTION_VVV			24
#define OPTION_MAX			25

#define OPTION_NAME_PUBKEY		"pubkey"
#define OPTION_NAME_PRIVKEY		"privkey"
#define OPTION_NAME_ISSUER_C	"issuer_c"
#define OPTION_NAME_ISSUER_CN	"issuer_cn"
#define OPTION_NAME_SERIAL		"serial"
#define OPTION_NAME_EXPIRY		"expiry"
#define OPTION_NAME_TYPE		"type"
#define OPTION_NAME_TYPE_SP		"SP"
#define OPTION_NAME_TYPE_CA		"CA"
#define OPTION_NAME_TYPE_PA		"PA"
#define OPTION_NAME_HELP		"help"
#define OPTION_NAME_SUBJECT_C	"subject_c"
#define OPTION_NAME_SUBJECT_CN	"subject_cn"
#define OPTION_NAME_SPC			"spc"
#define OPTION_NAME_SPC_TOKEN	"spc_token"
#define OPTION_NAME_CA_CERT		"ca_cert"
#define OPTION_NAME_CSR			"csr"
#define OPTION_NAME_TN_AUTH_LIST_URI	"uri"
#define OPTION_NAME_PORT		"port"
#define OPTION_NAME_URL			"url"
#define OPTION_NAME_JWT			"jwt"
#define OPTION_NAME_SSL		    "ssl"
#define OPTION_NAME_SSL_CERT	"ssl_cert"
#define OPTION_NAME_SSL_KEY	    "ssl_key"
#define OPTION_NAME_V			"v"
#define OPTION_NAME_VV			"vv"
#define OPTION_NAME_VVV			"vvv"

#define PRINT_SHAKEN_ERROR_IF_SET \
    if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: %s\n", error_description); \
		printf("Error code is: %d\n", error_code); \
	}

#define PRINT_SHAKEN_ERROR_IF_SET_PTR \
    if (stir_shaken_is_error_set(ss)) { \
		error_description = stir_shaken_get_error(ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

#define STIR_SHAKEN_CHECK_CONVERSION \
				if (helper > 0x10000 - 1) { \
					stirshaken_range_error(c, helper); \
					goto fail; \
				} \
				if ((pCh == optarg) || (*pCh != '\0')) { \
					fprintf(stderr, "Invalid argument\n"); \
					fprintf(stderr, "Parameter conversion error, nonconvertible part is: [%s]\n", pCh); \
					help_hint(argv[0]); \
					goto fail; \
				}

#define STIR_SHAKEN_CHECK_CONVERSION_EXT \
			helper = strtoul(sp->spc, &pCh, 10); \
			if (helper > 0x10000 - 1) { \
				fprintf(stderr, "\nERR, argument too big [%llu]\n\n", helper); \
				goto fail; \
			} \
			if ((pCh == optarg) || (*pCh != '\0')) { \
				fprintf(stderr, "Invalid argument\n"); \
				fprintf(stderr, "Parameter conversion error, nonconvertible part is: [%s]\n", pCh); \
				goto fail; \
			}

#define STIR_SHAKEN_CHECK_OPTARG \
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) { \
					fprintf(stderr, "Option value too long\n"); \
					goto fail; \
				}

#define CA_DIR	NULL
#define CRL_DIR	NULL

struct ca {
	stir_shaken_ca_t ca;
	char issuer_c[STIR_SHAKEN_BUFLEN];
	char issuer_cn[STIR_SHAKEN_BUFLEN];
	char subject_c[STIR_SHAKEN_BUFLEN];
	char subject_cn[STIR_SHAKEN_BUFLEN];
	int serial;
	int expiry_days;
	char file[STIR_SHAKEN_BUFLEN];
} ca;

struct pa {
	stir_shaken_pa_t pa;
	char issuer_cn[STIR_SHAKEN_BUFLEN];
	char spc[STIR_SHAKEN_BUFLEN];
	char url[STIR_SHAKEN_BUFLEN];
	char nb[STIR_SHAKEN_BUFLEN];
	char na[STIR_SHAKEN_BUFLEN];
	char file_name[STIR_SHAKEN_BUFLEN];
	size_t sp_code;
} pa;

struct sp {
	stir_shaken_sp_t sp;
	char subject_c[STIR_SHAKEN_BUFLEN];
	char subject_cn[STIR_SHAKEN_BUFLEN];
	char spc[STIR_SHAKEN_BUFLEN];
	char spc_token[STIR_SHAKEN_BUFLEN];
	int serial;
	int expiry_days;
	char file[STIR_SHAKEN_BUFLEN];
	char url[STIR_SHAKEN_BUFLEN];
} sp;

struct options {
	int command_cert_type;
	stir_shaken_ssl_keys_t keys;
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char public_key_name[STIR_SHAKEN_BUFLEN];
	char spc[STIR_SHAKEN_BUFLEN];
	char spc_token[STIR_SHAKEN_BUFLEN];
	char file[STIR_SHAKEN_BUFLEN];
	char type[STIR_SHAKEN_BUFLEN];
	char subject_c[STIR_SHAKEN_BUFLEN];
	char subject_cn[STIR_SHAKEN_BUFLEN];
	char issuer_c[STIR_SHAKEN_BUFLEN];
	char issuer_cn[STIR_SHAKEN_BUFLEN];
	const char *ca_dir;
	const char *crl_dir;
	int serial;
	int expiry_days;
	char ca_cert[STIR_SHAKEN_BUFLEN];
	char csr_name[STIR_SHAKEN_BUFLEN];
	char tn_auth_list_uri[STIR_SHAKEN_BUFLEN];
	uint16_t port;
	char url[STIR_SHAKEN_BUFLEN];
	char jwt[STIR_SHAKEN_BUFLEN];
	int loglevel;
    uint8_t use_ssl;
	char ssl_cert_name[STIR_SHAKEN_BUFLEN];
	char ssl_key_name[STIR_SHAKEN_BUFLEN];
} options;

void stirshaken_range_error(char arg, unsigned long val);

int stirshaken_command_configure(stir_shaken_context_t *ss, const char *command_name, struct ca *ca, struct pa *pa, struct sp *sp, struct options *options);
stir_shaken_status_t stirshaken_command_validate(stir_shaken_context_t *ss, int command, struct ca *ca, struct pa *pa, struct sp *sp, struct options *options);
stir_shaken_status_t stirshaken_command_execute(stir_shaken_context_t *ss, int command, struct ca *ca, struct pa *pa, struct sp *sp, struct options *options);
