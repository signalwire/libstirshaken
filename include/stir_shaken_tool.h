#include <stir_shaken.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <getopt.h>
#include <ctype.h>


#define STIR_SHAKEN_BUFLEN 1000

#define COMMAND_NAME_KEYS			"keys"
#define COMMAND_NAME_CERT			"cert"
#define COMMAND_NAME_CERT_CA		"cert (CA)"
#define COMMAND_NAME_CERT_SP		"cert (SP)"
#define COMMAND_NAME_INSTALL_CERT	"install"
#define COMMAND_NAME_UNKNOWN		"unknown"
#define COMMAND_KEYS 0
#define COMMAND_CSR	1
#define COMMAND_CERT 2
#define COMMAND_CERT_CA 3
#define COMMAND_CERT_SP 4
#define COMMAND_INSTALL_CERT 5
#define COMMAND_UNKNOWN 100

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
#define OPTION_MAX			12

#define OPTION_NAME_PUBKEY		"pubkey"
#define OPTION_NAME_PRIVKEY		"privkey"
#define OPTION_NAME_ISSUER_C	"issuer_c"
#define OPTION_NAME_ISSUER_CN	"issuer_cn"
#define OPTION_NAME_SERIAL		"serial"
#define OPTION_NAME_EXPIRY		"expiry"
#define OPTION_NAME_TYPE		"type"
#define OPTION_NAME_TYPE_SP		"SP"
#define OPTION_NAME_TYPE_CA		"CA"
#define OPTION_NAME_HELP		"help"
#define OPTION_NAME_SUBJECT_C	"subject_c"
#define OPTION_NAME_SUBJECT_CN	"subject_cn"
#define OPTION_NAME_SPC			"spc"

#define PRINT_SHAKEN_ERROR_IF_SET \
    if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

#define PRINT_SHAKEN_ERROR_IF_SET_PTR \
    if (stir_shaken_is_error_set(ss)) { \
		error_description = stir_shaken_get_error(ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

#define CA_DIR	NULL
#define CRL_DIR	NULL

struct ca {
	stir_shaken_ssl_keys_t keys;
    stir_shaken_cert_t cert;
	
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char public_key_name[STIR_SHAKEN_BUFLEN];
	char cert_name[STIR_SHAKEN_BUFLEN];
	char cert_text_name[STIR_SHAKEN_BUFLEN];
	char cert_name_hashed[STIR_SHAKEN_BUFLEN];
	char issuer_c[STIR_SHAKEN_BUFLEN];
	char issuer_cn[STIR_SHAKEN_BUFLEN];
	char subject_c[STIR_SHAKEN_BUFLEN];
	char subject_cn[STIR_SHAKEN_BUFLEN];
	int serial;
	int serial_sp;
	int expiry_days;
	int expiry_days_sp;
	const char *number_start_sp;
	const char *number_end_sp;
} ca;

struct sp {
	stir_shaken_ssl_keys_t keys;
	uint32_t code;
	stir_shaken_csr_t csr;
    stir_shaken_cert_t cert;
	
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char public_key_name[STIR_SHAKEN_BUFLEN];
	char csr_name[STIR_SHAKEN_BUFLEN];
	char csr_text_name[STIR_SHAKEN_BUFLEN];
	char cert_name[STIR_SHAKEN_BUFLEN];
	char cert_text_name[STIR_SHAKEN_BUFLEN];
	const char *subject_c;
	const char *subject_cn;
	int serial;
	int expiry_days;
} sp;

struct options {
	int command_cert_type;
	stir_shaken_ssl_keys_t keys;
	char private_key_name[STIR_SHAKEN_BUFLEN];
	char public_key_name[STIR_SHAKEN_BUFLEN];
	uint32_t spc;
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
} options;

int stirshaken_command_configure(stir_shaken_context_t *ss, const char *command_name, struct ca *ca, struct sp *sp, struct options *options);
stir_shaken_status_t stirshaken_command_validate(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, struct options *options);
stir_shaken_status_t stirshaken_command_execute(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, struct options *options);
