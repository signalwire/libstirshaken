#include <stir_shaken.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <getopt.h>
#include <ctype.h>


#define STIR_SHAKEN_BUFLEN 1000

#define COMMAND_NAME_KEYS			"keys"
#define COMMAND_NAME_CERT			"cert"
#define COMMAND_NAME_INSTALL_CERT	"install"
#define COMMAND_NAME_UNKNOWN		"unknown"
#define COMMAND_KEYS 0
#define COMMAND_CERT 1
#define COMMAND_INSTALL_CERT 2
#define COMMAND_UNKNOWN 100

#define OPTION_PUBKEY		1
#define OPTION_PRIVKEY		2
#define OPTION_ISSUER_C		3
#define OPTION_ISSUER_CN	4
#define OPTION_SERIAL		5
#define OPTION_EXPIRY		6
#define OPTION_TYPE			7
#define OPTION_HELP			8
#define OPTION_MAX			9

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
	const char *issuer_c;
	const char *issuer_cn;
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

stir_shaken_status_t stirshaken_command_validate(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, const char *ca_dir, const char *crl_dir);
stir_shaken_status_t stirshaken_command_execute(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, const char *ca_dir, const char *crl_dir);
