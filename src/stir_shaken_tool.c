#include <stir_shaken_tool.h>


static void stirshaken_usage(const char *name)
{
	if (name == NULL)
		return;
	
	fprintf(stderr, "\nusage:\t %s %s|%s|%s (params...) [-f output file name]\n\n", name, COMMAND_NAME_KEYS, COMMAND_NAME_CERT, COMMAND_NAME_INSTALL_CERT);
	fprintf(stderr, "     \t keys			: generate key pair\n");
	fprintf(stderr, "     \t cert			: generate SP or CA certificate depending on --type\n");
	fprintf(stderr, "     \t install		: hash CA certificate and copy into CA dir\n");
	fprintf(stderr, "\n");
}

static void stirshaken_range_error(char argument, unsigned long value)
{
	fprintf(stderr, "\nERR, argument [%c] too big [%lu]\n\n", argument, value);
}

static void help_hint(const char *name)
{
	if (name == NULL)
		return;
	fprintf(stderr, "\nTry %s --help for more information.\n", name);
	return;
}


int main(int argc, char *argv[])
{
	int c = -1;
	char f[STIR_SHAKEN_BUFLEN] = {0}, *pCh = NULL;
	unsigned long long  helper;
	unsigned long serial = 0;
	unsigned long expiry = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	int command = COMMAND_UNKNOWN;
	const char *command_name = COMMAND_NAME_UNKNOWN;


	if (argc < 2) {
		stirshaken_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	int option_index = 0;
	struct option long_options[] = {
		{ "pubkey", required_argument, 0, OPTION_PUBKEY },
		{ "privkey", required_argument, 0, OPTION_PRIVKEY },
		{ "issuer_c", required_argument, 0, OPTION_ISSUER_C },
		{ "issuer_cn", required_argument, 0, OPTION_ISSUER_CN },
		{ "serial", required_argument, 0, OPTION_SERIAL },
		{ "expiry", required_argument, 0, OPTION_EXPIRY },
		{ "type", required_argument, 0, OPTION_TYPE },
		{ "help", no_argument, 0, OPTION_HELP },
		{ 0 }
	};

	// Parse options

	while ((c = getopt_long(argc, argv, "f:", long_options, &option_index)) != -1) {

		if (c < OPTION_MAX) {
			fprintf(stderr, "+ Processing OPTION %d (%s)\n", c, long_options[option_index].name);
		} else {
			fprintf(stderr, "+ Processing OPTION %d ('%c')\n", c, c);
		}

		switch (c) {

			case OPTION_PUBKEY:
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "Public key name too long\n");
					goto fail;
				}
				strncpy(ca.public_key_name, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Public key name is: %s\n", ca.public_key_name);
				break;

			case OPTION_PRIVKEY:
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "Private key name too long\n");
					goto fail;
				}
				strncpy(ca.private_key_name, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Private key name is: %s\n", ca.private_key_name);
				break;

			case OPTION_ISSUER_CN:
				break;
			
			case OPTION_SERIAL:

				helper = strtoul(optarg, &pCh, 10);
				if (helper > 0x10000 - 1) {
					stirshaken_range_error(c, helper);
					goto fail;
				}
				if ((pCh == optarg) || (*pCh != '\0')) {    /* check */
					fprintf(stderr, "Invalid argument\n");
					fprintf(stderr, "Parameter conversion error, nonconvertible part is: [%s]\n", pCh);
					help_hint(argv[0]);
					goto fail;
				}
				serial = helper;
				break;
			
			case OPTION_EXPIRY:
				
				helper = strtoul(optarg, &pCh, 10);
				if (helper > 0x10000 - 1) {
					stirshaken_range_error(c, helper);
					goto fail;
				}
				if ((pCh == optarg) || (*pCh != '\0')) {    /* check */
					fprintf(stderr, "Invalid argument\n");
					fprintf(stderr, "Parameter conversion error, nonconvertible part is: [%s]\n", pCh);
					help_hint(argv[0]);
					goto fail;
				}
				expiry = helper;
				break;

			case OPTION_TYPE:

				break;

			case OPTION_HELP:
				stirshaken_usage(argv[0]);
				break;

			case 'f':
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "-f name too long\n");
					goto fail;
				}
				strncpy(f, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Output file is: %s\n", f);
				break;

			case '?':
				if (optopt == 'f')
					fprintf(stderr, "\nOption -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					fprintf(stderr,"Unknown option '-%c'.\n", optopt);
				else {
					fprintf(stderr, "Are there any long options? Please check that you have typed them correctly.\n");
				}
				stirshaken_usage(argv[0]);
				exit(EXIT_FAILURE);

			default:
				help_hint(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (1 != (argc - optind)) {
		fprintf(stderr, "\nInvalid number of non-option arguments.\nThere should be 1 non-option arguments\n");
		help_hint(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	// Parse the comamnd

	if (!strcmp(argv[optind], COMMAND_NAME_KEYS)) {

		fprintf(stderr, "\n\nCreating key pair...\n\n");
		command = COMMAND_KEYS;
		command_name = COMMAND_NAME_KEYS;

	} else if (!strcmp(argv[optind], COMMAND_NAME_CERT)) {

		fprintf(stderr, "\n\nCreating CA certificate...\n\n");
		command = COMMAND_CERT;
		command_name = COMMAND_NAME_CERT;

	} else if (!strcmp(argv[optind], COMMAND_NAME_INSTALL_CERT)) {

		fprintf(stderr, "\n\nInstalling CA certificate...\n\n");
		command = COMMAND_INSTALL_CERT;
		command_name = COMMAND_NAME_INSTALL_CERT;

	} else {

		fprintf(stderr, "Error. Unknown command: %s\n", argv[optind]);
		stirshaken_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	// Validate the command
	
	if (STIR_SHAKEN_STATUS_OK != stirshaken_command_validate(&ss, command, &ca, &sp, CA_DIR, CRL_DIR)) {
		fprintf(stderr, "\nError. Command %s cannot be executed because it's missing params or params are invalid\n", command_name);
		PRINT_SHAKEN_ERROR_IF_SET
		goto fail;
	}

	// Process the command
	
	if (STIR_SHAKEN_STATUS_OK != stirshaken_command_execute(&ss, command, &ca, &sp, CA_DIR, CRL_DIR)) {
		fprintf(stderr, "\nError. Command %s failed\n", command_name);
		PRINT_SHAKEN_ERROR_IF_SET
		goto fail;
	}
	
	fprintf(stderr, "=== OK.\n\n");
	return EXIT_SUCCESS;

fail:
	fprintf(stderr, "Error\n");
	return EXIT_FAILURE;
}
