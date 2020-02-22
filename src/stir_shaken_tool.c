#include <stir_shaken_tool.h>


static void stirshaken_usage(const char *name)
{
	if (name == NULL)
		return;
	
	fprintf(stderr, "\nusage:\t command\n\n", name);
	fprintf(stderr, "\t\t %s --%s pub.pem --%s priv.pem\n", COMMAND_NAME_KEYS, OPTION_NAME_PUBKEY, OPTION_NAME_PRIVKEY);
	fprintf(stderr, "\t\t %s --%s %s --%s key --%s key --%s C --%s CN --%s SERIAL --%s EXPIRY\n", COMMAND_NAME_CERT, OPTION_NAME_TYPE, OPTION_NAME_TYPE_CA, OPTION_NAME_PRIVKEY, OPTION_NAME_PUBKEY, OPTION_NAME_ISSUER_C, OPTION_NAME_ISSUER_CN, OPTION_NAME_SERIAL, OPTION_NAME_EXPIRY);
	fprintf(stderr, "\t\t %s --pubkey pub.pem --privkey priv.pem\n", COMMAND_NAME_INSTALL_CERT);
	fprintf(stderr, "\t\t %s			: generate key pair\n", COMMAND_NAME_KEYS);
	fprintf(stderr, "\t\t %s			: generate SP or CA certificate depending on --type\n", COMMAND_NAME_CERT);
	fprintf(stderr, "\t\t %s		: hash CA certificate and copy into CA dir\n\n", COMMAND_NAME_INSTALL_CERT);
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
	char *pCh = NULL;
	unsigned long long  helper;
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
		{ OPTION_NAME_PUBKEY, required_argument, 0, OPTION_PUBKEY },
		{ OPTION_NAME_PRIVKEY, required_argument, 0, OPTION_PRIVKEY },
		{ OPTION_NAME_ISSUER_C, required_argument, 0, OPTION_ISSUER_C },
		{ OPTION_NAME_ISSUER_CN, required_argument, 0, OPTION_ISSUER_CN },
		{ OPTION_NAME_SERIAL, required_argument, 0, OPTION_SERIAL },
		{ OPTION_NAME_EXPIRY, required_argument, 0, OPTION_EXPIRY },
		{ OPTION_NAME_TYPE, required_argument, 0, OPTION_TYPE },
		{ OPTION_NAME_HELP, no_argument, 0, OPTION_HELP },
		{ OPTION_NAME_SUBJECT_C, required_argument, 0, OPTION_SUBJECT_C },
		{ OPTION_NAME_SUBJECT_CN, required_argument, 0, OPTION_SUBJECT_CN },
		{ OPTION_NAME_SPC, required_argument, 0, OPTION_SPC },
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
					fprintf(stderr, "Option value too long\n");
					goto fail;
				}
				strncpy(options.public_key_name, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Public key name is: %s\n", options.public_key_name);
				break;

			case OPTION_PRIVKEY:
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "Option value too long\n");
					goto fail;
				}
				strncpy(options.private_key_name, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Private key name is: %s\n", options.private_key_name);
				break;

			case OPTION_ISSUER_C:
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "Option value too long\n");
					goto fail;
				}
				strncpy(options.issuer_c, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Issuer C is: %s\n", options.issuer_c);
				break;
			
			case OPTION_ISSUER_CN:
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "Option value too long\n");
					goto fail;
				}
				strncpy(options.issuer_cn, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Issuer CN is: %s\n", options.issuer_cn);
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
				options.serial = helper;
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
				options.expiry_days = helper;
				break;

			case OPTION_TYPE:
				if (!strcmp(optarg, OPTION_NAME_TYPE_CA)) {
					
					options.command_cert_type = COMMAND_CERT_CA;
				
				} else if (!strcmp(optarg, OPTION_NAME_TYPE_SP)) {

					options.command_cert_type = COMMAND_CERT_SP;

				} else {
					fprintf(stderr, "Invalid option %s for --type\n", optarg);
					goto fail;
				}

				break;

			case OPTION_HELP:
				stirshaken_usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;

			case 'f':
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "-f name too long\n");
					goto fail;
				}
				strncpy(options.file, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Output file is: %s\n", options.file);
				break;

			case OPTION_SUBJECT_C:
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "Option value too long\n");
					goto fail;
				}
				strncpy(options.subject_c, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Subject C is: %s\n", options.subject_c);
				break;
			
			case OPTION_SUBJECT_CN:
				if (strlen(optarg) > STIR_SHAKEN_BUFLEN - 1) {
					fprintf(stderr, "Option value too long\n");
					goto fail;
				}
				strncpy(options.subject_cn, optarg, STIR_SHAKEN_BUFLEN);
				fprintf(stderr, "Subject CN is: %s\n", options.subject_cn);
				break;
			
			case OPTION_SPC:
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
				options.spc = helper;
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
				fprintf(stderr, "Error. Missing options?");
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

	command = stirshaken_command_configure(&ss, argv[optind], &ca, &sp, &options);
	if (COMMAND_UNKNOWN == command) {
		fprintf(stderr, "\nError. Invalid command\n");
		PRINT_SHAKEN_ERROR_IF_SET
		goto fail;
	}


	// Validate the command
	
	if (STIR_SHAKEN_STATUS_OK != stirshaken_command_validate(&ss, command, &ca, &sp, &options)) {
		fprintf(stderr, "\nError. Missing params or params are invalid\n");
		PRINT_SHAKEN_ERROR_IF_SET
		goto fail;
	}

	// Process the command
	
	if (STIR_SHAKEN_STATUS_OK != stirshaken_command_execute(&ss, command, &ca, &sp, &options)) {
		fprintf(stderr, "\nError. Command failed\n");
		PRINT_SHAKEN_ERROR_IF_SET
		goto fail;
	}
	
	fprintf(stderr, "=== OK.\n\n");
	return EXIT_SUCCESS;

fail:
	fprintf(stderr, "Error\n");
	return EXIT_FAILURE;
}
