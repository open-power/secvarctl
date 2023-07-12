/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "common/read.h"
#include "guest_svc_backend.h"

/*
 * reads the esl data from path
 *
 * @param path , the path to the file with ending '/'
 * @param esl_data, esl data
 * @param esl_data_len, size of esl data
 */
static int variable_from_path(const char *path, uint8_t **esl_data, size_t *esl_data_len)
{
	int rc = SUCCESS;
	size_t buffer_size = 0;
	uint8_t *buffer = NULL;

	buffer = (uint8_t *)get_data_from_file(path, SIZE_MAX, &buffer_size);
	if (!buffer)
		return INVALID_FILE;

	*esl_data = buffer;
	*esl_data_len = buffer_size;

	return rc;
}

/*
 * create secure boot variable path
 *
 * @param path , the path to the file with ending '/'
 * @param variable_name , guest secure boot variable name
 * @param variable_path, path of variable
 * @return SUCCESS or error number
 */
static int get_variable_path(const char *path, const char *variable_name, char **variable_path)
{
	int len = 0;
	char *esl_data = "/data";

	len = strlen(path) + strlen(variable_name) + strlen(esl_data);
	*variable_path = malloc(len + 1);
	if (*variable_path == NULL) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	memset(*variable_path, 0x00, len + 1);
	len = 0;
	memcpy(*variable_path + len, path, strlen(path));
	len += strlen(path);
	memcpy(*variable_path + len, variable_name, strlen(variable_name));
	len += strlen(variable_name);
	memcpy(*variable_path + len, esl_data, strlen(esl_data));

	return SUCCESS;
}

/*
 * print esl file informations
 *
 * @param esl_data , esl data
 * @param esl_data_len , size of esl data
 * @param print_raw, 1 for human readable 0 for raw data
 * @param variable_name , guest secure boot variable name
 * @return SUCCESS or error number
 */
static int read_cert(const uint8_t *cert_data, const size_t cert_data_len, const int is_print_raw,
		     const uint8_t *variable_name)
{
	int rc = SUCCESS;
	crypto_x509_t *x509;

	if (is_print_raw) {
		print_raw((char *)cert_data, cert_data_len);
		return rc;
	}

	rc = crypto.get_x509_certificate(cert_data, cert_data_len, &x509);
	if (rc) {
		/*
       * if here, parsing cert in der failed
       * check if we have compiled with pkcs7_write functions
       * if so we can try to convert pem to der and try again
       */
#ifdef SECVAR_CRYPTO_WRITE_FUNC
		uint8_t *cert;
		size_t cert_size;
		prlog(PR_INFO, "failed to parse x509 as DER, trying PEM...\n");
		rc = crypto.get_der_from_pem(cert_data, cert_data_len, &cert, &cert_size);
		if (rc) {
			prlog(PR_ERR,
			      "ERROR: failed to parse x509 (tried DER and PEM formats). \n");
			return CERT_FAIL;
		}

		rc = crypto.get_x509_certificate(cert, cert_size, &x509);
		free(cert);
		if (rc)
			return rc;
#else
		prlog(PR_INFO, "ERROR: failed to parse x509. Make sure file is in DER not PEM\n");
		return rc;
#endif
	}

	rc = crypto.validate_x509_certificate(x509);
	if (rc)
		prlog(PR_ERR, "ERROR: x509 certificate is invalid (%d)\n", rc);
	else
		rc = print_cert_info(x509);

	crypto.release_x509_certificate(x509);

	return rc;
}

/*
 * print esl file informations
 *
 * @param esl_data , esl data
 * @param esl_data_len , size of esl data
 * @param print_raw, 1 for human readable 0 for raw data
 * @param variable_name , guest secure boot variable name
 * @return SUCCESS or error number
 */
static int read_esl(const uint8_t *esl_data, const size_t esl_data_len, const int is_print_raw,
		    const uint8_t *variable_name)
{
	int rc = SUCCESS;

	if (is_print_raw) {
		print_raw((char *)esl_data, esl_data_len);
		return rc;
	}

	rc = print_variables(esl_data, esl_data_len, variable_name);

	return rc;
}

/*
 * print auth file informations
 *
 * @param auth_data , auth data
 * @param auth_data_len , size of auth data
 * @param is_print_raw, 1 for human readable 0 for raw data
 * @param variable_name , guest secure boot variable name
 * @return SUCCESS or error number
 */
static int read_auth(const uint8_t *auth_data, size_t auth_data_len, const int is_print_raw,
		     const uint8_t *variable_name)
{
	int rc = SUCCESS, cert_num = 0;
	size_t auth_size, pkcs7_size, append_flag;
	crypto_x509_t *x509 = NULL;
	crypto_pkcs7_t *pkcs7 = NULL;
	auth_info_t *auth = NULL;

	if (is_print_raw) {
		print_raw((char *)auth_data, auth_data_len);
		return rc;
	}

	append_flag = extract_append_header(auth_data, auth_data_len);
	auth = (auth_info_t *)(auth_data + APPEND_HEADER_LEN);
	auth_data_len -= APPEND_HEADER_LEN;
	auth_size = auth->auth_cert.hdr.da_length + sizeof(auth->timestamp);
	pkcs7_size = extract_pkcs7_len(auth);

	printf("APPEND HEADER :\n");
	printf("\tAppend Flag : %zu\n", append_flag);
	printf("AUTH INFO:\n");
	printf("\tGuid code is : ");
	print_signature_type(&auth->auth_cert.cert_type);
	printf("\tType: PKCS7\n");
	printf("\tAuth File Size = %zu\n\t  -Auth/PKCS7 Data Size = %zu\n\t  -ESL Size = %zu\n",
	       auth_data_len, auth_size, auth_data_len - auth_size);
	printf("\tTimestamp: ");
	print_timestamp(auth->timestamp);

	printf("PKCS7:\n");

	rc = crypto.get_pkcs7_certificate(auth->auth_cert.cert_data, pkcs7_size, &pkcs7);
	if (rc != SUCCESS) {
		prlog(PR_ERR, "ERROR: parsing of pkcs7 certificate is failed (%d)\n", rc);
		return rc;
	}

	printf("\tDigest Alg: SHA256\n");

	while (rc == SUCCESS &&
	       crypto.get_signing_cert_from_pkcs7(pkcs7, cert_num, &x509) == SUCCESS) {
		printf("SIGNING CERTIFICATE:\n");

		if (rc == SUCCESS)
			rc = print_cert_info(x509);

		cert_num++;
	}

	crypto.release_pkcs7_certificate(pkcs7);

	printf("ESL INFO:\n");
	if (auth_size == auth_data_len)
		printf("ESL is empty, it is reset file.\n");
	else
		rc = print_variables(auth_data + APPEND_HEADER_LEN + auth_size,
				     auth_data_len - auth_size, variable_name);

	return rc;
}

/*
 * Does the appropriate read command depending on is_readable on the file <path>/<var>/data
 *
 * @param path , the path to the file with ending '/'
 * @param is_print_raw, 1 for human readable 0 for raw data
 * @param variable_name , guest secure boot variable name
 * @return SUCCESS or error number
 */
static int read_path(const char *path, const int is_print_raw, const char *variable_name)
{
	int rc;
	char *variable_path = NULL;
	uint8_t *esl_data = NULL;
	size_t esl_data_size = 0;

	if (variable_name != NULL) {
		rc = get_variable_path(path, variable_name, &variable_path);
		if (rc != SUCCESS)
			return rc;

		printf("READING %s :\n", variable_name);
		rc = variable_from_path(variable_path, &esl_data, &esl_data_size);
		if (rc == SUCCESS) {
			if (is_print_raw || esl_data_size == DEFAULT_PK_LEN)
				print_raw((char *)esl_data, esl_data_size);
			else if (esl_data_size >= TIMESTAMP_LEN)
				rc = print_variables(esl_data + TIMESTAMP_LEN,
						     esl_data_size - TIMESTAMP_LEN,
						     (uint8_t *)variable_name);
			else
				prlog(PR_WARNING, "WARNING: The %s database is empty.\n",
				      variable_name);

			if (esl_data != NULL)
				free(esl_data);
		} else
			prlog(PR_ERR, "ERROR: could not read %s database.\n", variable_name);

		if (variable_path != NULL)
			free(variable_path);
	} else {
		for (int i = 0; i < defined_sb_variable_len; i++) {
			rc = get_variable_path(path, (char *)defined_sb_variables[i],
					       &variable_path);
			if (rc != SUCCESS)
				return rc;

			printf("READING %s :\n", defined_sb_variables[i]);
			rc = variable_from_path(variable_path, &esl_data, &esl_data_size);
			if (rc == SUCCESS) {
				if (is_print_raw ||
				    (esl_data_size == DEFAULT_PK_LEN &&
				     memcmp(defined_sb_variables[i], PK_VARIABLE, PK_LEN) == 0))
					print_raw((char *)esl_data, esl_data_size);
				else if (esl_data_size >= TIMESTAMP_LEN)
					rc = print_variables(esl_data + TIMESTAMP_LEN,
							     esl_data_size - TIMESTAMP_LEN,
							     (uint8_t *)defined_sb_variables[i]);
				else
					prlog(PR_WARNING, "WARNING: The %s database is empty.\n",
					      defined_sb_variables[i]);

				if (esl_data != NULL)
					free(esl_data);
			} else {
				prlog(PR_WARNING, "WARNING: could not read %s database.\n",
				      defined_sb_variables[i]);
				rc = SUCCESS;
			}

			if (variable_path != NULL)
				free(variable_path);
		}
	}

	return rc;
}

/*
 * @param key , every option that is parsed has a value to identify it
 * @param arg, if key is an option than arg will hold its value ex: -<key> <arg>
 * @param state,  argp_state struct that contains useful information about the current parsing state
 * @return success or errno
 */
static int parse_options(int key, char *arg, struct argp_state *state)
{
	struct read_args *args = state->input;
	int rc = SUCCESS;

	switch (key) {
	case '?':
		args->help_flag = 1;
		argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
		break;
	case ARGP_OPT_USAGE_KEY:
		args->help_flag = 1;
		argp_state_help(state, stdout, ARGP_HELP_USAGE);
		break;
	case 'v':
		verbose = PR_DEBUG;
		break;
	case 'r':
		args->print_raw = 1;
		break;
	case 'p':
		args->path = arg;
		break;
	case 'n':
		args->variable_name = arg;
		if (args->variable_name != NULL && !is_secure_boot_variable(args->variable_name))
			prlog(PR_WARNING, "WARNING!! %s is an arbitrary variable name\n",
			      args->variable_name);
		break;
	case 'a':
		args->input_form = AUTH_FILE;
		break;
	case 'e':
		args->input_form = ESL_FILE;
		break;
	case 'c':
		args->input_form = CERT_FILE;
		break;
	case ARGP_KEY_ARG:
		if (args->input_file == NULL)
			args->input_file = arg;
		break;
	case ARGP_KEY_SUCCESS:
		/* check that all essential args are given and valid */
		if (args->help_flag)
			break;
		if (args->input_form != UNKNOWN_FILE && !args->input_file)
			prlog(PR_ERR, "ERROR: missing input file, see usage...\n");
		else
			break;
		argp_usage(state);
		rc = ARG_PARSE_FAIL;
		break;
	}

	if (rc)
		prlog(PR_ERR, "failed during argument parsing\n");

	return rc;
}

/*
 * handles argument parsing for read command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
 */
int guest_read_command(int argc, char *argv[])
{
	int rc;
	uint8_t *buffer = NULL;
	size_t buffer_size = 0;
	struct read_args args = { .help_flag = 0,
				  .print_raw = 0,
				  .path = SECVARPATH,
				  .variable_name = NULL,
				  .input_file = NULL,
				  .input_form = UNKNOWN_FILE };

	/* combine command and subcommand for usage/help messages */
	argv[0] = "secvarctl -m guest read";

	struct argp_option options[] = {
		{ "var", 'n', "VAR_NAME", 0,
		  "name of a secure boot variable, used when generating an PKCS7/Auth file." },
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "raw", 'r', 0, 0, "prints raw data, default is human readable information" },
		{ "esl", 'e', 0, 0, "file is an EFI Signature List (ESL)" },
		{ "cert", 'c', 0, 0, "file is an x509 cert (DER or PEM format)" },
		{ "auth", 'a', 0, 0, "file is a properly generated authenticated variable" },
		{ "path", 'p', "PATH", 0,
		  "looks for Guest secure boot variable directories in PATH, default is " SECVARPATH },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = { options, parse_options,
			     "This program command is created to easily view secure "
			     "variables. The current variables"
			     " that are able to be observed are the Guest secure boot variable."
			     "If no options are"
			     " given, then the information for the keys in the "
			     "default path will be printed."
			     " If the user would like to print the information for "
			     "another ESL file,"
			     " then the '-e' command would be appropriate."
			     "\vvalues for [VARIABLES] = guest secure boot variable "
			     "type one of the following to"
			     " get info on that key, default is all. NOTE does not "
			     "work when -e option is present" };

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.help_flag)
		return rc;

	if (args.input_file != NULL) {
		buffer = (uint8_t *)get_data_from_file(args.input_file, SIZE_MAX, &buffer_size);
		if (buffer == NULL) {
			prlog(PR_ERR, "ERROR: failed to get data from %s\n", args.input_file);
			return INVALID_FILE;
		}
	}

	switch (args.input_form) {
	case CERT_FILE:
		rc = read_cert(buffer, buffer_size, args.print_raw, (uint8_t *)args.variable_name);
		break;
	case ESL_FILE:
		rc = read_esl(buffer, buffer_size, args.print_raw, (uint8_t *)args.variable_name);
		break;
	case AUTH_FILE:
		rc = read_auth(buffer, buffer_size, args.print_raw, (uint8_t *)args.variable_name);
		break;
	default:
		rc = read_path(args.path, args.print_raw, args.variable_name);
		break;
	}

	if (buffer != NULL)
		free(buffer);

	if (!args.help_flag)
		printf("RESULT: %s\n", rc ? "FAILURE" : "SUCCESS");

	return rc;
}

struct command guest_command_table[] = { { .name = "read", .func = guest_read_command },
					 { .name = "write", .func = guest_write_command },
					 { .name = "validate", .func = guest_validation_command },
					 { .name = "verify", .func = guest_verify_command },
#ifdef SECVAR_CRYPTO_WRITE_FUNC
					 { .name = "generate", .func = guest_generate_command }
#endif
};
