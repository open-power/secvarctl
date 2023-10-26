/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023 IBM Corp.
 */
#include <argp.h>
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "common/util.h"
#include "common/validate.h"
#include "guest_svc_backend.h"

/*
 * @param key , every option that is parsed has a value to identify it
 * @param arg, if key is an option than arg will hold its value
 * @param state,  argp_state struct that contains useful information about the current parsing state
 * @return success or errno
 */
static int parse_options(int key, char *arg, struct argp_state *state)
{
	struct validate_args *args = state->input;
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
	case 'a':
		args->input_form = AUTH_FILE;
		break;
	case 'p':
		args->input_form = PKCS7_FILE;
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
		if (!args->input_file)
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
 * called from main()
 * handles argument parsing for validate command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
 */
int guest_validation_command(int argc, char *argv[])
{
	unsigned char *buff = NULL;
	size_t size;
	int rc;
	struct validate_args args = {
		.help_flag = 0,
		.input_file = NULL,
		.input_form = AUTH_FILE,
	};

	/* combine command and subcommand for usage/help messages */
	argv[0] = "secvarctl -m guest validate";

	struct argp_option options[] = {
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "pkcs7", 'p', 0, 0, "file is a PKCS7" },
		{ "esl", 'e', 0, 0, "file is an EFI Signature List (ESL)" },
		{ "cert", 'c', 0, 0, "file is an x509 cert (DER or PEM format)" },
		{ "auth", 'a', 0, 0,
		  "file is a properly generated authenticated variable, DEFAULT" },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = { options, parse_options, "<FILE>",
			     "The purpose of this command is to help ensure that the "
			     "format of the file is correct"
			     " and is able to be parsed for data. NOTE: This command "
			     "mainly performs formatting checks, "
			     "invalid content/signatures can still exist"
			     " use 'secvarctl -m guest verify' to see if content and file "
			     "signature (if PKCS7/auth) are valid" };

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.help_flag)
		return rc;

	buff = (unsigned char *)get_data_from_file(args.input_file, SIZE_MAX, &size);
	if (!buff) {
		prlog(PR_ERR, "ERROR: failed to get data from %s\n", args.input_file);
		return INVALID_FILE;
	}

	switch (args.input_form) {
	case CERT_FILE:
		rc = validate_cert(buff, size, false);
		break;
	case ESL_FILE:
		rc = validate_esl(buff, size);
		break;
	case PKCS7_FILE:
		rc = validate_pkcs7(buff, size);
		break;
	case AUTH_FILE:
	default:
		rc = validate_auth(buff, size);
		break;
	}

	if (buff)
		free(buff);

	if (!args.help_flag)
		printf("RESULT: %s\n", rc ? "FAILURE" : "SUCCESS");

	return rc;
}
