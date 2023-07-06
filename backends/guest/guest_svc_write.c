/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <argp.h>
#include "err.h"
#include "prlog.h"
#include "common/util.h"
#include "common/write.h"
#include "guest_svc_backend.h"

/*
 * @param key , every option that is parsed has a value to identify it
 * @param arg, if key is an option than arg will hold its value ex: -<key> <arg>
 * @param state,  argp_state struct that contains useful information about the current parsing state
 * @return success or errno
 */
static int parse_options(int key, char *arg, struct argp_state *state)
{
	struct write_args *args = state->input;
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
	case 'p':
		args->path = arg;
		break;
	case 'f':
		args->input_valid = 1;
		break;
	case 'v':
		verbose = PR_DEBUG;
		break;
	case ARGP_KEY_ARG:
		if (args->variable_name == NULL) {
			args->variable_name = arg;
			if (!is_secure_boot_variable(args->variable_name))
				prlog(PR_WARNING, "WARNING!! %s is an arbitrary variable name\n",
				      args->variable_name);
		} else if (args->input_file == NULL)
			args->input_file = arg;
		break;
	case ARGP_KEY_SUCCESS:
		if (args->help_flag)
			break;
		if (!args->variable_name)
			prlog(PR_ERR, "ERROR: missing variable, see usage...\n");
		else if (!args->input_file)
			prlog(PR_ERR, "ERROR: missing input file, see usage...\n");
		else
			break;
		argp_usage(state);
		rc = args->input_file ? INVALID_VAR_NAME : ARG_PARSE_FAIL;
		break;
	}

	if (rc)
		prlog(PR_ERR, "failed during argument parsing\n");

	return rc;
}

/*
 * handles argument parsing for write command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
 */
int guest_write_command(int argc, char *argv[])
{
	int rc;
	struct write_args args = { .help_flag = 0,
				   .input_valid = 0,
				   .path = NULL,
				   .input_file = NULL,
				   .variable_name = NULL };

	/* combine command and subcommand for usage/help messages */
	argv[0] = "secvarctl -m guest write";

	struct argp_option options[] = {
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "force", 'f', 0, 0, "force update, skips validation of file" },
		{ "path", 'p', "PATH", 0,
		  "looks for .../<var>/update file in PATH, default is " SECVARPATH },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = {
		options, parse_options, "<VARIABLE> <AUTH_FILE>",
		"This command updates a given secure variable with a new key contained in "
		"an auth file"
		" It is recommended that 'secvarctl verify' is tried on the update file "
		"before submitting."
		" This will ensure that the submission will be successful upon reboot."
		"\vvalues for <VARIABLE> = type one of guest secure boot variable name\n"
		"<AUTH_FILE> must be a properly generated authenticated variable file"
	};

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.help_flag)
		goto out;

	rc = write_variable((uint8_t *)args.variable_name, (uint8_t *)args.input_file,
			    (uint8_t *)args.path, args.input_valid);

out:
	if (!args.help_flag)
		printf("RESULT: %s\n", rc ? "FAILURE" : "SUCCESS");

	return rc;
}
