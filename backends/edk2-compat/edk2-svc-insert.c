/* Copyright 2021 IBM Corp.*/
#ifndef NO_CRYPTO
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define __USE_XOPEN // needed for strptime
#include <time.h> // for timestamp
#include <ctype.h> // for isspace
#include <argp.h>
#include "libstb/secvar/crypto/crypto.h"
#include "backends/edk2-compat/include/edk2-svc.h"

/*An `insert` command must always accept a new ESL file but it can append it to either an ESL from
 *any of the following means of input:
 *      1. the default secvar sysfs path
 *      2. a user defined path to secvars
 *      3. a user given file
 *Additionally, the final signed auth w appended new ESL can be output to any of the above locations
 *The goal is to input and output ESLs with any combination of the above methods
 *Therefore, there are about 9 applications of the insert command
 */
static int parse_opt(int key, char *arg, struct argp_state *state);

/*the following enums are to keep track of the different applications of this command*/
enum output_method { NO_SELECTION = 0, SUBMIT_AS_SECVAR_UPDATE, WRITE_TO_FILE };
enum input_method { READ_FROM_SECVAR_PATH = 0, READ_FROM_FILE };

struct Arguments {
	// the optionalOutFile is used if output_method is WRITE_TO_FILE
	// the optionalInFile is used if input_method is READ_FROM_FILE
	int help_flag, inp_valid;
	enum output_method output_method;
	enum input_method input_method;
	const char *new_esl, *out_file, *current_esl, *hash_alg, *path_to_sec_vars;
	struct Auth_specific_args auth_args;
};
static struct argp_child gen_auth_specific_child_parsers[] = {
	{ &gen_auth_specific_argp, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP,
	  "Auth Generation Options", 7 },
	{ 0 }
};

/*
 *called from main()
 *handles argument parsing for insert command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int performInsertCommand(int argc, char *argv[])
{
	int rc;
	size_t out_buff_size, new_esl_size, curr_esl_size, combined_esl_size;
	struct hash_funct *hash_function;
	unsigned char *new_esl_buff = NULL, *current_esl_buff = NULL, *combined_esl_buff = NULL,
		      *out_buff = NULL;
	struct Arguments args = { .help_flag = 0,
				  .inp_valid = 0,
				  .output_method = NO_SELECTION,
				  .input_method = READ_FROM_SECVAR_PATH,
				  .new_esl = NULL,
				  .current_esl = NULL,
				  .hash_alg = NULL,
				  .path_to_sec_vars = NULL,
				  .auth_args = { .signKeyCount = 0,
						 .signCertCount = 0,
						 .signCerts = NULL,
						 .signKeys = NULL,
						 .varName = NULL,
						 .time = NULL,
						 .pkcs7_gen_meth = NO_PKCS7_GEN_METHOD } };
	// combine command and subcommand for usage/help messages
	argv[0] = "secvarctl insert";

	struct argp_option options[] = {
		{ "alg", 'h', "HASH_ALG", 0,
		  "hash function, use when validating input ESL for dbx"
		  " currently accepted values: {'SHA256', 'SHA224', 'SHA1', 'SHA384', 'SHA512'}, Default is 'SHA256'" },
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "force", 'f', 0, 0,
		  "does not do prevalidation on the input file, assumes format is correct" },
		{ "esl", 'e', "FILE", 0,
		  "specify current ESL to append data to, default is to <PATH>/<VAR_NAME>/data" },
		{ "path", 'p', "PATH", 0,
		  "specify path to current secvars, default is " SECVARPATH
		  " expects subdirectory <PATH>/<VAR_NAME> to exist" },
		// these are hidden because they are mandatory and are described in the help message instead of in the options
		{ 0, 'i', "FILE", OPTION_HIDDEN, "input ESL file to add to current ESL" },
		{ 0, 'o', "FILE", OPTION_HIDDEN, "output file" },
		{ 0, 'w', 0, OPTION_HIDDEN, "write to secvars" },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = {
		options, parse_opt,
		"-n <var_name> -k/-s <key/sig> -c <crt> -i <new_esl> -o <out_file>\n-n <var_name> -k/-s <key/sig> -c <crt> -i <new_esl> -w",
		"This command appends an ESL to a current chain of ESL's and uses it to generate an valid Auth"
		" file. The generated Auth can be output to a file with '-o' or submited as a secvar update with '-w'."
		" The default location of secvars is " SECVARPATH ", use '-p' for other paths."
		" At the moment only files containing ESL's are acceptable as input. To generate an ESL, see 'secvarctl generate --help'. ",
		gen_auth_specific_child_parsers

	};

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.help_flag)
		goto out;

	/*fill in fields w/ default data*/

	if (strcmp(args.auth_args.varName, "dbx") == 0) {
		// default alg is sha256
		if (args.hash_alg == NULL)
			args.hash_alg = "SHA256";
		// get hash function
		rc = getHashFunction(args.hash_alg, &hash_function);
		if (rc)
			goto out;
	}
	if (args.auth_args.time == NULL) {
		args.auth_args.time = calloc(1, sizeof(*args.auth_args.time));
		if (!args.auth_args.time) {
			prlog(PR_ERR, "ERROR: failed to allocate memory\n");
			rc = ALLOC_FAIL;
			goto out;
		}
		rc = getTimestamp(args.auth_args.time);
		if (rc)
			goto out;
	}
	// if no custom path to secvars, use default
	if (args.path_to_sec_vars == NULL)
		args.path_to_sec_vars = SECVARPATH;

	// generate helpful info string
	prlog(PR_INFO, "New ESL %s, being appended to ", args.new_esl);
	if (args.input_method == READ_FROM_SECVAR_PATH)
		prlog(PR_INFO, "%s%s/data", args.path_to_sec_vars, args.auth_args.varName);
	else
		prlog(PR_INFO, "%s", args.current_esl);
	prlog(PR_INFO, ", will be output to ");
	if (args.output_method == SUBMIT_AS_SECVAR_UPDATE)
		prlog(PR_INFO, "%s%s/update\n", args.path_to_sec_vars, args.auth_args.varName);
	else
		prlog(PR_INFO, "%s\n", args.out_file);

	//arg parsing, debug printing is done, now start process
	// 1. get new ESL
	new_esl_buff = (unsigned char *)getDataFromFile(args.new_esl, SIZE_MAX, &new_esl_size);
	if (new_esl_buff == NULL) {
		rc = INVALID_FILE;
		goto out;
	}
	if (!args.inp_valid) {
		prlog(PR_INFO, "Validating new ESL...\n");
		rc = validateESL(new_esl_buff, new_esl_size, args.auth_args.varName);
		if (rc) {
			prlog(PR_ERR, "ERROR: Could not validate new ESL\n");
			goto out;
		}
	}
	// 2. get current esl from either getsecvar or read file
	if (args.input_method == READ_FROM_SECVAR_PATH)
		rc = getDataFromSecVar((char **)&current_esl_buff, &curr_esl_size,
				       args.path_to_sec_vars, args.auth_args.varName);
	else {
		current_esl_buff =
			(unsigned char *)getDataFromFile(args.current_esl, SIZE_MAX, &curr_esl_size);
		if (current_esl_buff == NULL)
			rc = INVALID_FILE;
	}
	if (rc) {
		prlog(PR_ERR, "ERROR: Could not get current ESL\n");
		goto out;
	}
	if (!args.inp_valid) {
		prlog(PR_INFO, "Validating current ESL...\n");
		rc = validateESL(current_esl_buff, curr_esl_size, args.auth_args.varName);
		if (rc) {
			prlog(PR_ERR, "ERROR: Could not validate current ESL\n");
			goto out;
		}
	}
	// 4. append the twos
	combined_esl_size = curr_esl_size + new_esl_size;
	combined_esl_buff = malloc(combined_esl_size);
	if (!combined_esl_buff) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = ALLOC_FAIL;
		goto out;
	}
	prlog(PR_INFO, "Copying %lu bytes from current esl...\n", curr_esl_size);
	memcpy(combined_esl_buff, current_esl_buff, curr_esl_size);
	prlog(PR_INFO, "Copying %lu bytes from new esl...\n", new_esl_size);
	memcpy(combined_esl_buff + curr_esl_size, new_esl_buff, new_esl_size);
	if (args.inp_valid)
		prlog(PR_INFO,
		      "Generated ESL with %lu bytes, skipping validation ('-f' flag detected)\n",
		      combined_esl_size);
	else {
		prlog(PR_INFO, "Validating new appended ESL of %lu bytes...\n", combined_esl_size);
		rc = validateESL(combined_esl_buff, combined_esl_size, args.auth_args.varName);
		if (rc) {
			prlog(PR_ERR,
			      "ERROR: Failed to generate a valid ESL by appending current and new ESLs\n");
			goto out;
		}
		prlog(PR_INFO, "Validating new  appended ESL successfull\n");
	}
	// 5. generate auth
	rc = toAuth(combined_esl_buff, combined_esl_size, &(args.auth_args), 42, &out_buff,
		    &out_buff_size);
	if (rc) {
		prlog(PR_ERR, "Failed to generate auth file with new appended ESL\n");
		goto out;
	}
	prlog(PR_INFO, "Auth generation successful\n");
	// 6. write file or write to secvars
	if (args.output_method == SUBMIT_AS_SECVAR_UPDATE) {
		prlog(PR_INFO, "Submitting secvar update...\n");
		rc = updateVar(args.path_to_sec_vars, args.auth_args.varName, out_buff,
			       out_buff_size);
		if (rc)
			prlog(PR_ERR, "Failed to submit as secvar update\n");
	} else if (args.output_method == WRITE_TO_FILE) {
		prlog(PR_INFO, "Writing to file %s...\n", args.out_file);
		rc = createFile(args.out_file, (char *)out_buff, out_buff_size);
		if (rc) {
			prlog(PR_ERR, "ERROR: Could not write new data to output file %s\n",
			      args.out_file);
		}
	}

out:
	if (new_esl_buff)
		free(new_esl_buff);
	if (out_buff)
		free(out_buff);
	if (current_esl_buff)
		free(current_esl_buff);
	if (combined_esl_buff)
		free(combined_esl_buff);
	if (args.auth_args.signKeys)
		free(args.auth_args.signKeys);
	if (args.auth_args.signCerts)
		free(args.auth_args.signCerts);
	if (args.auth_args.time)
		free(args.auth_args.time);
	if (!args.help_flag)
		printf("RESULT: %s\n", rc ? "FAILURE" : "SUCCESS");

	return rc;
}

/**
 *@param key , every option that is parsed has a value to identify it
 *@param arg, if key is an option than arg will hold its value ex: -<key> <arg>
 *@param state,  argp_state struct that contains useful information about the current parsing state 
 *@return success or errno
 */
static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct Arguments *args = state->input;
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
	case 'f':
		args->inp_valid = 1;
		break;
	case 'v':
		verbose = PR_DEBUG;
		break;
	case 'i':
		args->new_esl = arg;
		break;
	case 'o':
		args->output_method = WRITE_TO_FILE;
		args->out_file = arg;
		break;
	case 'w':
		args->output_method = SUBMIT_AS_SECVAR_UPDATE;
		break;
	case 'e':
		args->input_method = READ_FROM_FILE;
		args->current_esl = arg;
		break;
	case 'p':
		args->path_to_sec_vars = arg;
		break;
	case 'h':
		args->hash_alg = arg;
		break;
	case ARGP_KEY_INIT:
		// for first loop around argp requires us to specify which data struct to use for child parsers
		state->child_inputs[0] = &(args->auth_args);
		break;
	case ARGP_KEY_SUCCESS:
		// check that all essential args are given and valid
		if (args->help_flag)
			break;
		else if (args->auth_args.time && validateTime(args->auth_args.time))
			prlog(PR_ERR,
			      "Invalid timestamp flag '-t YYYY-MM-DDThh:mm:ss' , see usage...\n");
		else if (args->new_esl == NULL || isFile(args->new_esl))
			prlog(PR_ERR, "ERROR: Input file is invalid, see usage below...\n");
		else if (args->auth_args.varName == NULL || isVariable(args->auth_args.varName) ||
			 strcmp(args->auth_args.varName, "TS") == 0)
			prlog(PR_ERR, "ERROR: Invalid variable name, see usage below\n");
		else if (args->output_method == NO_SELECTION)
			prlog(PR_ERR,
			      "ERROR: No output selction given, use either '-w' or ''-o', see usage below...\n");
		else if (args->auth_args.signCertCount == 0)
			prlog(PR_ERR,
			      "ERROR: At least one certificate needed, use '-c', see usage below...\n");
		else if (args->auth_args.signKeyCount == 0)
			prlog(PR_ERR,
			      "ERROR: At least one private key/signature needed, use '-k'/'-s', see usage below...\n");
		//each signer needs a certificate
		else if (args->auth_args.signCertCount != args->auth_args.signKeyCount)
			prlog(PR_ERR,
			      "ERROR: Number of certificates does not equal number of %s files, %d != %d, see usage below...\n",
			      args->auth_args.pkcs7_gen_meth == W_EXTERNAL_GEN_SIG ? "signature" :
											   "private key",
			      args->auth_args.signCertCount, args->auth_args.signKeyCount);
		else
			break;
		argp_usage(state);
		rc = ARG_PARSE_FAIL;
		break;
	}

	if (rc)
		prlog(PR_ERR, "Failed during argument parsing\n");

	return rc;
}
#endif