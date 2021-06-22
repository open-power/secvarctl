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
#include "external/skiboot/libstb/secvar/secvar.h" // for secvar struct


/* child parser for insert and removes child parser */
static struct argp_child gen_auth_specific_child_parsers[] = {
	{ &gen_auth_specific_argp, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP,
	  "Auth Generation Options", 7 },
	{ 0 }
};

/*An `insert` command must always accept a new ESL file but it can append it to either an ESL from
 *any of the following means of input:
 *      1. the default secvar sysfs path
 *      2. a user defined path to secvars
 *      3. a user given file
 *Additionally, the final signed auth w appended new ESL can be output to any of the above locations
 *The goal is to input and output ESLs with any combination of the above methods
 *Therefore, there are about 9 applications of the insert command
 */
static int insert_specific_parse_opt(int key, char *arg, struct argp_state *state);
/*A `remove` command works similary to the above `insert` command comment except the input is a serial number not an ESL */
static int remove_specific_parse_opt(int key, char *arg, struct argp_state *state);


/*the following enums are to keep track of the different applications of this command*/
enum output_method { NO_SELECTION = 0, SUBMIT_AS_SECVAR_UPDATE, WRITE_TO_FILE };
enum input_method { READ_FROM_SECVAR_PATH = 0, READ_FROM_FILE };

struct Arguments {
	// the optionalOutFile is used if output_method is WRITE_TO_FILE
	// the optionalInFile is used if input_method is READ_FROM_FILE
	// new_esl is used for `insert` and serial_number is used for `remove`
	int help_flag, inp_valid;
	enum output_method output_method;
	enum input_method input_method;
	const char *new_esl, *out_file, *current_esl, *path_to_sec_vars, *serial_number;
	struct Auth_specific_args auth_args;
};

/* shared options for both insert and remove command */
static struct argp_option insert_and_remove_shared_argp_options[] = {
	{ "verbose", 'v', 0, 0, "print more verbose process information" },
	{ "force", 'f', 0, 0,
	  "does not do prevalidation on the input file, assumes format is correct" },
	{ "esl", 'e', "FILE", 0,
	  "specify current ESL to append/remove data to, default is to <PATH>/<VAR_NAME>/data" },
	{ "path", 'p', "PATH", 0,
	  "specify path to current secvars, default is " SECVARPATH
	  " expects subdirectory <PATH>/<VAR_NAME> to exist" },
	//  since mandatory we use OPTION_NO_USAGE which means they appear in the help message but not usage
	{ 0, 'o', "FILE", OPTION_NO_USAGE,
	  "output file, output will be an auth file, either this or '-w' is required" },
	{ "write", 'w', 0, OPTION_NO_USAGE,
	  "if successful, submit output as secvar update, path to secvars is assigned with '-p'" },
	{ "help", '?', 0, 0, "Give this help list", 1 },
	{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
	{ 0 }
};

/**
 *shared parser for both insert and remove command, this parser also has a child parser that parses auth generation flags
 *@param key , every option that is parsed has a value to identify it
 *@param arg, if key is an option than arg will hold its value ex: -<key> <arg>
 *@param state,  argp_state struct that contains useful information about the current parsing state 
 *@return success or errno
 */
static int insert_and_remove_shared_parse_opt(int key, char *arg, struct argp_state *state)
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
	case ARGP_KEY_INIT:
		// for first loop around argp requires us to specify which data struct to use for child parsers
		// yes confusion, this child parser has a child parser
		state->child_inputs[0] = &(args->auth_args);
		break;
	case ARGP_KEY_SUCCESS:
		// check that all essential args are given and valid
		if (args->help_flag)
			break;
		else if (args->auth_args.time && validateTime(args->auth_args.time))
			prlog(PR_ERR,
			      "Invalid timestamp flag '-t YYYY-MM-DDThh:mm:ss' , see usage...\n");
		else if (args->auth_args.varName == NULL || isVariable(args->auth_args.varName))
			prlog(PR_ERR, "ERROR: Invalid variable name, see usage below\n");
		else if (strcmp(args->auth_args.varName, "TS") == 0)
			prlog(PR_ERR,
			      "ERROR: TS is not a valid secvar for editing, see usage below...\n");
		// not sure if dbx entries are all in one ESL or a chain of single entry ESL's
		// TODO
		// seriously come back to this, we are reading dbx's as one per ESL w/ many appended ESLs. is this true?
		else if (strlen(args->auth_args.varName) > 2 &&
			 strcmp(args->auth_args.varName, "dbx") == 0)
			prlog(PR_ERR,
			      "ERROR: insert/removing entries from dbx not implemented yet, see usage below...\n");
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

	return rc;
}

// very confusing, child parser has a child parser
// to summarize: `insert` shares flags w `remove` (ex: {-o, -w, -e, -f, -v, --help, --usage, all auth flags})
// and `generate auth` shares flags w `insert/remove`(ex: all auth flags {-t, -s , -c, -k})
static struct argp insert_and_remove_shared_argp = { insert_and_remove_shared_argp_options,
						     insert_and_remove_shared_parse_opt, 0, 0,
						     gen_auth_specific_child_parsers };

static struct argp_child insert_remove_shared_child_parsers[] = {
	{ &insert_and_remove_shared_argp, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, 0 },
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
	unsigned char *new_esl_buff = NULL, *current_esl_buff = NULL, *combined_esl_buff = NULL,
		      *out_buff = NULL;
	struct Arguments args = { .help_flag = 0,
				  .inp_valid = 0,
				  .output_method = NO_SELECTION,
				  .input_method = READ_FROM_SECVAR_PATH,
				  .new_esl = NULL,
				  .current_esl = NULL,
				  .path_to_sec_vars = NULL,
				  .serial_number = NULL,
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
		{ 0, 'i', "FILE", OPTION_NO_USAGE,
		  "required input file, constains new ESL to add to current ESL" },
		{ 0 }
	};

	struct argp argp = {
		options, insert_specific_parse_opt,
		"-n <var_name> -k/-s <key/sig> -c <crt> -i <new_esl> -o <out_file>\n-n <var_name> -k/-s <key/sig> -c <crt> -i <new_esl> -w",
		"This command appends an ESL to a current chain of ESL's and uses it to generate an valid Auth"
		" file. The generated Auth can be output to a file with '-o' or submited as a secvar update with '-w'."
		" The default location of secvars is " SECVARPATH ", use '-p' for other paths."
		" At the moment only files containing ESL's are acceptable as input. To generate an ESL, see 'secvarctl generate --help'. ",
		insert_remove_shared_child_parsers
	};

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.help_flag)
		goto out;

	/*fill in fields w/ default data*/

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
static int insert_specific_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct Arguments *args = state->input;
	int rc = SUCCESS;

	switch (key) {
	case 'i':
		args->new_esl = arg;
		break;
	case ARGP_KEY_INIT:
		// for first loop around argp requires us to specify which data struct to use for child parsers
		state->child_inputs[0] = args;
		break;
	case ARGP_KEY_SUCCESS:
		// check that all essential args are given and valid
		if (args->help_flag)
			break;
		else if (args->new_esl == NULL || isFile(args->new_esl))
			prlog(PR_ERR, "ERROR: Input file is invalid, see usage below...\n");
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

static int convert_ascii_hex_to_raw_hex(const char *ascii, unsigned char *raw, size_t raw_len)
{
	char *tmp_hex = NULL;
	char *end_ptr = NULL;
	char *ascii_cpy = NULL;
	
	ascii_cpy = malloc(strlen(ascii) + 1);
	if (!ascii_cpy) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	memcpy(ascii_cpy, ascii, strlen(ascii) + 1);
	for (int i = 0; i < raw_len; i++) {
		if (i == 0)
			tmp_hex = strtok(ascii_cpy, ":");
		else
			tmp_hex = strtok(NULL, ":");
		if (!tmp_hex || strlen(tmp_hex) != 2) {
			prlog(PR_ERR, "ERROR: Failed to parse given serial number %s, unparsed string segment = %s\n",
						ascii, ascii + (3*i) );
			free(ascii_cpy);
			return ARG_PARSE_FAIL;
		}
		raw[i] = (unsigned char) strtoul(tmp_hex, &end_ptr, 16);
		if (*end_ptr != '\0'){
			prlog(PR_ERR, "Parsing %s segment of serial %s failed\n", tmp_hex, ascii);
			free(ascii_cpy);
			return ARG_PARSE_FAIL;
		}
	}
	free(ascii_cpy);
	return SUCCESS;
}
// WHERE NICK LEFT OFF, NOT COMPILING, CHECK FORMAT OF RETURNED SERIAL NUMBER, CLEANUP RETURN CODE
/*
 *removes an ESL from a chain of ESLs and returns the ESL without the ESL containing the given serial number
 *@param esl_chain, pointer to chains of ESL buffer, esl's must contain x509s
 *@param chain_size, length of esl_chain in bytes
 *@param sn, pointer to serial number string, should be 20 bytes sperated by a colon, XX:...:XX
 *@param ret_esl, a pointer to already allocarted memory to fill with the new ESL chain w/o the matching esl 
 *@param ret_esl_size, size of the esl pointed to by ret_esl
 *@return SUCCESS if an ESL with the serial number exists, else errno.
 */
static int remove_esl_with_serial(unsigned char *esl_chain, size_t chain_size, const char *sn, unsigned char **ret_esl, size_t *ret_esl_size)
{
    size_t remaining_esl_size, offset = 0, serial_len;
    int rc, esl_data_size, itr_esl_size = 0, count = 1;
    unsigned char *esl_data = NULL, sn_raw[20];
    const unsigned char *itr_serial = NULL;
    EFI_SIGNATURE_LIST *itr_esl;
    crypto_x509 *x509 = NULL;
    bool found_flag = false;

    *ret_esl_size = 0;
    // convert ascii serial number string to raw buffer
    rc = convert_ascii_hex_to_raw_hex(sn, sn_raw, 20);
    if (rc)
    	return rc;
    // loop through esl chain, if SN matches, don't add it
    for (remaining_esl_size = chain_size; remaining_esl_size > 0; 
        remaining_esl_size -= itr_esl_size, offset += itr_esl_size, count++) {
        // get nex sig list size
        itr_esl = get_esl_signature_list((char *)esl_chain + offset, remaining_esl_size);
        if (itr_esl == NULL) {
            prlog(PR_ERR, "Failed to parse ESL #%d\n", count);
        }
        itr_esl_size = itr_esl->SignatureListSize;
        // buff to esl is basically type cast so this is our one sanity check
        if (itr_esl_size > remaining_esl_size) {
            prlog(PR_ERR, "ERROR: Expected size of ESL #%d is %d but only %lu bytes are available\n", count, itr_esl_size, remaining_esl_size);
            break;
        }
        // get data from esl
        esl_data_size = get_esl_cert((char *)esl_chain + offset, remaining_esl_size, (char **)&esl_data);
        if (esl_data_size <= 0) {
            prlog(PR_ERR, "\tERROR: Failed to extract certificate from ESL, no data\n");
            break;
        }
        // get x509 from data
        rc = parseX509(&x509, esl_data, (size_t)esl_data_size);
        if (rc)
            break;
        // get serial number from x509
        itr_serial = crypto_x509_get_serial_number(x509, &serial_len);
        if (verbose >= PR_INFO) {
        	prlog(PR_INFO,"Comparing serial against serial = ");
        	printHex((unsigned char *)itr_serial, serial_len);
        }
        // compare
        if (serial_len != 20) {
        	prlog(PR_ERR, "ERROR: Serial number has length %zd, expected 20\n", serial_len);
        	break;
        }
        //if not the ESL we want to remove,  add it to the new ESL
        if (memcmp(itr_serial, sn_raw, serial_len) != 0) {
        	memcpy(*ret_esl + *ret_esl_size, itr_esl, itr_esl_size);
        	*ret_esl_size += itr_esl_size;
        }
        else {
        	prlog(PR_INFO, "Found matching ESL. Removing now...\n");
        	found_flag = true;
        }
        free(esl_data);
        esl_data = NULL;
    	crypto_x509_free(x509);
    	x509 = NULL;
    }

    if (esl_data)
    	free(esl_data);
    if (x509)
    	crypto_x509_free(x509);
    
    if (found_flag)
    	return SUCCESS;

    return ESL_FAIL;

}
// WHEERE NICK LEFT OFF, I THINK ITS WORKING KINDA. IF REMOVE THE ONLY ESL THEN RETURNED IS 0 BYTES DO THE RIGHT THING W THAT! 
// I DIDNT GE TTO GENERATE NOTHIN SO TEST THAT

/*
 *called from main()
 *handles argument parsing for remove command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number
 */
int performRemoveCommand(int argc, char *argv[])
{
	int rc;
	size_t out_buff_size, curr_esl_size, updated_esl_size;
	unsigned char *current_esl_buff = NULL, *updated_esl_buf = NULL, *out_buff = NULL;
	struct Arguments args = { .help_flag = 0,
				  .inp_valid = 0,
				  .output_method = NO_SELECTION,
				  .input_method = READ_FROM_SECVAR_PATH,
				  .new_esl = NULL,
				  .current_esl = NULL,
				  .path_to_sec_vars = NULL,
				  .serial_number = NULL,
				  .auth_args = { .signKeyCount = 0,
						 .signCertCount = 0,
						 .signCerts = NULL,
						 .signKeys = NULL,
						 .varName = NULL,
						 .time = NULL,
						 .pkcs7_gen_meth = NO_PKCS7_GEN_METHOD } };
	// combine command and subcommand for usage/help messages
	argv[0] = "secvarctl remove";
	struct argp_option options[] = {
		{ "serialnum", 'x', "XX:XX...:XX", OPTION_NO_USAGE,
		  "required serial number contained in X509 of ESL that is to be removed. "
          "Must be 20 bytes, capitalized hex with each byte separated with ':'. Use "
          "`secvarctl read` or `secvarctl validate -v -e` for correct SN format" },
		{ 0 }
	};

	struct argp argp = {
		options, remove_specific_parse_opt,
		"-n <var_name> -k/-s <key/sig> -c <crt> -x <XX:XX..:XX> -o <out_file>\n-n <var_name> -k/-s <key/sig> -c <crt> -x <XX:XX..:XX> -w",
		"This command removes an ESL from a current chain of ESL's and uses it to generate an valid Auth"
		" file. The generated Auth can be output to a file with '-o' or submited as a secvar update with '-w'."
		" The default location of secvars is " SECVARPATH ", use '-p' for other paths."
		" At the moment only ESl's containing X509s can be removed. To see an x509 serial number contained in ESLs, see 'secvarctl read/validate --help'. ",
		insert_remove_shared_child_parsers
	};

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.help_flag)
		goto out;

	/*fill in fields w/ default data*/

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
	prlog(PR_INFO, "Looking for ESL containing X509 with Serial Number %s in", args.serial_number);
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
	// 1. get current esl from either getsecvar or read file
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

    // max size of new esl is current esl
    updated_esl_buf = malloc(curr_esl_size);
    if (updated_esl_buf == NULL) {
        prlog(PR_ERR, "ERROR: Failed to allocate memory\n");
        goto out;
    }
    // 2. remove esl with serial number
    rc = remove_esl_with_serial(current_esl_buff, curr_esl_size, args.serial_number, &updated_esl_buf, &updated_esl_size);
    if (rc) {
        prlog(PR_ERR, "ERROR: Could not find ESL with serial number %s in ESL chain\n", args.serial_number);
        goto out;
    }
	if (args.inp_valid)
		prlog(PR_INFO,
		      "Generated ESL with %lu bytes, skipping validation ('-f' flag detected)\n",
		      updated_esl_size);
	else {
		prlog(PR_INFO, "Validating updated ESL of %lu bytes...\n", updated_esl_size);
		// empty ESL is valid but cannot be validated
		if (updated_esl_size != 0) {
			rc = validateESL(updated_esl_buf, updated_esl_size, args.auth_args.varName);
			if (rc) {
				prlog(PR_ERR,
				      "ERROR: Failed to generate a valid ESL\n");
				goto out;
			}
		}
		prlog(PR_INFO, "Validating new  appended ESL successfull\n");
	}
	// 5. generate auth
	rc = toAuth(updated_esl_buf, updated_esl_size, &(args.auth_args), 42, &out_buff,
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
	if (out_buff)
		free(out_buff);
	if (current_esl_buff)
		free(current_esl_buff);
	if (updated_esl_buf)
		free(updated_esl_buf);
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
static int remove_specific_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct Arguments *args = state->input;
    int rc = SUCCESS;

    switch (key) {
    case 'x':
        args->serial_number = arg;
        break;
    case ARGP_KEY_INIT:
        // for first loop around argp requires us to specify which data struct to use for child parsers
        state->child_inputs[0] = args;
        break;
    case ARGP_KEY_SUCCESS:
        // check that all essential args are given and valid
        if (args->help_flag)
            break;
        // serial number must be 20 hex bytes, all caps, each byte seperated by ':' = 20*2 + 19
        else if (args->serial_number == NULL)
             prlog(PR_ERR, "ERROR: Missing serial number of ESL to remove, use '-x <XX:XX..:XX> `, see usage below...\n");
        else if (strlen(args->serial_number) != 59)
            prlog(PR_ERR, "ERROR: Input serial number format is invalid, needs 20 hex bytes seprated by ':' (59 chars total, found %lu)  see usage below...\n", strlen(args->serial_number));
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