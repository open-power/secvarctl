/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#ifdef SECVAR_CRYPTO_WRITE_FUNC
#include <string.h>
#include <argp.h>
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "common/util.h"
#include "common/validate.h"
#include "common/generate.h"
#include "guest_svc_backend.h"

/*
 * check it whether given variable is PK or KEK
 */
static bool is_global_variable(const char *variable_name)
{
	return !strcmp(variable_name, PK_VARIABLE) || !strcmp(variable_name, KEK_VARIABLE);
}

/*
 * check it whether given variable is SBAT
 */
static bool is_sbat_variable(const char *variable_name)
{
	return !strcmp(variable_name, SBAT_VARIABLE);
}

/*
 * does prevalidation on input info, then given all the input information it should generate
 * an esl file and its size and return a SUCCESS or negative number (ERROR)
 *
 * @param buffer, data to be added to ESL, it must be of the same type as specified by inform
 * @param buffer_size , length of buff
 * @param args, struct of input info
 * @param hash_funct, index of hash function information to use for ESL GUID,
 *                   also helps in prevalation, if inform is '[c]ert' then this doesn't matter
 * @param out_buffer, the resulting ESL File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 * @param out_buffer_size, the length of out_buffer
 * @return SUCCESS or err number
 */
static int generate_esl(const uint8_t *buffer, size_t buffer_size, struct generate_args *args,
			enum signature_type hash_funct, uint8_t **out_buffer,
			size_t *out_buffer_size)
{
	int rc = SUCCESS;
	uuid_t const *esl_guid = &PKS_CERT_X509_GUID;
	uint8_t hash_data[64] = { 0 }, *cert_data = NULL, *data = (uint8_t *)buffer;
	size_t hash_data_size = 0, cert_data_size = 0, data_size = buffer_size;

	switch (args->input_form[0]) {
	case 'r':
		esl_guid = &PKS_CERT_DELETE_GUID;
		break;
	case 'f':
		if (is_global_variable(args->variable_name)) {
			prlog(PR_ERR,
			      "ERROR: PK and KEK are not allowed to generate hash from file\n");
			return INVALID_VAR_NAME;
		} else if (is_sbat_variable(args->variable_name)) {
			if (!validate_sbat(buffer, buffer_size)) {
				prlog(PR_ERR, "ERROR: invalid SBAT file\n");
				return INVALID_SBAT;
			}

			esl_guid = &PKS_CERT_SBAT_GUID;
			break;
		}

		rc = get_hash_data(buffer, buffer_size, hash_funct, args->variable_name, hash_data,
				   &hash_data_size);
		if (rc != SUCCESS) {
			prlog(PR_ERR, "ERROR: failed to generate hash from file\n");
			break;
		}

		data = hash_data;
		data_size = hash_data_size;
		/* intentionally flow into hash validation */
	case 'h':
		if (!args->input_valid) {
			rc = validate_hash_alg(data_size, hash_funct);
			if (rc != SV_SUCCESS) {
				prlog(PR_ERR, "ERROR: failed to validate input hash data\n");
				break;
			}
		}

		esl_guid = get_uuid(hash_funct);
		break;
	case 'c':
		rc = is_x509certificate(buffer, buffer_size, &cert_data, &cert_data_size,
					is_trustedcadb_variable(args->variable_name));
		if (rc != SUCCESS) {
			prlog(PR_ERR, "ERROR: could not validate certificate\n");
			break;
		}

		esl_guid = &PKS_CERT_X509_GUID;
		/* new input is the der */
		data = cert_data;
		data_size = cert_data_size;
		break;
	case 'a':
		if (!args->input_valid) {
			rc = validate_auth(data, data_size);
			if (rc != SUCCESS) {
				prlog(PR_ERR, "ERROR: could not validate signed auth file\n");
				break;
			}
			data += APPEND_HEADER_LEN;
			data_size -= APPEND_HEADER_LEN;
		}
		break;
	default:
		prlog(PR_ERR,
		      "ERROR: unknown input format %s for generating an ESL,"
		      " use `--help` for more info\n",
		      args->input_form);
		rc = ARG_PARSE_FAIL;
	}

	if (rc != SUCCESS) {
		prlog(PR_ERR, "ERROR: failed to validate input format\n");
		goto out;
	}
	/* if input file is auth than extract it */
	if (args->input_form[0] == 'a')
		rc = extract_esl_from_auth(data, data_size, out_buffer, out_buffer_size);
	else
		/* now we have either a hash or x509 in der and is ready to be put into an ESL */
		rc = create_esl(data, data_size, *esl_guid, out_buffer, out_buffer_size);
	if (rc != SUCCESS) {
		prlog(PR_ERR, "ERROR: failed to generate ESL file\n");
		goto out;
	}

out:
	if (cert_data != NULL)
		free(cert_data);

	return rc;
}

/*
 * does prevalidation on input info, then given all the input information it should generate
 * hashed data and its size and return a SUCCESS or negative number (ERROR)
 *
 * @param data, data to be hashed, it must be of the same type as specified by inform
 * @param data_size , length of buff
 * @param args, struct containing important command line info
 * @param hash_funct, index of hash function information to use as hash algorithm
 * @param hash, the resulting hash, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 * @param hash_size, the length of outHash
 * @return SUCCESS or err number
 */
static int generate_sha256_hash(const uint8_t *data, size_t data_size, struct generate_args *args,
				enum signature_type alg, uint8_t **hash, size_t *hash_size)
{
	int rc;

	/*  if the input is not declared valid then we validate it is the same as inForm format */
	if (!args->input_valid) {
		switch (args->input_form[0]) {
		case 'f':
			rc = SUCCESS;
			break;
		case 'c':
			rc = validate_cert(data, data_size,
					   is_trustedcadb_variable(args->variable_name));
			break;
		case 'e':
			rc = validate_esl(data, data_size);
			break;
		case 'p':
			rc = validate_pkcs7(data, data_size);
			break;
		case 'a':
			rc = validate_auth(data, data_size);
			data += APPEND_HEADER_LEN;
			data_size -= APPEND_HEADER_LEN;
			break;
		default:
			prlog(PR_ERR,
			      "ERROR: unknown input format %s for generating a hash,"
			      " use `--help` for more info\n",
			      args->input_form);
			rc = ARG_PARSE_FAIL;
		}

		if (rc) {
			prlog(PR_ERR, "failed to validate input format of input file when "
				      "generating hash, "
				      "try again with -f to skip format validation of input\n");
			return rc;
		}
	}

	rc = crypto_md_generate_hash(data, data_size, get_crypto_alg_id(alg), hash, hash_size);
	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_ERR, "failed to generate hash, rc %d\n", rc);
		return HASH_FAIL;
	}

	return validate_hash_alg(*hash_size, alg);
}

/*
 * does prevalidation on input info, then given all the input information it should generate
 * an auth or PKCS7 (depending on args->output_form)
 * file and its size and return a SUCCESS or negative number (ERROR)
 *
 * @param buffer, data to be added to auth or PKCS7, it must be of the same type as specified by inform
 * @param buffer_size , length of buff
 * @param args, struct containing command line info and lots of other important information
 * @param hash_funct, index of hash function information to use for signing (see above for format)
 * @param out_buffer, the resulting auth or PKCS7 File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 * @param out_buffer_size, the length of out_buffer
 * @return SUCCESS or err number
 */
static int generate_authorpkcs7(const uint8_t *buffer, size_t buffer_size,
				struct generate_args *args, const enum signature_type hash_funct,
				uint8_t **out_buffer, size_t *out_buffer_size)
{
	int rc = SUCCESS;
	size_t intermediate_buffer_size, input_size = buffer_size;
	uint8_t *intermediate_buffer = NULL, **input_ptr;
	uint16_t *var_name = NULL;
	uuid_t *guid;

	input_ptr = (unsigned char **)&buffer;

	switch (args->input_form[0]) {
	case 'r':
		/* if creating a reset key, ensure input is NULL and size of zero */
		if (input_size != 0 && *input_ptr != NULL) {
			prlog(PR_ERR, "ERROR: input data must be empty for generation of "
				      "reset file\n");
			rc = INVALID_FILE;
			break;
		} else if (strcmp(PK_VARIABLE, args->variable_name) == 0) {
			buffer = (const uint8_t *)WIPE_SB_MAGIC;
			buffer_size = strlen(WIPE_SB_MAGIC);
		} else
			break;
	case 'f': /* intentional flow */
	case 'h': /* intentional flow */
	case 'c':
		rc = generate_esl(buffer, buffer_size, args, hash_funct, &intermediate_buffer,
				  &intermediate_buffer_size);
		if (rc != SUCCESS) {
			break;
		}
		input_ptr = &intermediate_buffer;
		input_size = intermediate_buffer_size;
		/* intentionaly flow into ESL validation */
	case 'e':
		/* if data is known to be valid than do not validate */
		if (!args->input_valid) {
			rc = validate_esl(*input_ptr, input_size);
			if (rc != SV_SUCCESS) {
				prlog(PR_ERR, "ERROR: could not validate ESL File\n");
				break;
			}
		}
		break;
	default:
		prlog(PR_ERR, "ERROR: unknown input format %s for generating %s file.\n",
		      args->input_form, (args->output_form[0] == 'a' ? "an Auth" : "a PKCS7"));
		rc = ARG_PARSE_FAIL;
	}

	if (rc != SUCCESS) {
		prlog(PR_ERR, "ERROR: failed to validate input format\n");
		goto out;
	}

	var_name = (uint16_t *)get_wide_character(args->variable_name, strlen(args->variable_name));
	if (var_name == NULL) {
		rc = ALLOC_FAIL;
		goto out;
	}

	guid = get_guid(var_name);

	if (args->output_form[0] == 'a')
		rc = create_auth_msg(*input_ptr, input_size, args, *guid, out_buffer,
				     out_buffer_size);
	else if (args->output_form[0] == 'x')
		rc = create_presigned_hash(*input_ptr, input_size, args, *guid, out_buffer,
					   out_buffer_size);
	else
		rc = create_pkcs7(*input_ptr, input_size, args, *guid, out_buffer, out_buffer_size);

	if (rc != SUCCESS) {
		prlog(PR_ERR, "ERROR: failed to generate %s file, use `--help` for more info\n",
		      args->output_form[0] == 'a' ? "Auth" :
		      args->output_form[0] == 'x' ? "pre-signed hash" :
						    "PKCS7");
		goto out;
	}

out:
	if (var_name != NULL)
		free(var_name);

	if (intermediate_buffer != NULL)
		free(intermediate_buffer);

	return rc;
}

/*
 * after parsing argument information and getting input data, this will return
 * the generated output data given the output format
 *
 * @param buffer, inut data, it must be of the same type as specified by inform
 * @param buffer_size , length of buff
 * @param args, struct containing lots of input info
 * @param hash_funct, array of hash function information to use if hashing
 * @param out_buffer, the resultinggenerated File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 * @param out_buffer_size, the length of out_buffer
 * @return SUCCESS or err number
 */
static int generate_data(const uint8_t *buffer, size_t buffer_size, struct generate_args *args,
			 enum signature_type hash_function, uint8_t **out_buffer,
			 size_t *out_buffer_size)
{
	int rc = SUCCESS;

	/* once here it is time to plan the course of action depending on the output type desired */
	switch (args->output_form[0]) {
	case 'c':
		rc = CERT_FAIL; /* cannot generate a cert */
		break;
	case 'h':
		if (is_global_variable(args->variable_name)) {
			prlog(PR_ERR, "ERROR: PK and KEK are not allowed to generate hash\n");
			return INVALID_VAR_NAME;
		}
		rc = generate_sha256_hash(buffer, buffer_size, args, hash_function, out_buffer,
					  out_buffer_size);
		break;
	case 'x': /* intentional flow */
	case 'a': /* intentional flow into pkcs7 */
	case 'p':
		/* if no time is given then get curent time */
		if (!args->time) {
			args->time = calloc(1, sizeof(*args->time));
			if (!args->time) {
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				rc = ALLOC_FAIL;
				break;
			}

			rc = get_timestamp(args->time);
			if (rc)
				break;
		}

		rc = generate_authorpkcs7(buffer, buffer_size, args, hash_function, out_buffer,
					  out_buffer_size);
		break;
	case 'e':
		rc = generate_esl(buffer, buffer_size, args, hash_function, out_buffer,
				  out_buffer_size);
		break;
	default:
		prlog(PR_ERR, "ERROR: unknown output format %s, use `--help` for more info\n",
		      args->output_form);
		rc = ARG_PARSE_FAIL;
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
	struct generate_args *args = state->input;
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
	case 'k':
		/* if already storing signed data, then don't allow for private keys */
		if (args->pkcs7_gen_method == W_EXTERNAL_GEN_SIG) {
			prlog(PR_ERR, "ERROR: cannot have both signed data files and "
				      "private keys for signing\n");
			rc = ARG_PARSE_FAIL;
			break;
		}

		args->pkcs7_gen_method = W_PRIVATE_KEYS;
		args->sign_key_count++;
		rc = realloc_array((void **)&args->sign_keys, args->sign_key_count,
				   sizeof(*args->sign_keys));
		if (rc) {
			prlog(PR_ERR, "Failed to realloc private key (-k <>) array\n");
			break;
		}
		args->sign_keys[args->sign_key_count - 1] = arg;
		break;
	case 'c':
		args->sign_cert_count++;
		rc = realloc_array((void **)&args->sign_certs, args->sign_cert_count,
				   sizeof(*args->sign_certs));
		if (rc) {
			prlog(PR_ERR, "Failed to realloc certificate (-c <>) array\n");
			break;
		}
		args->sign_certs[args->sign_cert_count - 1] = arg;
		break;
	case 'f':
		args->input_valid = 1;
		break;
	case 'v':
		verbose = PR_DEBUG;
		break;
	case 's':
		/* if already storing private keys, then don't allow for signed data */
		if (args->pkcs7_gen_method == W_PRIVATE_KEYS) {
			prlog(PR_ERR, "ERROR: cannot have both signed data files and "
				      "private keys for signing");
			rc = ARG_PARSE_FAIL;
			break;
		}
		args->pkcs7_gen_method = W_EXTERNAL_GEN_SIG;
		args->sign_key_count++;
		rc = realloc_array((void **)&args->sign_keys, args->sign_key_count,
				   sizeof(*args->sign_keys));
		if (rc) {
			prlog(PR_ERR, "failed to realloc signature (-s <>) array\n");
			break;
		}
		args->sign_keys[args->sign_key_count - 1] = arg;
		break;
	case 'i':
		args->input_file = arg;
		break;
	case 'o':
		args->output_file = arg;
		break;
	case 'h':
		args->hash_alg = arg;
		break;
	case 'n':
		args->variable_name = arg;
		if (args->variable_name != NULL && !is_secure_boot_variable(args->variable_name))
			prlog(PR_WARNING, "WARNING!! %s is an arbitrary variable name\n",
			      args->variable_name);
		break;
	case 't':
		args->time = calloc(1, sizeof(*args->time));
		if (!args->time) {
			prlog(PR_ERR, "ERROR: failed to allocate memory\n");
			rc = ALLOC_FAIL;
			break;
		}
		if (parse_custom_timestamp(args->time, arg)) {
			prlog(PR_ERR,
			      "ERROR: could not parse given timestamp %s, make sure it is in"
			      " format YYYY-MM-DDThh:mm:ss\n",
			      arg);
			rc = ARG_PARSE_FAIL;
		}
		break;
	case 'a':
		args->append_flag = 1;
		break;
	case ARGP_KEY_ARG:
		/* check if reset key is desired */
		if (!strcmp(arg, "reset")) {
			args->input_form = "reset";
			args->input_file = "empty";
			args->output_form = "auth";
			break;
		}
		/* else set input and output formats */
		args->input_form = strtok(arg, ":");
		args->output_form = strtok(NULL, ":");
		break;
	case ARGP_KEY_SUCCESS:
		/* check that all essential args are given and valid */
		if (args->help_flag)
			break;
		else if (args->input_form == NULL || args->output_form == NULL)
			prlog(PR_ERR, "ERROR: incorrect '<input_format>:<output_format>', see "
				      "usage...\n");
		else if (args->time && validate_time(args->time))
			prlog(PR_ERR, "invalid timestamp flag '-t YYYY-MM-DDThh:mm:ss' , "
				      "see usage...\n");
		else if (args->input_form[0] != 'r' &&
			 (args->input_file == NULL || is_file(args->input_file)))
			prlog(PR_ERR, "ERROR: input file is invalid, see usage below...\n");
		else if (args->variable_name == NULL)
			prlog(PR_ERR,
			      "ERROR: no secure variable name given... use -n <variable_name> "
			      "option\n");
		else if (args->output_file == NULL)
			prlog(PR_ERR, "ERROR: no output file given, see usage below...\n");
		else
			break;
		argp_usage(state);
		rc = ARG_PARSE_FAIL;
		break;
	}

	if (rc)
		prlog(PR_ERR, "failed during argument parsing\n");

	// Special case, filter out appends on PK
	if (args->append_flag > 0 && strcmp(PK_VARIABLE, args->variable_name) == 0) {
		prlog(PR_ERR, "ERROR: PK does not support the append flag\n");
		rc = ARG_PARSE_FAIL;
	}

	return rc;
}

/*
 * called from main()
 * handles argument parsing for generate command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
 */
int guest_generate_command(int argc, char *argv[])
{
	int rc = 0;
	size_t out_buffer_size = 0, size = 0;
	enum signature_type hash_function;
	unsigned char *buffer = NULL, *out_buffer = NULL;
	struct generate_args args = { 0 };

	memset(&args, 0x00, sizeof(struct generate_args));
	args.append_flag = 0;
	args.pkcs7_gen_method = NO_PKCS7_GEN_METHOD;

	/* combine command and subcommand for usage/help messages */
	argv[0] = "secvarctl -m guest generate";

	struct argp_option options[] = {
		{ "var", 'n', "VAR_NAME", 0,
		  "name of a secure boot variable, used when generating an PKCS7/Auth file." },
		{ "alg", 'h', "HASH_ALG", 0,
		  "hash function, use when '[h]ash' is input/output format."
		  " currently accepted values: {'SHA256', 'SHA224', 'SHA1', 'SHA384', "
		  "'SHA512'}, Default is 'SHA256'" },
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "key", 'k', "FILE", 0,
		  "private RSA key (PEM), used when signing data for PKCS7/Auth files"
		  " must have a corresponding '-c FILE' ."
		  " you can also use multiple signers by declaring several '-k <> -c <>' "
		  "pairs" },
		{ "signature", 's', "FILE", 0,
		  "raw signed data, alternative to using private keys when generating "
		  "PKCS7/Auth"
		  " files, must have a corresponding '-c <crtFile>' ."
		  " you can also use multiple signers by declaring several '-s <> -c <>' "
		  "pairs."
		  " for valid secure variable auth files, this data should be generated "
		  "with"
		  " `secvarctl generate c:x ...` and then signed externally into FILE, "
		  "remember to use the"
		  " same '-t <timestamp>' argument for both commands" },
		{ "cert", 'c', "FILE", 0,
		  "x509 cetificate (PEM), used when signing data for PKCS7/Auth files" },
		{ "time", 't', "<YYYY-MM-DDThh:mm:ss>", 0,
		  "set custom timestamp in UTC when generating PKCS7/Auth/presigned "
		  "digest, default is currrent time in UTC, format defined by ISO 8601, "
		  "note 'T' is literally in the string, see manpage for value "
		  "info/ranges" },
		{ "force", 'f', 0, 0,
		  "does not do prevalidation on the input file, assumes format is correct" },
		{ "append", 'a', 0, 0, "set append flag, used when generating auth file" },
		{ 0, 'i', "FILE", OPTION_HIDDEN, "input file" },
		{ 0, 'o', "FILE", OPTION_HIDDEN, "output file" },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = {
		options, parse_options,
		"<input_format>:<output_format> -i <input_file> -o <output_file>\n"
		"reset -i <input_file> -o <output_file>",
		"This command generates various files related to updating secure boot "
		"variables"
		" It requires an input file that is formatted according to <inputFormat> "
		"(see below)"
		" and produces an output file that is formatted according to "
		"<output_format> (see below).\v"
		"Accepted <inputFormat>:"
		"\n\t[h]ash\tA file containing only hashed data\n"
		"\t[c]ert\tAn x509 certificate (PEM format)\n"
		"\t[e]sl\tAn EFI Signature List, if dbx must specify '-n dbx'\n"
		"\t[p]kcs7\tA PKCS7 file\n"
		"\t[a]uth\ta properly generated authenticated variable fileI\n"
		"\t[f]ile\tAny file type, Warning: no format validation will be done\n\n"
		"accepted <output_format>:\n"
		"\t[h]ash\tA file containing only hashed data\n"
		"\t[e]sl\tAn EFI Signature List\n"
		"\t[p]kcs7\tA PKCS7 file containing signed data\n"
		"\t[a]uth\ta properly generated authenticated variable file\n"
		"\t[x]\tA valid secure variable presigned digest.\n\n"
		"Using with `reset` instead of `<input_format>:<output_format>' generates a "
		"valid variable reset file."
		" this file is just an auth file with an empty ESL. `reset` requires "
		"arguments: output file, signer"
		" crt/key pair and variable name, no input file is required. use this flag "
		"to delete a variable.\n\n"
		"Typical commands:\n"
		"  -create valid dbx ESL from binary file with SHA512:\n"
		"\t'... f:e -i <file> -o <file> -h SHA512'\n"
		"  -create an ESL from an x509 certificate:\n"
		"\t'... c:e -i <file> -o <file>'\n"
		"  -create an ESL with Timestamp from an x509 certificate: with .tesl "
		"extenstion for guest secure boot\n"
		"\t'... c:s -i <file> -t <y-m-dTh:m:s> -o <file>'\n"
		"  -create an auth file from an ESL:\n"
		"\t'... e:a -k <file> -c <file> -n <variable_name> -i <file> -o <file>'\n"
		"  -create an auth file from an x509:\n"
		"\t'... c:a -k <file> -c <file> -n <variable_name> -i <file> -o <file>'\n"
		"  -create a valid dbx update (auth) file from a binary file:\n"
		"\t'... f:a -h <hash_algo> -k <file> -c <file> -n dbx -i <file> -o <file>'\n"
		"  -retrieve the ESL from an auth file:\n"
		"\t'... a:e -i <file> -o <file>'\n"
		"  -create an auth file for a key reset:\n"
		"\t'... reset -k <file> -c <file> -n <variable_name> -o <file>'\n"
		"  -create an auth file using an external signing framework:\n"
		"\t'... c:x -n <variable_name> -t <y-m-dTh:m:s> -i <file> -o <file>'\n"
		"\tthen user gets output signed through server (<sig_file>):\n"
		"\t'... c:a -n <> -t <same_time!> -s <sig_file> -c <crt_file> -i <file> -o "
		"<file>\n"

	};

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.help_flag)
		goto out;

	if (args.sign_cert_count != args.sign_key_count) {
		if (args.pkcs7_gen_method == W_EXTERNAL_GEN_SIG)
			prlog(PR_ERR,
			      "ERROR: number of certificates does not equal number of signature files, %d != %d\n",
			      args.sign_cert_count, args.sign_key_count);
		else
			prlog(PR_ERR,
			      "ERROR: number of certificates does not equal number of keys, %d != %d\n",
			      args.sign_cert_count, args.sign_key_count);
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	prlog(PR_INFO, "input file is %s of type %s , output file is %s of type %s\n",
	      args.input_file, args.input_form, args.output_file, args.output_form);

	/* if reset key than don't look for an input file */
	if (args.input_form[0] == 'r')
		size = 0;
	else {
		/* get data from input file */
		buffer = (unsigned char *)get_data_from_file(args.input_file, SIZE_MAX, &size);
		if (buffer == NULL) {
			prlog(PR_ERR, "ERROR: could not find data in file %s\n", args.input_file);
			rc = INVALID_FILE;
			goto out;
		}
	}

	/* default alg is sha256 */
	if (args.hash_alg == NULL)
		args.hash_alg = "SHA256";

	/* get hash function */
	rc = get_hash_function(args.hash_alg, &hash_function);
	if (rc)
		goto out;

	/* now we can try to generate the desired output format */
	rc = generate_data(buffer, size, &args, hash_function, &out_buffer, &out_buffer_size);
	if (rc) {
		prlog(PR_ERR, "failed to generate into output format: %s\n", args.output_form);
		goto out;
	}

	prlog(PR_INFO, "writing %zu bytes to %s\n", out_buffer_size, args.output_file);
	/* write data to new file */
	rc = create_file(args.output_file, (char *)out_buffer, out_buffer_size);
	if (rc) {
		prlog(PR_ERR, "ERROR: could not write new data to output file %s\n",
		      args.output_file);
	}

out:

	if (buffer)
		free(buffer);

	if (out_buffer)
		free(out_buffer);

	if (args.sign_keys)
		free(args.sign_keys);

	if (args.sign_certs)
		free(args.sign_certs);

	if (args.time)
		free(args.time);

	if (!args.help_flag)
		printf("RESULT: %s\n", rc ? "FAILURE" : "SUCCESS");

	return rc;
}
#endif
