// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifdef SECVAR_CRYPTO_WRITE_FUNC
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define __USE_XOPEN // needed for strptime
#include <time.h> // for timestamp
#include <ctype.h> // for isspace
#include <argp.h>
#include "secvar/crypto/crypto.h"
#include <ccan/endian/endian.h>
#include "host_svc_backend.h"
#include "secvar/backend/edk2-compat-process.h" // work on factoring this out

enum pkcs7_generation_method {
	// for -k <key> option
	W_PRIVATE_KEYS = 0,
	// for -s <sig> option
	W_EXTERNAL_GEN_SIG,
	// default, when not generating a pkcs7/auth
	NO_PKCS7_GEN_METHOD
};

struct Arguments {
	// the pkcs7_gen_meth is to determine if signKeys stores a private key file(0) or signed data (1)
	int helpFlag, inpValid, signKeyCount, signCertCount;
	const char *inFile, *outFile, **signCerts, **signKeys, *inForm, *outForm, *varName,
		*hashAlg;
	struct efi_time *time;
	enum pkcs7_generation_method pkcs7_gen_meth;
};

static int parse_opt(int key, char *arg, struct argp_state *state);
static int generateHash(const unsigned char *data, size_t size, struct Arguments *args,
			const struct hash_funct *alg, unsigned char **outHash, size_t *outHashSize);
static int validateHashAndAlg(size_t size, const struct hash_funct *alg);
static int toESL(const unsigned char *data, size_t size, const uuid_t guid, unsigned char **outESL,
		 size_t *outESLSize);
static int getHashFunction(const char *name, struct hash_funct **returnFunct);
static int toPKCS7ForSecVar(const unsigned char *newData, size_t dataSize, struct Arguments *args,
			    int hashFunct, unsigned char **outBuff, size_t *outBuffSize);
static int toAuth(const unsigned char *newESL, size_t eslSize, struct Arguments *args,
		  int hashFunct, unsigned char **outBuff, size_t *outBuffSize);
static int generateESL(const unsigned char *buff, size_t size, struct Arguments *args,
		       const struct hash_funct *hashFunct, unsigned char **outBuff,
		       size_t *outBuffSize);
static int generateAuthOrPKCS7(const unsigned char *buff, size_t size, struct Arguments *args,
			       const struct hash_funct *hashFunct, unsigned char **outBuff,
			       size_t *outBuffSize);
static int getTimestamp(struct efi_time *ts);
static int getOutputData(const unsigned char *buff, size_t size, struct Arguments *args,
			 const struct hash_funct *hashFunction, unsigned char **outBuff,
			 size_t *outBuffSize);
static int authToESL(const unsigned char *in, size_t inSize, unsigned char **out, size_t *outSize);
static int toHashForSecVarSigning(const unsigned char *ESL, size_t ESL_size, struct Arguments *args,
				  unsigned char **outBuff, size_t *outBuffSize);
static int getPreHashForSecVar(unsigned char **outData, size_t *outSize, const unsigned char *ESL,
			       size_t ESL_size, struct Arguments *args);
static int parseCustomTimestamp(struct efi_time *strct, const char *str);
static void convert_tm_to_efi_time(struct efi_time *efi_t, struct tm *tm_t);
/*
 *called from main()
 *handles argument parsing for generate command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int performGenerateCommand(int argc, char *argv[])
{
	int rc;
	size_t outBuffSize, size;
	struct hash_funct *hashFunction;
	unsigned char *buff = NULL, *outBuff = NULL;
	struct Arguments args = { .helpFlag = 0,
				  .inpValid = 0,
				  .signKeyCount = 0,
				  .signCertCount = 0,
				  .inFile = NULL,
				  .outFile = NULL,
				  .signCerts = NULL,
				  .signKeys = NULL,
				  .inForm = NULL,
				  .outForm = NULL,
				  .varName = NULL,
				  .hashAlg = NULL,
				  .time = NULL,
				  .pkcs7_gen_meth = NO_PKCS7_GEN_METHOD };
	// combine command and subcommand for usage/help messages
	argv[0] = "secvarctl -m host generate";

	struct argp_option options[] = {
		{ "var", 'n', "VAR_NAME", 0,
		  "name of a secure boot variable, used when generating an PKCS7/Auth file."
		  " Also, when an ESL or Auth file contains hashed data use '-n dbx'."
		  " currently accepted values: {'PK','KEK','db','dbx'}" },
		{ "alg", 'h', "HASH_ALG", 0,
		  "hash function, use when '[h]ash' is input/output format."
		  " currently accepted values: {'SHA256', 'SHA224', 'SHA1', 'SHA384', 'SHA512'}, Default is 'SHA256'" },
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "key", 'k', "FILE", 0,
		  "private RSA key (PEM), used when signing data for PKCS7/Auth files"
		  " must have a corresponding '-c FILE' ."
		  " you can also use multiple signers by declaring several '-k <> -c <>' pairs" },
		{ "signature", 's', "FILE", 0,
		  "raw signed data, alternative to using private keys when generating PKCS7/Auth"
		  " files, must have a corresponding '-c <crtFile>' ."
		  " you can also use multiple signers by declaring several '-s <> -c <>' pairs."
		  " for valid secure variable auth files, this data should be generated with"
		  " `secvarctl generate c:x ...` and then signed externally into FILE, remember to use the"
		  " same '-t <timestamp>' argument for both commands" },
		{ "cert", 'c', "FILE", 0,
		  "x509 cetificate (PEM), used when signing data for PKCS7/Auth files" },
		{ "time", 't', "<YYYY-MM-DDThh:mm:ss>", 0,
		  "set custom timestamp in UTC when generating PKCS7/Auth/presigned "
		  "digest, default is currrent time in UTC, format defined by ISO 8601, note 'T' is literally in the string, see manpage for value info/ranges" },
		{ "force", 'f', 0, 0,
		  "does not do prevalidation on the input file, assumes format is correct" },
		// these are hidden because they are mandatory and are described in the help message instead of in the options
		{ 0, 'i', "FILE", OPTION_HIDDEN, "input file" },
		{ 0, 'o', "FILE", OPTION_HIDDEN, "output file" },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = {
		options, parse_opt,
		"<inputFormat>:<outputFormat> -i <inputFile> -o <outputFile>\nreset -i <inputFile> -o <outputFile>",
		"This command generates various files related to updating secure boot variables"
		" It requires an input file that is formatted according to <inputFormat> (see below)"
		" and produces an output file that is formatted according to <outputFormat> (see below).\v"
		"Accepted <inputFormat>:"
		"\n\t[h]ash\tA file containing only hashed data\n"
		"\t[c]ert\tAn x509 certificate (PEM format)\n"
		"\t[e]sl\tAn EFI Signature List, if dbx must specify '-n dbx'\n"
		"\t[p]kcs7\tA PKCS7 file\n"
		"\t[a]uth\ta properly generated authenticated variable fileI\n"
		"\t[f]ile\tAny file type, Warning: no format validation will be done\n\n"
		"Accepted <outputFormat>:\n"
		"\t[h]ash\tA file containing only hashed data\n"
		"\t[e]sl\tAn EFI Signature List\n"
		"\t[p]kcs7\tA PKCS7 file containing signed data\n"
		"\t[a]uth\ta properly generated authenticated variable file\n"
		"\t[x]\tA valid secure variable presigned digest.\n\n"
		"Using with `reset` instead of `<inputFormat>:<outputFormat>' generates a valid variable reset file."
		" this file is just an auth file with an empty ESL. `reset` requires arguments: output file, signer"
		" crt/key pair and variable name, no input file is required. use this flag to delete a variable.\n\n"
		"Typical commands:\n"
		"  -create valid dbx ESL from binary file with SHA512:\n"
		"\t'... f:e -i <file> -o <file> -h SHA512'\n"
		"  -create an ESL from an x509 certificate:\n"
		"\t'... c:e -i <file> -o <file>'\n"
		"  -create an auth file from an ESL:\n"
		"\t'... e:a -k <file> -c <file> -n <varName> -i <file> -o <file>'\n"
		"  -create an auth file from an x509:\n"
		"\t'... c:a -k <file> -c <file> -n <varName> -i <file> -o <file>'\n"
		"  -create a valid dbx update (auth) file from a binary file:\n"
		"\t'... f:a -h <hashAlg> -k <file> -c <file> -n dbx -i <file> -o <file>'\n"
		"  -retrieve the ESL from an auth file:\n"
		"\t'... a:e -i <file> -o <file>'\n"
		"  -create an auth file for a key reset:\n"
		"\t'... reset -k <file> -c <file> -n <varName> -o <file>'\n"
		"  -create an auth file using an external signing framework:\n"
		"\t'... c:x -n <varName> -t <y-m-dTh:m:s> -i <file> -o <file>'\n"
		"\tthen user gets output signed through server (<sigFile>):\n"
		"\t'... c:a -n <> -t <sameTime!> -s <sigFile> -c <crtfile> -i <file> -o <file>\n"

	};

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.helpFlag)
		goto out;

	// if signing each signer needs a certificate
	if (args.signCertCount != args.signKeyCount) {
		if (args.pkcs7_gen_meth == W_EXTERNAL_GEN_SIG)
			prlog(PR_ERR,
			      "ERROR: Number of certificates does not equal number of signature files, %d != %d\n",
			      args.signCertCount, args.signKeyCount);
		else
			prlog(PR_ERR,
			      "ERROR: Number of certificates does not equal number of keys, %d != %d\n",
			      args.signCertCount, args.signKeyCount);
		rc = ARG_PARSE_FAIL;
		goto out;
	}
	prlog(PR_INFO, "Input file is %s of type %s , output file is %s of type %s\n", args.inFile,
	      args.inForm, args.outFile, args.outForm);

	// if reset key than don't look for an input file
	if (args.inForm[0] == 'r')
		size = 0;
	else {
		// get data from input file
		buff = (unsigned char *)get_data_from_file(args.inFile, SIZE_MAX, &size);
		if (buff == NULL) {
			prlog(PR_ERR, "ERROR: Could not find data in file %s\n", args.inFile);
			rc = INVALID_FILE;
			goto out;
		}
	}
	// default alg is sha256
	if (args.hashAlg == NULL)
		args.hashAlg = "SHA256";
	// get hash function
	rc = getHashFunction(args.hashAlg, &hashFunction);
	if (rc)
		goto out;
	// now we can try to generate the desired output format
	rc = getOutputData(buff, size, &args, hashFunction, &outBuff, &outBuffSize);
	if (rc) {
		prlog(PR_ERR, "Failed to generate into output format: %s\n", args.outForm);
		goto out;
	}

	prlog(PR_INFO, "Writing %zu bytes to %s\n", outBuffSize, args.outFile);
	// write data to new file
	rc = create_file(args.outFile, (char *)outBuff, outBuffSize);
	if (rc) {
		prlog(PR_ERR, "ERROR: Could not write new data to output file %s\n", args.outFile);
	}

out:
	if (buff)
		free(buff);
	if (outBuff)
		free(outBuff);
	if (args.signKeys)
		free(args.signKeys);
	if (args.signCerts)
		free(args.signCerts);
	if (args.time)
		free(args.time);
	if (!args.helpFlag)
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
		args->helpFlag = 1;
		argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
		break;
	case ARGP_OPT_USAGE_KEY:
		args->helpFlag = 1;
		argp_state_help(state, stdout, ARGP_HELP_USAGE);
		break;
	case 'k':
		// if already storing signed data, then don't allow for private keys
		if (args->pkcs7_gen_meth == W_EXTERNAL_GEN_SIG) {
			prlog(PR_ERR,
			      "ERROR: Cannot have both signed data files and private keys for signing\n");
			rc = ARG_PARSE_FAIL;
			break;
		}
		args->pkcs7_gen_meth = W_PRIVATE_KEYS;
		args->signKeyCount++;
		rc = realloc_array((void **)&args->signKeys, args->signKeyCount,
				   sizeof(*args->signKeys));
		if (rc) {
			prlog(PR_ERR, "Failed to realloc private key (-k <>) array\n");
			break;
		}
		args->signKeys[args->signKeyCount - 1] = arg;
		break;
	case 'c':
		args->signCertCount++;
		rc = realloc_array((void **)&args->signCerts, args->signCertCount,
				   sizeof(*args->signCerts));
		if (rc) {
			prlog(PR_ERR, "Failed to realloc certificate (-c <>) array\n");
			break;
		}
		args->signCerts[args->signCertCount - 1] = arg;
		break;
	case 'f':
		args->inpValid = 1;
		break;
	case 'v':
		verbose = PR_DEBUG;
		break;
	case 's':
		// if already storing private keys, then don't allow for signed data
		if (args->pkcs7_gen_meth == W_PRIVATE_KEYS) {
			prlog(PR_ERR,
			      "ERROR: Cannot have both signed data files and private keys for signing");
			rc = ARG_PARSE_FAIL;
			break;
		}
		args->pkcs7_gen_meth = W_EXTERNAL_GEN_SIG;
		args->signKeyCount++;
		rc = realloc_array((void **)&args->signKeys, args->signKeyCount,
				   sizeof(*args->signKeys));
		if (rc) {
			prlog(PR_ERR, "Failed to realloc signature (-s <>) array\n");
			break;
		}
		args->signKeys[args->signKeyCount - 1] = arg;
		break;
	case 'i':
		args->inFile = arg;
		break;
	case 'o':
		args->outFile = arg;
		break;
	case 'h':
		args->hashAlg = arg;
		break;
	case 'n':
		args->varName = arg;
		break;
	case 't':
		args->time = calloc(1, sizeof(*args->time));
		if (!args->time) {
			prlog(PR_ERR, "ERROR: failed to allocate memory\n");
			rc = ALLOC_FAIL;
			break;
		}
		if (parseCustomTimestamp(args->time, arg)) {
			prlog(PR_ERR,
			      "ERROR: Could not parse given timestamp %s, make sure it is in format YYYY-MM-DDThh:mm:ss\n",
			      arg);
			rc = ARG_PARSE_FAIL;
		}
		break;
	case ARGP_KEY_ARG:
		// check if reset key is desired
		if (!strcmp(arg, "reset")) {
			args->inForm = "reset";
			args->inFile = "empty";
			args->outForm = "auth";
			break;
		}
		// else set input and output formats
		args->inForm = strtok(arg, ":");
		args->outForm = strtok(NULL, ":");
		break;
	case ARGP_KEY_SUCCESS:
		// check that all essential args are given and valid
		if (args->helpFlag)
			break;
		else if (args->inForm == NULL || args->outForm == NULL)
			prlog(PR_ERR,
			      "ERROR: Incorrect '<inputFormat>:<outputFormat>', see usage...\n");
		else if (args->time && validateTime(args->time))
			prlog(PR_ERR,
			      "Invalid timestamp flag '-t YYYY-MM-DDThh:mm:ss' , see usage...\n");
		else if (args->inForm[0] != 'r' && (args->inFile == NULL || is_file(args->inFile)))
			prlog(PR_ERR, "ERROR: Input File is invalid, see usage below...\n");
		else if (args->varName && isVariable(args->varName))
			prlog(PR_ERR, "ERROR: %s is not a valid variable name\n", args->varName);
		else if (args->outFile == NULL)
			prlog(PR_ERR, "ERROR: No output file given, see usage below...\n");
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

/*
 *parses a '-t YYYY-MM-DDThh:mm:ss>' argument into the efi_time struct
 *@param strct, the allocated efi_time struct, to be filled with data
 *@param str,  the given timestamp string
 *@return SUCCESS or errno if failed to extract data
 */
static int parseCustomTimestamp(struct efi_time *strct, const char *str)
{
	struct tm t;
	char *ret = NULL;
	memset(&t, 0, sizeof(t));
	ret = strptime(str, "%FT%T", &t);
	if (ret == NULL)
		return INVALID_TIMESTAMP;
	else if (*ret != '\0') {
		prlog(PR_ERR, "ERROR: Failed to parse timestamp value at %s\n", ret);
		return INVALID_TIMESTAMP;
	}

	convert_tm_to_efi_time(strct, &t);
	return SUCCESS;
}
/*
 *after parsing argument information and getting input data, this will return the generated output data given the output format
 *@param buff, inut data, it must be of the same type as specified by inform
 *@param size , length of buff
 *@param args, struct containing lots of input info
 *@param hashFunct, array of hash function information to use if hashing
 *@param outBuff, the resultinggenerated File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outBuffSize, the length of outBuff
 *@return SUCCESS or err number 
 */
static int getOutputData(const unsigned char *buff, size_t size, struct Arguments *args,
			 const struct hash_funct *hashFunction, unsigned char **outBuff,
			 size_t *outBuffSize)
{
	int rc;
	// once here it is time to plan the course of action depending on the output type desired
	switch (args->outForm[0]) {
	case 'c':
		rc = CERT_FAIL; // cannot generate a cert
		break;
	case 'h':
		rc = generateHash(buff, size, args, hashFunction, outBuff, outBuffSize);
		break;
	case 'x':
		// intentional flow
	case 'a':
		// intentional flow into pkcs7
	case 'p':
		// if no time is given then get curent time
		if (!args->time) {
			args->time = calloc(1, sizeof(*args->time));
			if (!args->time) {
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				rc = ALLOC_FAIL;
				goto out;
			}
			rc = getTimestamp(args->time);
			if (rc)
				goto out;
		}
		rc = generateAuthOrPKCS7(buff, size, args, hashFunction, outBuff, outBuffSize);
		break;
	case 'e':
		rc = generateESL(buff, size, args, hashFunction, outBuff, outBuffSize);
		break;
	default:
		prlog(PR_ERR, "ERROR: Unknown output format %s, use `--help` for more info\n",
		      args->outForm);
		rc = ARG_PARSE_FAIL;
	}
out:
	return rc;
}

/*
 *does prevalidation on input info, then given all the input information it should generate an auth or PKCS7 (depending on args->outForm)
 *file and its size and return a SUCCESS or negative number (ERROR)
 *@param buff, data to be added to auth or PKCS7, it must be of the same type as specified by inform
 *@param size , length of buff
 *@param args, struct containing command line info and lots of other important information
 *@param hashFunct, array of hash function information to use for signing (see above for format)
 *@param outBuff, the resulting auth or PKCS7 File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outBuffSize, the length of outBuff
 *@return SUCCESS or err number 
 */
static int generateAuthOrPKCS7(const unsigned char *buff, size_t size, struct Arguments *args,
			       const struct hash_funct *hashFunct, unsigned char **outBuff,
			       size_t *outBuffSize)
{
	int rc;
	size_t intermediateBuffSize, inpSize = size;
	unsigned char *intermediateBuff = NULL, **inpPtr;
	inpPtr = (unsigned char **)&buff;

	switch (args->inForm[0]) {
	case 'f':
		// intentional flow
	case 'h':
		// intentional flow
	case 'c':
		rc = generateESL(buff, size, args, hashFunct, &intermediateBuff,
				 &intermediateBuffSize);
		if (rc) {
			break;
		}
		inpPtr = &intermediateBuff;
		inpSize = intermediateBuffSize;
		// intentionaly flow into ESL validation
	case 'e':
		// if data is known to be valid than do not validate
		if (!args->inpValid) {
			rc = validateESL(*inpPtr, inpSize, args->varName);
			if (rc) {
				prlog(PR_ERR, "ERROR: Could not validate ESL\n");
				break;
			}
		}
		rc = SUCCESS;
		break;
	case 'r':
		// if creating a reset key, ensure input is NULL and size of zero
		if (inpSize == 0 && *inpPtr == NULL)
			rc = SUCCESS;
		else {
			printf("ERROR: Input data must be empty for generation of reset file\n");
			rc = INVALID_FILE;
			break;
		}
		break;
	default:
		prlog(PR_ERR, "ERROR: Unknown input format %s for generating %s file.\n",
		      args->inForm, (args->outForm[0] == 'a' ? "an Auth" : "a PKCS7"));
		rc = ARG_PARSE_FAIL;
	}
	if (rc) {
		prlog(PR_ERR, "Failed to validate input format\n");
		goto out;
	}

	if (args->outForm[0] == 'a')
		rc = toAuth(*inpPtr, inpSize, args, hashFunct->crypto_md_funct, outBuff,
			    outBuffSize);
	else if (args->outForm[0] == 'x')
		rc = toHashForSecVarSigning(*inpPtr, inpSize, args, outBuff, outBuffSize);
	else
		rc = toPKCS7ForSecVar(*inpPtr, inpSize, args, hashFunct->crypto_md_funct, outBuff,
				      outBuffSize);

	if (rc) {
		prlog(PR_ERR, "Failed to generate %s file, use `--help` for more info\n",
		      args->outForm[0] == 'a' ? "Auth" :
		      args->outForm[0] == 'x' ? "pre-signed hash" :
						"PKCS7");
		goto out;
	}
out:
	if (intermediateBuff)
		free(intermediateBuff);
	return rc;
}

/*
 *does prevalidation on input info, then given all the input information it should generate an esl file and its size and return a SUCCESS or negative number (ERROR)
 *@param buff, data to be added to ESL, it must be of the same type as specified by inform
 *@param size , length of buff
 *@param args, struct of input info
 *@param hashFunct, array of hash function information to use for ESL GUID, also helps in prevalation, if inform is '[c]ert' then this doesn't matter
 *@param outBuff, the resulting ESL File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outBuffSize, the length of outBuff
 *@return SUCCESS or err number 
 */
static int generateESL(const unsigned char *buff, size_t size, struct Arguments *args,
		       const struct hash_funct *hashFunct, unsigned char **outBuff,
		       size_t *outBuffSize)
{
	int rc;
	size_t intermediateBuffSize, inpSize = size;
	unsigned char *intermediateBuff = NULL, **inpPtr;
	uuid_t const *eslGUID = &EFI_CERT_X509_GUID;
	inpPtr = (unsigned char **)&buff;

	switch (args->inForm[0]) {
	case 'f':
		rc = crypto_md_generate_hash(buff, size, hashFunct->crypto_md_funct,
					     &intermediateBuff, &intermediateBuffSize);
		if (rc != CRYPTO_SUCCESS) {
			prlog(PR_ERR, "Failed to generate hash from file\n");
			break;
		}
		// new input is the hash file
		inpPtr = &intermediateBuff;
		inpSize = intermediateBuffSize;
		// intentionally flow into hash validation
	case 'h':
		if (!args->inpValid) {
			rc = validateHashAndAlg(inpSize, hashFunct);
			if (rc) {
				prlog(PR_ERR, "Failed to validate input hash data\n");
				break;
			}
		}
		rc = SUCCESS;
		eslGUID = hashFunct->guid;
		break;
	case 'c':
		// two intermediate buffers needed, one for input -> DER and one for DER -> ESL,
		prlog(PR_INFO, "Converting x509 from PEM to DER...\n");
		rc = crypto_convert_pem_to_der(*inpPtr, inpSize,
					       (unsigned char **)&intermediateBuff,
					       &intermediateBuffSize);
		if (rc != CRYPTO_SUCCESS) {
			prlog(PR_ERR, "ERROR: Could not convert PEM to DER\n");
			break;
		}
		if (!args->inpValid) {
			rc = validateCert(intermediateBuff, intermediateBuffSize, args->varName);
			if (rc) {
				prlog(PR_ERR, "ERROR: Could not validate certificate\n");
				break;
			}
		}
		eslGUID = &EFI_CERT_X509_GUID;
		rc = SUCCESS;
		// new input is the der
		inpPtr = &intermediateBuff;
		inpSize = intermediateBuffSize;
		break;
	case 'a':
		if (!args->inpValid) {
			rc = validateAuth(buff, size, args->varName);
			if (rc) {
				prlog(PR_ERR, "ERROR: Could not validate signed auth file\n");
				break;
			}
		}
		rc = SUCCESS;
		break;
	default:
		prlog(PR_ERR,
		      "ERROR: unknown input format %s for generating an ESL, use `--help` for more info\n",
		      args->inForm);
		rc = ARG_PARSE_FAIL;
	}
	if (rc) {
		prlog(PR_ERR, "Failed to validate input format\n");
		goto out;
	}
	// if input file is auth than extract it
	if (args->inForm[0] == 'a')
		rc = authToESL(*inpPtr, inpSize, outBuff, outBuffSize);
	else
		// now we have either a hash or x509 in der and is ready to be put into an ESL
		rc = toESL(*inpPtr, inpSize, *eslGUID, outBuff, outBuffSize);
	if (rc) {
		prlog(PR_ERR, "Failed to generate ESL file\n");
		goto out;
	}
out:
	if (intermediateBuff)
		free(intermediateBuff);
	return rc;
}

/*
 *does prevalidation on input info, then given all the input information it should generate hashed data and its size and return a SUCCESS or negative number (ERROR)
 *@param data, data to be hashed, it must be of the same type as specified by inform
 *@param size , length of buff
 *@param args, struct containing important command line info
 *@param hashFunct, array of hash function information to use as hash algorithm
  *@param outHash, the resulting hash, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outHashSize, the length of outHash
 *@return SUCCESS or err number 
 */
static int generateHash(const unsigned char *data, size_t size, struct Arguments *args,
			const struct hash_funct *alg, unsigned char **outHash, size_t *outHashSize)
{
	int rc;
	//  if the input is not declared valid then we validate it is the same as inForm format
	if (!args->inpValid) {
		switch (args->inForm[0]) {
		case 'f':
			rc = SUCCESS;
			break;
		case 'c':
			rc = validateCert(data, size, args->varName);
			break;
		case 'e':
			rc = validateESL(data, size, args->varName);
			break;
		case 'p':
			rc = validatePKCS7(data, size);
			break;
		case 'a':
			rc = validateAuth(data, size, args->varName);
			break;
		default:
			prlog(PR_ERR,
			      "ERROR: unknown input format %s for generating a hash, use `--help` for more info\n",
			      args->inForm);
			rc = ARG_PARSE_FAIL;
		}
		if (rc) {
			prlog(PR_ERR,
			      "Failed to validate input format of input file when generating hash, try again with -f to skip format validation of input\n");
			return rc;
		}
	}
	rc = crypto_md_generate_hash(data, size, alg->crypto_md_funct, outHash, outHashSize);
	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_ERR, "Failed to generate hash\n");
		return rc;
	}
	return validateHashAndAlg(*outHashSize, alg);
}

/*
 *validates that the size of the hash buffer is equal to the expected, only real check we can do on a hash
 *@param size , length of hash to be validated
 *@param hashFunct, array of hash function information
 *@return SUCCESS or err number 
 */
static int validateHashAndAlg(size_t size, const struct hash_funct *alg)
{
	if (size != alg->size) {
		prlog(PR_ERR,
		      "ERROR: length of hash data does not equal expected size of hash %s, expected %zu found %zu bytes\n",
		      alg->name, alg->size, size);
		return HASH_FAIL;
	}
	return SUCCESS;
}

/* 
 *generates ESL from input data, esl will have GUID specified by guid
 *@param data, data to be added to ESL
 *@param size , length of data
 *@param guid, guid of data type of data
 *@param outESL, the resulting ESL File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outESLSize, the length of outBuff
 *@return SUCCESS or err number 
 */
static int toESL(const unsigned char *data, size_t size, const uuid_t guid, unsigned char **outESL,
		 size_t *outESLSize)
{
	EFI_SIGNATURE_LIST esl;
	size_t offset = 0;

	prlog(PR_INFO, "Creating ESL from %s... Adding:\n", getSigType(guid));
	esl.SignatureType = guid;
	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "\t%s Guid - ", getSigType(guid));
		printGuidSig(&guid);
	}

	esl.SignatureListSize = sizeof(esl) + sizeof(uuid_t) + size;
	prlog(PR_INFO, "\tSig List Size - %u\n", esl.SignatureListSize);
	// for some reason we are using header size is zero in all our files
	esl.SignatureHeaderSize = 0;
	esl.SignatureSize = size + sizeof(uuid_t);
	prlog(PR_INFO, "\tSignature Data Size - %u\n", esl.SignatureSize);

	/*ESL Structure:
		-ESL header - 28 bytes
		-ESL Owner uuid - 16 bytes
		-data
	*/
	// add ESL header stuff
	*outESL = calloc(1, esl.SignatureListSize);
	if (!*outESL) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	prlog(PR_INFO, "\tCombining header info and data\n");
	memcpy(*outESL, &esl, sizeof(esl));
	offset += sizeof(esl);

	// add owner guid here, leave blank for now
	offset += sizeof(uuid_t);
	// add data
	memcpy(*outESL + offset, data, size);
	*outESLSize = esl.SignatureListSize;
	prlog(PR_INFO, "ESL generation successful...\n");
	return SUCCESS;
}

/**
 *actually performs the extraction of the esl from the authfile
 *@param in , in buffer, auth buffer 
 *@param inSize, length of auth buffer
 *@param out , out ESL, ESL buffer
 *@param outSize, length of ESL
 *NOTE: This allocates memory for output buffer, FREE LATER
 *@return SUCCESS or error number
 */
static int authToESL(const unsigned char *in, size_t inSize, unsigned char **out, size_t *outSize)
{
	size_t length, auth_buffer_size, offset = 0, pkcs7_size;
	const struct efi_variable_authentication_2 *auth;

	auth = (struct efi_variable_authentication_2 *)in;
	length = auth->auth_info.hdr.dw_length;
	if (length == 0 || length > inSize) { // if total size of header and pkcs7
		prlog(PR_ERR, "ERROR: Invalid auth size %zu\n", length);
		return AUTH_FAIL;
	}
	pkcs7_size = get_pkcs7_len(auth);
	/*pkcs7_size=length-(sizeof(auth->auth_info.hdr)+sizeof(auth->auth_info.cert_type));*/ // =sizeof cert_data[] AKA pkcs7 data
	// if total size of header and pkcs7
	if (pkcs7_size == 0 || pkcs7_size > length) {
		prlog(PR_ERR, "ERROR: Invalid pkcs7 size %zu\n", pkcs7_size);
		return PKCS7_FAIL;
	}
	/*
	 * efi_var_2->auth_info.data = auth descriptor + new ESL data.
	 * We want only only the auth descriptor/pkcs7 from .data.
	 */
	auth_buffer_size = sizeof(auth->timestamp) + sizeof(auth->auth_info.hdr) +
			   sizeof(auth->auth_info.cert_type) + pkcs7_size;
	if (auth_buffer_size > inSize) { // If no ESL DATA attatched
		prlog(PR_ERR, "ERROR: No data to verify, no attatched ESL\n");
		return ESL_FAIL;
	}
	prlog(PR_NOTICE,
	      "\tAuth File Size = %zu\n\t  -Auth/PKCS7 Data Size = %zu\n\t  -ESL Size = %zu\n",
	      inSize, auth_buffer_size, inSize - auth_buffer_size);

	// skips over entire pkcs7 in cert_datas
	offset = sizeof(auth->timestamp) + length;
	if (offset == inSize) {
		prlog(PR_WARNING, "WARNING: ESL is empty\n");
	}
	*outSize = inSize - offset;
	*out = malloc(*outSize);
	memcpy(*out, in + offset, *outSize);

	return SUCCESS;
}

/*
 *given a string, it will return the corresponding hash_funct info array
 *@param name, the name of the hash function {"SHA1", "SHA246"...}
 *@param returnFunct, the corresponding hash_funct info array
 *@return SUCCESS or err number if not a valid hash function name
 */
static int getHashFunction(const char *name, struct hash_funct **returnFunct)
{
	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
		if (!strcmp(name, hash_functions[i].name)) {
			*returnFunct = (struct hash_funct *)&hash_functions[i];
			return SUCCESS;
		}
	}
	prlog(PR_ERR, "ERROR: Invalid hash algorithm %s , hint: use -h { ", name);
	// loop through all known hashes
	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
		if (i == sizeof(hash_functions) / sizeof(struct hash_funct) - 1)
			prlog(PR_ERR, "%s }\n", hash_functions[i].name);
		else
			prlog(PR_ERR, "%s, ", hash_functions[i].name);
	}

	return ARG_PARSE_FAIL;
}

/*
 *converts the time in a tm timestamp to the equivalent efi_time
 *@param efi_t , a pointer to an allocated efi_time struct, will be filled in with data
 *@param tm_t , the tm struct filled with data
 */
static void convert_tm_to_efi_time(struct efi_time *efi_t, struct tm *tm_t)
{
	efi_t->year = 1900 + tm_t->tm_year;
	efi_t->month = tm_t->tm_mon + 1; // makes 1-12 not 0-11
	efi_t->day = tm_t->tm_mday;
	efi_t->hour = tm_t->tm_hour;
	efi_t->minute = tm_t->tm_min;
	efi_t->second = tm_t->tm_sec;
}

/*
 *gets current time and puts into an efi_time struct
 *@param ts, the outputted current time
 *@return SUCCESS or errno if generated timestamp is incorrect
 */
static int getTimestamp(struct efi_time *ts)
{
	time_t epochTime;
	struct tm *t;

	time(&epochTime);
	t = gmtime(&epochTime);
	convert_tm_to_efi_time(ts, t);

	return validateTime(ts);
}

/*
 *generates presigned hashed data, this accepts an ESL and all metadata, it performs a SHA hash
 *@param ESL, ESL data buffer
 *@param ESL_size , length of ESL
 *@param args, struct containing command line info and lots of other important information
 *@param outBuff, the resulting hashed data, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outBuffSize, the length of hashed data (should be 32 bytes)
 *@return SUCCESS or err number 
 */
static int toHashForSecVarSigning(const unsigned char *ESL, size_t ESL_size, struct Arguments *args,
				  unsigned char **outBuff, size_t *outBuffSize)
{
	int rc;
	unsigned char *preHash = NULL;
	size_t preHash_size;

	rc = getPreHashForSecVar(&preHash, &preHash_size, ESL, ESL_size, args);
	if (rc) {
		prlog(PR_ERR, "Failed to generate pre-hash data\n");
		goto out;
	}
	rc = crypto_md_generate_hash(preHash, preHash_size, CRYPTO_MD_SHA256, outBuff, outBuffSize);
	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_ERR, "Failed to generate hash\n");
		goto out;
	}
	if (*outBuffSize != 32) {
		prlog(PR_ERR, "ERROR: size of SHA256 is not 32 bytes, found %zu bytes\n",
		      *outBuffSize);
		rc = HASH_FAIL;
	}

out:
	if (preHash)
		free(preHash);

	return rc;
}
/* 
 *Expand char to wide character size , for edk2 since ESL's use double wides
 *@param key ,key name
 *@param keylen, length of key
 *@return the new keylen with double length, REMEMBER TO UNALLOC
 */
static char *char_to_wchar(const char *key, const size_t keylen)
{
	int i;
	char *str;

	str = zalloc(keylen * 2);
	if (!str)
		return NULL;

	for (i = 0; i < keylen * 2; key++) {
		str[i++] = *key;
		str[i++] = '\0';
	}

	return str;
}

/*
 *generates data that is ready to be hashed and eventually signed for secure variables
 *more specifically this accepts an ESL and preprends metadata 
 *@param outData, the outputted data with prepended data / REMEMBER TO UNALLOC 
 *@param outSize, length of output data
 *@param ESL, the new ESL data 
 *@param ESL_size, length of ESL buffer
 *@param args, struct containing imprtant metadata info
 *@return, success or error number
 */
static int getPreHashForSecVar(unsigned char **outData, size_t *outSize, const unsigned char *ESL,
			       size_t ESL_size, struct Arguments *args)
{
	int rc = SUCCESS;
	unsigned char *ptr = NULL;
	char *wkey = NULL;
	size_t varlen;
	le32 attr = cpu_to_le32(SECVAR_ATTRIBUTES);
	uuid_t guid;

	if (!args->varName) {
		prlog(PR_ERR, "ERROR: No secure variable name given... use -n <varName> option\n");
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	if (!ESL && ESL_size != 0) {
		prlog(PR_ERR, "%s: ESL is NULL, but ESL_size is not zero this is probably a bug\n",
		      __func__);
		return ARG_PARSE_FAIL;
	}

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "Timestamp is : ");
		printTimestamp(*args->time);
	}

	// some parts taken from edk2-compat-process.c
	if (key_equals(args->varName, "PK") || key_equals(args->varName, "KEK"))
		guid = EFI_GLOBAL_VARIABLE_GUID;
	else if (key_equals(args->varName, "db") || key_equals(args->varName, "dbx"))
		guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
	else {
		prlog(PR_ERR, "ERROR: unknown update variable %s\n", args->varName);
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	/* Expand char name to wide character width */
	varlen = strlen(args->varName) * 2;
	wkey = char_to_wchar(args->varName, strlen(args->varName));
	// with timestamp and all this funky bussiniss, we can  make the correct data to be hashed
	*outSize = varlen + sizeof(guid) + sizeof(attr) + sizeof(struct efi_time) + ESL_size;
	*outData = malloc(*outSize);
	if (!*outData) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = ALLOC_FAIL;
		goto out;
	}
	ptr = *outData;
	memcpy(ptr, wkey, varlen);
	ptr += varlen;
	memcpy(ptr, &guid, sizeof(guid));
	ptr += sizeof(guid);
	memcpy(ptr, &attr, sizeof(attr));
	ptr += sizeof(attr);
	memcpy(ptr, args->time, sizeof(struct efi_time));
	ptr += sizeof(*args->time);
	// Skip zero-sized memcpy if generating a reset to make static analysis happy
	if (ESL)
		memcpy(ptr, ESL, ESL_size);

out:
	if (wkey)
		free(wkey);
	return rc;
}

/*
 *generates a PKCS7 that is compatable with Secure variables AKA the data to be hashed will be keyname + timestamp +attr etc. etc ... + newData 
 *@param newData, data to be added to be used in digest
 *@param dataSize , length of newData
 *@param args,  struct containing important information for generation
 *@param hashFunct, digest to use, NOTE: hashFucnt doesn't matter currently, it will always use SHA256 until edk2-compat-process.c supports different digest algorithms
 *@param outBuff, the resulting PKCS7, newData not appended, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outBuffSize, the length of outBuff
 *@return SUCCESS or err number 
 */
static int toPKCS7ForSecVar(const unsigned char *newData, size_t dataSize, struct Arguments *args,
			    int hashFunct, unsigned char **outBuff, size_t *outBuffSize)
{
	int rc;
	size_t totalSize;
	unsigned char *actualData = NULL;

	rc = getPreHashForSecVar(&actualData, &totalSize, newData, dataSize, args);
	if (rc) {
		prlog(PR_ERR, "Failed to generate pre-hash data for PKCS7\n");
		goto out;
	}
	// get pkcs7 and size, if we are already given ths signatures then call appropriate funcion
	if (args->pkcs7_gen_meth) {
		prlog(PR_INFO, "Generating PKCS7 with already signed data\n");
		rc = crypto_pkcs7_generate_w_already_signed_data(
			(unsigned char **)outBuff, outBuffSize, actualData, totalSize,
			args->signCerts, args->signKeys, args->signKeyCount, CRYPTO_MD_SHA256);
	} else
		rc = crypto_pkcs7_generate_w_signature((unsigned char **)outBuff, outBuffSize,
						       actualData, totalSize, args->signCerts,
						       args->signKeys, args->signKeyCount,
						       CRYPTO_MD_SHA256);
	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_ERR, "ERROR: making PKCS7 failed\n");
		rc = PKCS7_FAIL;
		goto out;
	}

out:
	if (actualData)
		free(actualData);

	return rc;
}

/*
 *generate an auth file and its size and return a SUCCESS or negative number (ERROR)
 *@param newESL, data to be added to auth, it must be of the same type as specified by inform
 *@param eslSize , length of newESL
 *@param args, struct containing important command line info
 *@param hashFunct, array of hash function information to use for signing NOTE: NOT CURRENTLY DOING ANYTING SEE toPKCS7ForSecVar
 *@param outBuff, the resulting auth File, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outBuffSize, the length of outBuff
 *@return SUCCESS or err number 
 */
static int toAuth(const unsigned char *newESL, size_t eslSize, struct Arguments *args,
		  int hashFunct, unsigned char **outBuff, size_t *outBuffSize)
{
	int rc;
	size_t pkcs7Size, offset = 0;
	unsigned char *pkcs7 = NULL;
	struct efi_variable_authentication_2 authHeader;

	if ((newESL == NULL) && (eslSize != 0)) {
		prlog(PR_ERR, "%s: newESL is NULL but eslSize is nonzero, this is probably a bug\n",
		      __func__);
		rc = ALLOC_FAIL;
		goto out;
	}

	// generate PKCS7
	rc = toPKCS7ForSecVar(newESL, eslSize, args, hashFunct, &pkcs7, &pkcs7Size);
	if (rc) {
		prlog(PR_ERR, "Cannot generate Auth File, failed to generate PKCS7\n");
		goto out;
	}
	//  create Auth header
	authHeader.timestamp = *args->time;
	authHeader.auth_info.hdr.dw_length = sizeof(authHeader.auth_info.hdr) +
					     sizeof(authHeader.auth_info.cert_type) + pkcs7Size;
	authHeader.auth_info.hdr.w_revision = cpu_to_be16(WIN_CERT_TYPE_PKCS_SIGNED_DATA);
	// ranges from f0 -ff, but all files Ive seen have f10e
	authHeader.auth_info.hdr.w_certificate_type = cpu_to_be16(0xf10e);
	authHeader.auth_info.cert_type = EFI_CERT_TYPE_PKCS7_GUID;

	// now build auth file, = auth header + pkcs7 + new ESL
	*outBuffSize = pkcs7Size + sizeof(authHeader) + eslSize;
	*outBuff = malloc(*outBuffSize);
	if (!*outBuff) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = ALLOC_FAIL;
		goto out;
	}
	prlog(PR_INFO, "Combining Auth header, PKCS7 and new ESL:\n");
	memcpy(*outBuff + offset, &authHeader, sizeof(authHeader));
	offset += sizeof(authHeader);
	prlog(PR_INFO, "\t+ Auth Header %zu bytes\n", sizeof(authHeader));
	memcpy(*outBuff + offset, pkcs7, pkcs7Size);
	offset += pkcs7Size;
	prlog(PR_INFO, "\t+ PKCS7 %zu bytes\n", pkcs7Size);
	if (newESL != NULL)
		memcpy(*outBuff + offset, newESL, eslSize);
	offset += eslSize;
	prlog(PR_INFO, "\t+ new ESL %zu bytes\n\t= %zu total bytes\n", eslSize, offset);

out:
	if (pkcs7)
		free(pkcs7);

	return rc;
}
#endif
