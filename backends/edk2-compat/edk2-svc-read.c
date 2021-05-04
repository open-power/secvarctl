// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include <fcntl.h> // O_RDONLY
#include <unistd.h> // has read/open funcitons
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include "libstb/secvar/crypto/crypto.h"
#include "external/skiboot/libstb/secvar/secvar.h" // for secvar struct
#include "backends/edk2-compat/include/edk2-svc.h"

static int readFiles(const char *var, const char *file, int hrFlag, const char *path);
static int printReadable(const char *c, size_t size, const char *key);
static int readFileFromSecVar(const char *path, const char *variable, int hrFlag);
static int readFileFromPath(const char *path, int hrFlag);
static int getSizeFromSizeFile(size_t *returnSize, const char *path);
static int readTS(const char *data, size_t size);

struct Arguments {
	int helpFlag, printRaw;
	const char *pathToSecVars, *varName, *inFile;
};
static int parse_opt(int key, char *arg, struct argp_state *state);

/*
 *called from main()
 *handles argument parsing for read command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int performReadCommand(int argc, char *argv[])
{
	int rc;
	struct Arguments args = {
		.helpFlag = 0, .printRaw = 0, .pathToSecVars = NULL, .inFile = NULL, .varName = NULL
	};
	// combine command and subcommand for usage/help messages
	argv[0] = "secvarctl read";

	struct argp_option options[] = {
		{ "raw", 'r', 0, 0, "prints raw data, default is human readable information" },
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "file", 'f', "FILE", 0, "navigates to ESL file from working directiory" },
		{ "path", 'p', "PATH", 0,
		  "looks for key directories {'PK','KEK','db','dbx', 'TS'} in PATH, default is " SECVARPATH },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = {
		options, parse_opt, "[VARIABLE]",
		"This program command is created to easily view secure variables. The current variables"
		" that are able to be observed are the PK, KEK, db, dbx, TS. If no options are"
		" given, then the information for the keys in the default path will be printed."
		" If the user would like to print the information for another ESL file,"
		" then the '-f' command would be appropriate."
		"\vvalues for [VARIABLES] = {'PK','KEK','db','dbx', 'TS'} type one of the following to get info on that key, default is all. NOTE does not work when -f option is present"
	};
	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.helpFlag)
		goto out;

	rc = readFiles(args.varName, args.inFile, !args.printRaw, args.pathToSecVars);

out:
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
	case 'r':
		args->printRaw = 1;
		break;
	case 'p':
		args->pathToSecVars = arg;
		break;
	case 'f':
		args->inFile = arg;
		break;
	case 'v':
		verbose = PR_DEBUG;
		break;
	case ARGP_KEY_ARG:
		args->varName = arg;
		rc = isVariable(args->varName);
		if (rc)
			prlog(PR_ERR, "ERROR: Invalid variable name %s\n", args->varName);
		break;
	}

	if (rc)
		prlog(PR_ERR, "Failed during argument parsing\n");

	return rc;
}

/**
 *Function that recieves arguments to read command and handles getting data, finding paths, iterating through variables to read
 *@param var  string to variable wanted if <variable> option is given, NULL if not
 *@param file string to filename with path if -f option, NULL if not
 *@param hrFLag 1 if -hr for human readable output, 0 for raw data
 *@param path string to path where {PK,KEK,db,dbx,TS} subdirectories are, default SECVARPATH if none given
 *@return succcess if at least one file was successfully read
 */
static int readFiles(const char *var, const char *file, int hrFlag, const char *path)
{
	// program is successful if at least one var was able to be read
	int rc, successCount = 0;

	if (file)
		prlog(PR_NOTICE, "Looking in file %s for ESL's\n", file);
	else
		prlog(PR_NOTICE, "Looking in %s for %s variable with %s format\n",
		      path ? path : SECVARPATH, var ? var : "ALL", hrFlag ? "ASCII" : "raw_data");

	// set default path if no path chosen
	if (!path) {
		path = SECVARPATH;
	}

	if (!file) {
		for (int i = 0; i < ARRAY_SIZE(variables); i++) {
			// if var is defined and it is not the current one then skip
			if (var && strcmp(var, variables[i]) != 0) {
				continue;
			}
			printf("READING %s :\n", variables[i]);
			rc = readFileFromSecVar(path, variables[i], hrFlag);
			if (rc == SUCCESS)
				successCount++;
		}
	} else {
		rc = readFileFromPath(file, hrFlag);
		if (rc == SUCCESS)
			successCount++;
	}
	// if no good files read then count it as a failure
	if (successCount < 1) {
		prlog(PR_ERR, "No valid files to print, returning failure\n");
		return INVALID_FILE;
	}

	return SUCCESS;
}

/**
 *Does the appropriate read command depending on hrFlag on the file <path>/<var>/data
 *@param path , the path to the file with ending '/'
 *@param variable , variable name one of {db,dbx,KEK,PK,TS}
 *@param hrFlag, 1 for human readable 0 for raw data
 *@return SUCCESS or error number
 */
static int readFileFromSecVar(const char *path, const char *variable, int hrFlag)
{
	int extra = 10, rc;
	struct secvar *var = NULL;
	char *fullPath = NULL;

	fullPath = malloc(strlen(path) + strlen(variable) + extra);
	if (!fullPath) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	strcpy(fullPath, path);
	strcat(fullPath, variable);
	strcat(fullPath, "/data");

	rc = getSecVar(&var, variable, fullPath);

	free(fullPath);

	if (rc) {
		goto out;
	}
	if (hrFlag) {
		if (var->data_size == 0) {
			printf("%s is empty\n", var->key);
			rc = SUCCESS;
		} else if (strcmp(var->key, "TS") == 0)
			rc = readTS(var->data, var->data_size);
		else
			rc = printReadable(var->data, var->data_size, var->key);

		if (rc)
			prlog(PR_WARNING, "ERROR: Could not parse file, continuing...\n");
	} else {
		printRaw(var->data, var->data_size);
		rc = SUCCESS;
	}

out:
	dealloc_secvar(var);

	return rc;
}

/**
 *Does the appropriate read command depending on hrFlag on the file 
 *@param file , the path to the file 
 *@param hrFlag, 1 for human readable 0 for raw data
 *@return SUCCESS or error number
 */
static int readFileFromPath(const char *file, int hrFlag)
{
	int rc;
	size_t size = 0;
	char *c = NULL;
	c = getDataFromFile(file, &size);
	if (!c) {
		return INVALID_FILE;
	}
	if (hrFlag) {
		rc = printReadable(c, size, NULL);
		if (rc)
			prlog(PR_WARNING, "ERROR: Could not parse file\n");
		else
			rc = SUCCESS;
	} else {
		printRaw(c, size);
		rc = SUCCESS;
	}
	free(c);

	return rc;
}

/**
 *gets the secvar struct from a file
 *@param var , returned secvar
 *@param name , secure variable name {db,dbx,KEK,PK}
 *@param fullPath, file and path <path>/<varname>/data
 *NOTE: THIS IS ALLOCATING DATA AND var STILL NEEDS TO BE DEALLOCATED
 */
int getSecVar(struct secvar **var, const char *name, const char *fullPath)
{
	int rc, fptr;
	size_t size;
	ssize_t read_size;
	char *sizePath = NULL, *c = NULL;
	struct stat fileInfo;
	rc = isFile(fullPath);
	if (rc) {
		return rc;
	}
	sizePath = malloc(strlen(fullPath) + 1);
	if (!sizePath) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	// since we are reading from a secvar, it can be assumed it has a <var>/size file for more accurate size
	// fullPath currently holds <path>/<var>/data we are going to take off data and add size to get the desired file
	strcpy(sizePath, fullPath);
	// add null terminator so strncat works
	sizePath[strlen(sizePath) - strlen("data")] = '\0';
	strncat(sizePath, "size", strlen("size") + 1);
	rc = getSizeFromSizeFile(&size, sizePath);
	if (rc < 0) {
		prlog(PR_WARNING, "ERROR: Could not get size of variable, TIP: does %s exist?\n",
		      sizePath);
		rc = INVALID_FILE;
		free(sizePath);
		return rc;
	}
	free(sizePath);

	if (size == 0) {
		prlog(PR_WARNING, "Secure Variable has size of zero, (specified by size file)\n");
		/*rc = INVALID_FILE;
		return rc;*/
	}

	fptr = open(fullPath, O_RDONLY);
	if (fptr < 0) {
		prlog(PR_WARNING, "-----opening %s failed: %s-------\n\n", fullPath,
		      strerror(errno));
		return INVALID_FILE;
	}
	if (fstat(fptr, &fileInfo) < 0) {
		return INVALID_FILE;
	}
	// if file size is less than expeced size, error
	if (fileInfo.st_size < size) {
		prlog(PR_ERR, "ERROR: expected size (%zd) is less than actual size (%ld)\n", size,
		      fileInfo.st_size);
		return INVALID_FILE;
	}
	prlog(PR_NOTICE, "---opening %s is success: reading %zd bytes---- \n", fullPath, size);
	c = malloc(size);
	if (!c) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	read_size = read(fptr, c, size);
	if (read_size != size) {
		prlog(PR_ERR, "ERROR: did not read all data of %s in one go\n", fullPath);
		free(c);
		close(fptr);
		return INVALID_FILE;
	}
	close(fptr);
	if (!c) {
		prlog(PR_ERR, "ERROR: no data in file");
		return INVALID_FILE;
	}

	*var = new_secvar(name, strlen(name) + 1, c, size, 0);
	if (*var == NULL) {
		prlog(PR_ERR, "ERROR: Could not convert data to secvar\n");
		free(c);
		return INVALID_FILE;
	}
	free(c);

	return SUCCESS;
}

/*
 *prints human readable data in of ESL buffer
 *@param c , buffer containing ESL data
 *@param size , length of buffer
 *@param key, variable name {"db","dbx","KEK", "PK"} b/c dbx is a different format
 *@return SUCCESS or error number if failure
 */
static int printReadable(const char *c, size_t size, const char *key)
{
	ssize_t eslvarsize = size, cert_size;
	size_t eslsize = 0;
	int count = 0, offset = 0, rc;
	unsigned char *cert = NULL;
	EFI_SIGNATURE_LIST *sigList;
	crypto_x509 *x509 = NULL;

	while (eslvarsize > 0) {
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST)) {
			prlog(PR_ERR,
			      "ERROR: ESL has %zd bytes and is smaller than an ESL (%zd bytes), remaining data not parsed\n",
			      eslvarsize, sizeof(EFI_SIGNATURE_LIST));
			break;
		}
		// Get sig list
		sigList = get_esl_signature_list(c + offset, eslvarsize);
		// check size info is logical
		if (sigList->SignatureListSize > 0) {
			if ((sigList->SignatureSize <= 0 && sigList->SignatureHeaderSize <= 0) ||
			    sigList->SignatureListSize <
				    sigList->SignatureHeaderSize + sigList->SignatureSize) {
				/*printf("Sig List : %d , sig Header: %d, sig Size: %d\n",list.SignatureListSize,list.SignatureHeaderSize,list.SignatureSize);*/
				prlog(PR_ERR,
				      "ERROR: Sig List is not structured correctly, defined size and actual sizes are mismatched\n");
				break;
			}
		}
		if (sigList->SignatureListSize > eslvarsize ||
		    sigList->SignatureHeaderSize > eslvarsize ||
		    sigList->SignatureSize > eslvarsize) {
			prlog(PR_ERR,
			      "ERROR: Expected Sig List Size %d + Header size %d + Signature Size is %d larger than actual size %zd\n",
			      sigList->SignatureListSize, sigList->SignatureHeaderSize,
			      sigList->SignatureSize, eslvarsize);
			break;
		}
		eslsize = sigList->SignatureListSize;
		printESLInfo(sigList);
		// puts sig data in cert
		cert_size = get_esl_cert(c + offset, eslvarsize, (char **)&cert);
		if (cert_size <= 0) {
			prlog(PR_ERR, "\tERROR: Signature Size was too small, no data \n");
			break;
		}
		if (key && !strcmp(key, "dbx")) {
			printf("\tHash: ");
			printHex(cert, cert_size);
		} else {
			rc = parseX509(&x509, cert, (size_t)cert_size);
			if (rc)
				break;
			rc = printCertInfo(x509);
			if (rc)
				break;
			free(cert);
			cert = NULL;
			crypto_x509_free(x509);
			x509 = NULL;
		}

		count++;
		// we read all eslsize bytes so iterate to next esl
		offset += eslsize;
		// size left of total file
		eslvarsize -= eslsize;
	}
	printf("\tFound %d ESL's\n\n", count);
	if (x509)
		crypto_x509_free(x509);
	if (cert)
		free(cert);

	if (!count)
		return ESL_FAIL;

	return SUCCESS;
}

// prints info on ESL, nothing on ESL data
void printESLInfo(EFI_SIGNATURE_LIST *sigList)
{
	printf("\tESL SIG LIST SIZE: %d\n", sigList->SignatureListSize);
	printf("\tGUID is : ");
	printGuidSig(&sigList->SignatureType);
	printf("\tSignature type is: %s\n", getSigType(sigList->SignatureType));
}

// prints info on x509
int printCertInfo(crypto_x509 *x509)
{
	char *x509_info = NULL;
	int failures;

	x509_info = calloc(1, CERT_BUFFER_SIZE);
	if (!x509_info) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return CERT_FAIL;
	}
	// failures = number of bytes written, x509_info now has string of ascii data
	failures = crypto_x509_get_long_desc(x509_info, CERT_BUFFER_SIZE, "\t\t", x509);
	if (failures <= 0) {
		prlog(PR_ERR,
		      "\tERROR: Failed to get cert info, wrote %d bytes when getting info\n",
		      failures);
		return CERT_FAIL;
	}
	printf("\tFound certificate info:\n %s \n", x509_info);
	free(x509_info);

	return SUCCESS;
}

/**
 *prints all 16 byte timestamps into human readable of TS variable
 *@param data, timestamps of normal variables {pk, db, kek, dbx}
 *@param size, size of timestamp data, should be 16*4
 *@return SUCCESS or error depending if ts data is understandable
 */
static int readTS(const char *data, size_t size)
{
	struct efi_time *tmpStamp;
	// data length must have a timestamp for every variable besides the TS variable
	if (size != sizeof(struct efi_time) * (ARRAY_SIZE(variables) - 1)) {
		prlog(PR_ERR,
		      "ERROR: TS variable does not contain data on all the variables, expected %ld bytes of data, found %zd\n",
		      sizeof(struct efi_time) * (ARRAY_SIZE(variables) - 1), size);
		return INVALID_TIMESTAMP;
	}

	for (tmpStamp = (struct efi_time *)data; size > 0;
	     tmpStamp = (void *)tmpStamp + sizeof(struct efi_time),
	    size -= sizeof(struct efi_time)) {
		// print variable name
		printf("\t%s:\t",
		       variables[(ARRAY_SIZE(variables) - 1) - (size / sizeof(struct efi_time))]);
		printTimestamp(*tmpStamp);
	}

	return SUCCESS;
}

/**
 *finds format type given by guid
 *@param type uuid_t of guid of file
 *@return string of format type, "UNKNOWN" if type doesnt match any known formats
 */
const char *getSigType(const uuid_t type)
{
	// loop through all known hashes
	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
		if (uuid_equals(&type, hash_functions[i].guid))
			return hash_functions[i].name;
	}
	// try other known guids
	if (uuid_equals(&type, &EFI_CERT_X509_GUID))
		return "X509";
	else if (uuid_equals(&type, &EFI_CERT_RSA2048_GUID))
		return "RSA2048";
	else if (uuid_equals(&type, &EFI_CERT_TYPE_PKCS7_GUID))
		return "PKCS7";

	return "UNKNOWN";
}

/**
 *prints guid id
 *@param sig pointer to uuid_t
 */
void printGuidSig(const void *sig)
{
	const unsigned char *p = sig;
	for (int i = 0; i < 16; i++)
		printf("%02hhx", p[i]);
	printf("\n");
}

/*
 *gets the integer value from the ascii file "size"
 *@param size, the returned size of size file
 *@param path , lccation of "size" file
 *@return errror number if fail, <0
 */
static int getSizeFromSizeFile(size_t *returnSize, const char *path)
{
	int fptr, rc;
	ssize_t maxdigits = 8, read_size;
	char *c = NULL;

	struct stat fileInfo;
	fptr = open(path, O_RDONLY);
	if (fptr < 0) {
		prlog(PR_WARNING, "----opening %s failed : %s----\n", path, strerror(errno));
		return INVALID_FILE;
	}
	if (fstat(fptr, &fileInfo) < 0) {
		return INVALID_FILE;
	}
	if (fileInfo.st_size < maxdigits) {
		maxdigits = fileInfo.st_size;
	}
	// initiate string to empty, with null pointer
	c = calloc(maxdigits + 1, 1);
	if (!c) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		close(fptr);
		return ALLOC_FAIL;
	}
	prlog(PR_NOTICE, "----opening %s is success: reading %zd of %zd bytes----\n", path,
	      maxdigits, fileInfo.st_size);
	read_size = read(fptr, c, maxdigits);
	if (read_size <= 0) {
		prlog(PR_ERR, "ERROR: error reading %s\n", path);
		free(c);
		close(fptr);
		return INVALID_FILE;
	}

	close(fptr);
	// turn string into base 10 int
	*returnSize = strtol(c, NULL, 0);
	// strol likes to return zero if there is no conversion from string to int
	// so we need to differentiate an error from a file that actually contains 0
	if (*returnSize == 0 && c[0] != '0')
		rc = INVALID_FILE;
	else
		rc = SUCCESS;
	free(c);

	return rc;
}

struct command edk2_compat_command_table[] = {
	{ .name = "read", .func = performReadCommand },
	{ .name = "write", .func = performWriteCommand },
	{ .name = "validate", .func = performValidation },
	{ .name = "verify", .func = performVerificationCommand },
#ifndef NO_CRYPTO
	{ .name = "generate", .func = performGenerateCommand }
#endif
};
