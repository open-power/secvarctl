// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // for exit
#include <argp.h>
#include "secvar/crypto/crypto.h"
#include "host_svc_backend.h"

struct Arguments {
	int helpFlag;
	const char *inFile, *varName;
	char inForm;
};

static bool validate_hash(uuid_t type, size_t size);
static int parse_opt(int key, char *arg, struct argp_state *state);
static int validateSingularESL(size_t *bytesRead, const unsigned char *esl, size_t eslvarsize,
			       const char *varName);
static int validateCertStruct(crypto_x509 *x509, const char *varName);

enum fileTypes { AUTH_FILE = 'a', PKCS7_FILE = 'p', ESL_FILE = 'e', CERT_FILE = 'c' };

/*
 *called from main()
 *handles argument parsing for validate command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number
 */
int performValidation(int argc, char *argv[])
{
	unsigned char *buff = NULL;
	size_t size;
	int rc;
	struct Arguments args = {
		.helpFlag = 0, .inFile = NULL, .inForm = AUTH_FILE, .varName = NULL
	};
	// combine command and subcommand for usage/help messages
	argv[0] = "secvarctl -m host validate";

	struct argp_option options[] = {
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "pkcs7", 'p', 0, 0, "file is a PKCS7" },
		{ "esl", 'e', 0, 0, "file is an EFI Signature List (ESL)" },
		{ "cert", 'c', 0, 0, "file is an x509 cert (DER or PEM format)" },
		{ "auth", 'a', 0, 0,
		  "file is a properly generated authenticated variable, DEFAULT" },
		{ "dbx", 'x', 0, 0,
		  "file is for the dbx (allows for data to contain a hash not an x509), "
		  "Note: user still should specify the file type" },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = { options, parse_opt, "<FILE>",
			     "The purpose of this command is to help ensure that the "
			     "format of the file is correct"
			     " and is able to be parsed for data. NOTE: This command "
			     "mainly performs formatting checks, invalid "
			     "content/signatures can still exist"
			     " use 'secvarctl verify' to see if content and file "
			     "signature (if PKCS7/auth) are valid" };

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.helpFlag)
		goto out;

	buff = (unsigned char *)get_data_from_file(args.inFile, SIZE_MAX, &size);
	if (!buff) {
		prlog(PR_ERR, "ERROR: failed to get data from %s\n", args.inFile);
		rc = INVALID_FILE;
		goto out;
	}

	switch (args.inForm) {
	case CERT_FILE:
		rc = validateCert(buff, size, args.varName);
		break;
	case ESL_FILE:
		rc = validateESL(buff, size, args.varName);
		break;
	case PKCS7_FILE:
		rc = validatePKCS7(buff, size);
		break;
	case AUTH_FILE:
	default:
		rc = validateAuth(buff, size, args.varName);
		break;
	}
out:
	if (buff)
		free(buff);
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
	case 'v':
		verbose = PR_DEBUG;
		break;
	// set varname as dbx, important for validating ESL
	case 'x':
		args->varName = "dbx";
		break;
	case 'a':
		args->inForm = AUTH_FILE;
		break;
	case 'p':
		args->inForm = PKCS7_FILE;
		break;
	case 'e':
		args->inForm = ESL_FILE;
		break;
	case 'c':
		args->inForm = CERT_FILE;
		break;
	case ARGP_KEY_ARG:
		if (args->inFile == NULL)
			args->inFile = arg;
		break;
	case ARGP_KEY_SUCCESS:
		// check that all essential args are given and valid
		if (args->helpFlag)
			break;
		if (!args->inFile)
			prlog(PR_ERR, "ERROR: missing input file, see usage...\n");
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

/**
 *given an pointer to auth data, determines if containing fields, pkcs7,esl and certs are valid
 *@param authBuf pointer to auth file data
 *@param buflen length of buflen
 *@param key, variable name {"db","dbx","KEK", "PK"} b/c dbx is a different format
 *@return PKCS7_FAIL if validate validatePKCS7 returns PKCS7_FAIL
 *@return whatever is returned from validateESl
 */
int validateAuth(const unsigned char *authBuf, size_t buflen, const char *key)
{
	int rc;
	size_t authSize, pkcs7_size;
	const struct efi_variable_authentication_2 *auth =
		(struct efi_variable_authentication_2 *)authBuf;
	prlog(PR_INFO, "VALIDATING AUTH FILE:\n");

	if (!authBuf) {
		prlog(PR_ERR, "ERROR: No data for auth\n");
		return AUTH_FAIL;
	}

	if (buflen < sizeof(struct efi_variable_authentication_2)) {
		prlog(PR_ERR, "ERROR: auth file is too small to be valid auth file\n");
		return AUTH_FAIL;
	}

	// total size of auth and pkcs7 data (appended ESL not included)
	authSize = auth->auth_info.hdr.dw_length + sizeof(auth->timestamp);
	// if expected length is greater than the actual length or not a valid size, return fail
	if ((ssize_t)authSize <= 0 || authSize > buflen) {
		prlog(PR_ERR, "ERROR: Invalid auth size, expected %zd found %zd\n", authSize,
		      buflen);
		return AUTH_FAIL;
	}

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "\tGuid code is : ");
		printGuidSig(&auth->auth_info.cert_type);
	}
	// make sure guid is PKCS7
	if (strcmp(getSigType(auth->auth_info.cert_type), "PKCS7") != 0) {
		prlog(PR_ERR, "ERROR: Auth file does not contain PKCS7 guid\n");
		return AUTH_FAIL;
	}
	prlog(PR_INFO, "\tType: PKCS7\n");

	pkcs7_size = get_pkcs7_len(auth);
	// ensure pkcs7 size is valid length
	if ((ssize_t)pkcs7_size <= 0 || pkcs7_size > authSize) {
		prlog(PR_ERR, "ERROR: Invalid pkcs7 size %zd\n", pkcs7_size);
		return AUTH_FAIL;
	}

	prlog(PR_INFO,
	      "\tAuth File Size = %zd\n\t  -Auth/PKCS7 Data Size = %zd\n\t  -ESL Size = %zd\n",
	      buflen, authSize, buflen - authSize);

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "\tTimestamp: ");
		printTimestamp(auth->timestamp);
	}
	// validate pkcs7
	rc = validatePKCS7(auth->auth_info.cert_data, pkcs7_size);
	if (rc) {
		prlog(PR_ERR, "ERROR: PKCS7 FAILED\n");
		return rc;
	}

	// now validate appended ESL
	// if no ESL appended then print warning and continue, could be a delete key update
	if (authSize == buflen) {
		prlog(PR_WARNING, "WARNING: appended ESL is empty, (valid key reset file)...\n");
	} else {
		rc = validateESL(authBuf + authSize, buflen - authSize, key);
		if (rc) {
			prlog(PR_ERR, "ERROR: ESL FAILED\n");
			return rc;
		}
	}

	return rc;
}

/**
 *calls Nayna Jain's pkcs7 functions to validate the pkcs7 inside of the given auth struct
 *@param auth, pointer to auth struct data containing the pkcs7 in auth->auth_info.hdr.cert_data
 *@return PKCS7_FAIL if something goes wrong, SUCCESS if everything is correct
 */
int validatePKCS7(const unsigned char *cert_data, size_t len)
{
	void *pkcs7_cert = NULL;
	crypto_pkcs7 *pkcs7 = NULL;
	int rc = SUCCESS, cert_num = 0;

	prlog(PR_INFO, "VALIDATING PKCS7:\n");
	pkcs7 = crypto_pkcs7_parse_der(cert_data, len);
	if (!pkcs7) {
		rc = PKCS7_FAIL;
		goto out;
	}
	// make sure digest alg is sha246
	if (crypto_pkcs7_md_is_sha256(pkcs7) != 0) {
		prlog(PR_ERR, "ERROR: PKCS7 data is not signed with SHA256\n");
		rc = PKCS7_FAIL;
		goto out;
	}
	prlog(PR_INFO, "\tDigest Alg: SHA256\n");
	// print info on all siging certificates
	pkcs7_cert = crypto_pkcs7_get_signing_cert(pkcs7, cert_num);

	do {
		prlog(PR_INFO, "VALIDATING SIGNING CERTIFICATE:\n");
		// ensure first cert is not null
		if (pkcs7_cert)
			rc = validateCertStruct(pkcs7_cert, NULL);
		else
			rc = CERT_FAIL;
		if (rc) {
			prlog(PR_ERR, "ERROR: failure to parse x509 signing certificate\n");
			goto out;
		}

		cert_num++;
		pkcs7_cert = crypto_pkcs7_get_signing_cert(pkcs7, cert_num);
	} while (pkcs7_cert);
	rc = SUCCESS;

out:
	if (pkcs7) {
		crypto_pkcs7_free(pkcs7);
	}

	return rc;
}

/**
 *gets ESL from ESL data buffer and validates ESL fields and contained certificates, expects chained esl's each with one certificate
 *@param eslBuf pointer to ESL all ESL data, could be appended ESL's
 *@param buflen length of eslBuf
 *@param key, variable name {"db","dbx","KEK", "PK"} b/c dbx is a different format
 *@return ESL_FAIL if the less than one ESL could be validated
 *@return CERT_FAIL if validateCertificate fails
 *@return SUCCESS if at least one ESL validates
 */
int validateESL(const unsigned char *eslBuf, size_t buflen, const char *key)
{
	ssize_t eslvarsize = buflen;
	size_t eslsize = 0;
	int count = 0, offset = 0;
	prlog(PR_INFO, "VALIDATING ESL:\n");
	while (eslvarsize > 0) {
		int rc = validateSingularESL(&eslsize, eslBuf + offset, eslvarsize, key);
		// verify current esl to ensure it is a valid sigList, if 1 is returned break or error
		if (rc) {
			prlog(PR_ERR, "ERROR: Sig List #%d is not structured correctly\n", count);
			// if there is one good esl just leave the loop
			if (count)
				break;
			else
				return rc;
		}

		count++;
		// we read all eslsize bytes so iterate to next esl
		offset += eslsize;
		// size left of total file
		eslvarsize -= eslsize;
	}
	prlog(PR_INFO, "\tFound %d ESL's\n\n", count);
	if (!count)
		return ESL_FAIL;

	return SUCCESS;
}

/*
 *checks fields of the struct to ensure that the buffer was correctly into a sig list
 *for now, only checks that sizes of field are valid
 *@param bytesRead will be filled with the number of bytes read during this function (eslsize)
 *@param esl, pointer to start of esl
 *@param eslvarsize, remaining size of eslbuf
 *@param varName, variable name {"db","dbx","KEK", "PK"} b/c dbx is a different format
 *@return SUCCESS if cetificate and header info is valid, errno otherwise
 */
static int validateSingularESL(size_t *bytesRead, const unsigned char *esl, size_t eslvarsize,
			       const char *varName)
{
	ssize_t cert_size;
	int rc;
	size_t eslsize;
	unsigned char *cert = NULL;
	EFI_SIGNATURE_LIST *sigList;

	*bytesRead = 0;
	// verify struct to ensure it is a valid sigList, if 1 is returned break
	if (eslvarsize < sizeof(EFI_SIGNATURE_LIST)) {
		prlog(PR_ERR,
		      "ERROR: ESL has %zd bytes and is smaller than an ESL (%zd bytes), remaining data not parsed\n",
		      eslvarsize, sizeof(EFI_SIGNATURE_LIST));
		return ESL_FAIL;
	}
	// Get sig list
	sigList = get_esl_signature_list((const char *)esl, eslvarsize);
	// check size info is logical
	if (sigList->SignatureListSize > 0) {
		if ((sigList->SignatureSize <= 0 && sigList->SignatureHeaderSize <= 0) ||
		    sigList->SignatureListSize <
			    sigList->SignatureHeaderSize + sigList->SignatureSize) {
			/*printf("Sig List : %d , sig Header: %d, sig Size: %d\n",list.SignatureListSize,list.SignatureHeaderSize,list.SignatureSize);*/
			prlog(PR_ERR, "ERROR: Sig List is not structured correctly, defined "
				      "size and actual sizes are mismatched\n");
			return ESL_FAIL;
		}
	}
	if (verbose >= PR_INFO)
		printESLInfo(sigList);
	if (sigList->SignatureListSize > eslvarsize || sigList->SignatureHeaderSize > eslvarsize ||
	    sigList->SignatureSize > eslvarsize) {
		prlog(PR_ERR,
		      "ERROR: Expected Sig List Size %d + Header size %d + Signature Size is %d larger than actual size %zd\n",
		      sigList->SignatureListSize, sigList->SignatureHeaderSize,
		      sigList->SignatureSize, eslvarsize);
		return ESL_FAIL;
	} else if ((int)sigList->SignatureListSize <= 0) {
		prlog(PR_ERR, "ERROR: Sig List has incorrect size %d \n",
		      sigList->SignatureListSize);
		return ESL_FAIL;
	}
	eslsize = sigList->SignatureListSize;
	// if eslsize is greater than remaining buffer size, error
	if (eslsize > eslvarsize) {
		prlog(PR_ERR,
		      "ERROR: Sig list size is greater than remaining data size: %zd > %zd\n",
		      eslsize, eslvarsize);
		return ESL_FAIL;
	}

	// if dbx expect some type of SHA
	if (varName && !strcmp(varName, "dbx")) {
		if (strncmp(getSigType(sigList->SignatureType), "SHA", 3) != 0) {
			prlog(PR_ERR,
			      "ERROR: dbx has wrong guid type, expected a SHA function found %s\n",
			      getSigType(sigList->SignatureType));
			return ESL_FAIL;
		}
	}
	// else expect x509
	else if (strcmp(getSigType(sigList->SignatureType), "X509") != 0) {
		prlog(PR_ERR, "ERROR: Sig list is not X509 format\n");
		return ESL_FAIL;
	}
	// get certificate
	cert_size = get_esl_cert((const char *)esl, eslvarsize,
				 (char **)&cert); // puts sig data in cert
	if (cert_size <= 0) {
		prlog(PR_ERR, "\tERROR: Signature Size was too small, no data \n");
		return ESL_FAIL;
	}
	// if dbx, make sure it is 32 bytes if SHA256, 64 for SHA512 etc, and skip x509 validation
	if (varName && !strcmp(varName, "dbx")) {
		if (!validate_hash(sigList->SignatureType, cert_size)) {
			prlog(PR_ERR,
			      "ERROR: dbx data of type %s and number of bytes %zd, is invalid\n",
			      getSigType(sigList->SignatureType), cert_size);
			rc = HASH_FAIL;
		} else
			rc = SUCCESS;

		if (verbose >= PR_INFO) {
			prlog(PR_INFO, "\tHash: ");
			print_hex(cert, cert_size);
		}
	} else {
		rc = validateCert(cert, cert_size, varName);
	}
	free(cert);
	*bytesRead = eslsize;

	return rc;
}

// from edk2-compat-process.c
static bool validate_hash(uuid_t type, size_t size)
{
	// loop through all known hashes
	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
		if (uuid_equals(&type, hash_functions[i].guid) && (size == hash_functions[i].size))
			return true;
	}

	return false;
}

/**
 *parses x509 certficate buffer into certificate and verifies it
 *@param certBuf pointer to certificate data
 *@param buflen length of certBuf
 *@param varName,  variable name {"db","dbx","KEK", "PK"} b/c db allows for any RSA len, if NULL expect RSA-2048
 *@return CERT_FAIL if certificate had incorrect data
 *@return SUCCESS if certificate is valid
 */
int validateCert(const unsigned char *certBuf, size_t buflen, const char *varName)
{
	int rc;
	crypto_x509 *x509 = NULL;

	if (buflen == 0) {
		prlog(PR_ERR, "ERROR: Length %zd is invalid\n", buflen);
		return CERT_FAIL;
	}
	rc = parseX509(&x509, certBuf, buflen);
	if (rc) {
		rc = CERT_FAIL;
		goto out;
	}

	rc = validateCertStruct(x509, varName);

out:
	if (x509)
		crypto_x509_free(x509);

	return rc;
}

/**
 *takes a pointer to the x509 struct and validates the content for secvar specific requirements
 *@param x509, a pointer to either an openssl or a mbedtls x509 struct, already filled with data
 *@param varName ,  variable name {"db","dbx","KEK", "PK"} b/c db allows for any RSA len, if NULL expect RSA-2048
 *@return SUCCESS or errno depending on if x509 is valid
 */
static int validateCertStruct(crypto_x509 *x509, const char *varName)
{
	int rc, len, version;
	// check raw cert data has data
	len = crypto_x509_get_der_len(x509);
	if (len < 0) {
		prlog(PR_ERR, "ERROR: Could not read X509 length in DER\n");
		return CERT_FAIL;
	}
	if (len == 0) {
		prlog(PR_ERR, "ERROR: X509 has no data\n");
		return CERT_FAIL;
	}
	// check raw certificate body has TBSCertificate data
	len = crypto_x509_get_tbs_der_len(x509);
	if (len < 0) {
		prlog(PR_ERR, "ERROR: Could not read length of X509 TBS Certificate\n");
		return CERT_FAIL;
	}
	if (len == 0) {
		prlog(PR_ERR, "ERROR: X509 TBS Certificate has no data\n");
		return CERT_FAIL;
	}
	// check if version is something other than 1,2,3
	version = crypto_x509_get_version(x509);

	if (version < 1 || version > 3) {
		prlog(PR_ERR, "ERROR: X509 version %d is not valid\n", version);
		return CERT_FAIL;
	}
	// if public key type is not RSA, then quit (example failures: DSA, ECDSA, RSA_PCC)
	rc = crypto_x509_is_RSA(x509);
	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_ERR,
		      "ERROR: public key type not supported, expected RSA, found type ID %d (defined by crypto lib)\n",
		      rc);
		return CERT_FAIL;
	}

	len = crypto_x509_get_sig_len(x509);
	// if sig doesnt have data
	if (len <= 0) {
		prlog(PR_ERR, "ERROR: X509 has no signature data\n");
		return CERT_FAIL;
	}

	// if x509 for db then signature can be RSA 4096 or other (since it won't be signing anything else)
	// this addresses OS's that release certificates with non RSA-2048 (ex: RHEL)
	if (varName == NULL || strncmp(varName, "db", strlen(varName))) {
		if (crypto_x509_md_is_sha256(x509) || crypto_x509_oid_is_pkcs1_sha256(x509) ||
		    crypto_x509_get_pk_bit_len(x509) != 2048) {
			// calloc to ensure null terminator
			char *x509_info = calloc(CERT_BUFFER_SIZE, 1);
			if (!x509_info) {
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				return CERT_FAIL;
			}
			crypto_x509_get_short_info(x509, x509_info, CERT_BUFFER_SIZE);
			prlog(PR_ERR,
			      "ERROR: Wanted x509 with RSA 2048 and SHA-256. Discovered %s with signature length %d bits\n",
			      x509_info, crypto_x509_get_pk_bit_len(x509));
			if (x509_info)
				free(x509_info);
			return CERT_FAIL;
		}
	}

	// This part is to print out certificate info
	if (verbose >= PR_INFO) {
		rc = printCertInfo(x509);
		if (rc) {
			return CERT_FAIL;
		}
	}

	// if made it this far then return success
	return SUCCESS;
}

#ifdef SECVAR_CRYPTO_WRITE_FUNC
/*
 *This function is just an extension of parseX509
 *It allows us to declare new variables at the start of the function rather than the middle
 *It is dependent on crypto_convert_pem_to_der which is dependent on SECVAR_CRYPTO_WRITE_FUNC
 */
static crypto_x509 *parseX509_PEM(const unsigned char *data_pem, size_t data_len)
{
	unsigned char *generatedDER = NULL;
	size_t generatedDERSize;
	crypto_x509 *x509 = NULL;
	if (crypto_convert_pem_to_der(data_pem, data_len, &generatedDER, &generatedDERSize)) {
		prlog(PR_ERR, "ERROR: Failed to parse file from is DER to PEM\n");
		return NULL;
	}
	// if success then try to parse into x509 struct again
	x509 = crypto_x509_parse_der(generatedDER, generatedDERSize);
	if (generatedDER)
		free(generatedDER);

	return x509;
}
#endif

/**
 *parses x509 certficate buffer (PEM or DER) into certificate struct
 *@param x509, returned pointer to address of x509,
 *@param certBuf pointer to certificate data
 *@param buflen length of certBuf
 *@return CERT_FAIL if certificate cant be parsed
 *@return SUCCESS if certificate is valid
 *NOTE: Remember to unallocate the returned x509 struct!
 */
int parseX509(crypto_x509 **x509, const unsigned char *certBuf, size_t buflen)
{
	if ((ssize_t)buflen <= 0) {
		prlog(PR_ERR, "ERROR: Certificate has invalid length %zd, cannot validate\n",
		      buflen);
		return CERT_FAIL;
	}
	// returns x509 struct on success or NULL on fail
	*x509 = crypto_x509_parse_der(certBuf, buflen);
	if (*x509)
		return SUCCESS;
/*
 *if here, parsing cert in der failed
 *check if we have compiled with pkcs7_write functions
 *if so we can try to convert pem to der and try again
 */
#ifdef SECVAR_CRYPTO_WRITE_FUNC
	prlog(PR_INFO, "Failed to parse x509 as DER, trying PEM...\n");
	// if failed, maybe input is PEM and so try converting PEM to DER, if conversion fails then we know it was DER and it failed
	*x509 = parseX509_PEM(certBuf, buflen);
	if (!x509) {
		prlog(PR_ERR, "ERROR: Failed to parse x509 (tried DER and PEM formats). \n");
		return CERT_FAIL;
	}
#else
	prlog(PR_INFO, "ERROR: Failed to parse x509. Make sure file is in DER not PEM\n");
	return CERT_FAIL;
#endif

	return SUCCESS;
}

static bool timestamp_is_empty(char *ts_ptr)
{
	for (size_t i = 0; i < sizeof(struct efi_time); i++) {
		if (ts_ptr[i] != 0x00)
			return false;
	}

	return true;
}

/**
 *determines if Timestamp variable is in the right format
 *@param data, timestamps of normal variables {pk, db, kek, dbx}
 *@param size, size of timestamp data, should be 16*4
 *@return SUCCESS or error depending if ts data is understandable
 */
int validateTS(const unsigned char *data, size_t size)
{
	int rc;
	char *pointer;
	struct efi_time *tmpStamp;
	// data length must have a timestamp for every variable besides the TS variable
	if (size != sizeof(struct efi_time) * (ARRAY_SIZE(variables) - 1)) {
		prlog(PR_ERR,
		      "ERROR: TS variable does not contain data on all the variables, expected %ld bytes of data, found %zd\n",
		      sizeof(struct efi_time) * (ARRAY_SIZE(variables) - 1), size);
		return INVALID_TIMESTAMP;
	}
	for (pointer = (char *)data; size > 0;
	     pointer += sizeof(struct efi_time), size -= sizeof(struct efi_time)) {
		tmpStamp = (struct efi_time *)pointer;
		// an empty TS is valid, means uninitialized
		if (timestamp_is_empty(pointer))
			rc = SUCCESS;
		else
			rc = validateTime(tmpStamp);
		if (rc)
			goto out;
		if (verbose >= PR_INFO) {
			prlog(PR_INFO, "\t%s:\t",
			      variables[(ARRAY_SIZE(variables) - 1) -
					(size / sizeof(struct efi_time))]);
			printTimestamp(*tmpStamp);
		}
	}
	rc = SUCCESS;
out:
	if (rc) {
		prlog(PR_ERR, "ERROR: Timestamp contains invalid data : ");
		printTimestamp(*tmpStamp);
	}

	return rc;
}

/*
 *ensures that efi_time values are  in correct ranges
 *@param time , pointer to an efi_time struct
 *return SUCCESS or INVALID_TIMESTAMP if not valid
 */
int validateTime(struct efi_time *time)
{
	if (time->year < 1900 || time->year > 9999) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for year: %d\n", time->year);
		return INVALID_TIMESTAMP;
	}

	if (time->month < 1 || time->month > 12) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for month: %d\n", time->month);
		return INVALID_TIMESTAMP;
	}

	if (time->day < 1 || time->day > 31) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for day: %d\n", time->day);
		return INVALID_TIMESTAMP;
	}

	if (time->hour < 0 || time->hour > 23) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for hour: %d\n", time->hour);
		return INVALID_TIMESTAMP;
	}

	if (time->minute < 0 || time->minute > 59) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for minute: %d\n", time->minute);
		return INVALID_TIMESTAMP;
	}

	if (time->second < 0 || time->second > 60) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for second: %d\n", time->second);
		return INVALID_TIMESTAMP;
	}

	return SUCCESS;
}

void printTimestamp(struct efi_time t)
{
	// NOTE: if auth is made with sign-efi-sig-list, year will be actual year+1 (see https:// blog.hansenpartnership.com/updating-pk-kek-db-and-x-in-user-mode/),
	// also month could be one less bc months are 0-11 not 1-12
	printf("%04d-%02d-%02d %02d:%02d:%02d UTC\n", t.year, t.month, t.day, t.hour, t.minute,
	       t.second);
}
