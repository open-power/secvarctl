// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>// for exit
#include <mbedtls/pk_internal.h> // for validating cert pk data
#include "../../external/extraMbedtls/include/pkcs7.h"
#include "include/edk2-svc.h"// import last!!

struct Arguments {
	int helpFlag;
	const char *inFile, *varName;
	char inForm;
}; 

static void usage();
static void help();
static bool validate_hash(uuid_t type, size_t size);
static int parseArgs(int argc, char *argv[], struct Arguments *args);
static int validateSingularESL(size_t* bytesRead, const unsigned char* esl, size_t eslvarsize, const char *varName);



enum fileTypes{
	AUTH = 'a',
	PKCS7 = 'p',
	ESL = 'e',
	CERT = 'c'
};

/*
 *called from main()
 *handles argument parsing for validate command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int performValidation(int argc, char* argv[])
{
	unsigned char *buff = NULL;
	size_t size;
	int rc; 
	struct Arguments args = {	
		.helpFlag = 0, 
		.inFile = NULL, .inForm = AUTH, .varName = NULL
	};

	rc = parseArgs(argc, argv, &args);
	if (rc || args.helpFlag)
		goto out;
	

	if (!args.inFile) {
		usage();
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	buff = (unsigned char *)getDataFromFile(args.inFile, &size);
	if (!buff) {
		prlog(PR_ERR,"ERROR: failed to get data from %s\n", args.inFile);
		rc = INVALID_FILE;
		goto out;
	}

	switch (args.inForm) {
		case CERT:
			rc = validateCert(buff, size, args.varName);
			break;
		case ESL:
			rc = validateESL(buff, size, args.varName);
			break;
		case PKCS7:
			rc = validatePKCS7(buff,size);
			break;
		case AUTH:
		default:
			rc = validateAuth(buff, size, args.varName);
			break;
	}
out:
	if (rc) 
		printf("RESULT: Failure\n");
	else 
		printf("RESULT: SUCCESS\n");
	if (buff) 
		free(buff);
	
	return rc;
}

static void usage() {
	printf("USAGE:\n\t $ secvarctl validate [OPTIONS] <file>"
		"\n\tOPTIONS:"
		"\n\t\t--help/--usage"
		"\n\t\t-v\t\tverbose, print process info"
		"\n\t\t-x\t\tfile is for the dbx, allows data to be a hash not an x509,\n\t"
		"\t\t\tNOTE: user still needs to specify file type"
		"\n\t\t-p\t\tfile is a PKCS7\n\t\t-e\t\tfile is an ESL"
		"\n\t\t-c\t\tfile is a x509 cert (DER or PEM format)"
		"\n\t\t-a\t\tfile is a signed authenticated file containg a PKCS7 and appended ESL\n\t"
		"\t\t\tDEFAULT\n");
}

static void help() {
	printf( "HELP:\n\t"
		"This purpose of this command is to help ensure that the format of the file is correct\n\t"
		"and is able to be parsed for data. NOTE: This command does little data content checks,\n"
		"\tuse 'secvarctl verify' to see if content and file signature (if PKCS7/auth) is valid\n");
	usage();
}

/**
 *@param argv , array of command line arguments
 *@param argc, length of argv
 *@param args, struct that will be filled with data from argv
 *@return success or errno
 */
static int parseArgs( int argc, char *argv[], struct Arguments *args) {
	int rc = SUCCESS;
	for (int i = 0; i < argc; i++) {
		if (argv[i][0] != '-') {
			args->inFile = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--usage")) {
			usage();
			args->helpFlag = 1;
			goto out;
		}
		else if (!strcmp(argv[i], "--help")) {
			help();
			args->helpFlag = 1;
			goto out;
		}
		switch (argv[i][1]) {
		// set verbose flag
			case 'v': 
				verbose = PR_DEBUG; 
				break;
		// set varname as dbx, important for validating ESL
			case 'x':
				args->varName = "dbx";
				break;
			case 'a':
				args->inForm = AUTH;
				break;
			case 'p':
				args->inForm = PKCS7;
				break;
			case 'e':
				args->inForm = ESL;
				break;
			case 'c':
				args->inForm = CERT;
				break;
			default:
				prlog(PR_ERR, "ERROR: Unknown argument: %s\n", argv[i]);
				rc = ARG_PARSE_FAIL;
				goto out;
		}
		
	}
		
out:
	if (rc) {
		prlog(PR_ERR, "Failed during argument parsing\n");
		usage();
	}

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
	const struct efi_variable_authentication_2 *auth = (struct efi_variable_authentication_2 *)authBuf;
	prlog(PR_INFO, "VALIDATING AUTH FILE:\n");

	if (!authBuf) {
		prlog(PR_ERR, "ERROR: No data for auth\n");
		return AUTH_FAIL;
	}

	if (buflen < sizeof(struct efi_variable_authentication_2)) {
		prlog(PR_ERR,"ERROR: auth file is too small to be valid auth file\n");
		return AUTH_FAIL;
	}

	// total size of auth and pkcs7 data (appended ESL not included)
	authSize = auth->auth_info.hdr.dw_length + sizeof(auth->timestamp);
	// if expected length is greater than the actual length or not a valid size, return fail
	if ((ssize_t)authSize <= 0 || authSize > buflen) { 
		prlog(PR_ERR,"ERROR: Invalid auth size, expected %zd found %zd\n", authSize, buflen);
		return AUTH_FAIL;
	}

	if (verbose >= PR_INFO) {
		prlog(PR_INFO,"\tGuid code is : ");			
		printGuidSig(&auth->auth_info.cert_type);
	}
	// make sure guid is PKCS7
	if (strcmp(getSigType(auth->auth_info.cert_type), "PKCS7") != 0) {
		prlog(PR_ERR,"ERROR: Auth file does not contain PKCS7 guid\n");
		return AUTH_FAIL;
	}
	prlog(PR_INFO, "\tType: PKCS7\n");

	pkcs7_size = get_pkcs7_len(auth);
	// ensure pkcs7 size is valid length
	if ((ssize_t)pkcs7_size <= 0 || pkcs7_size > authSize) { 
		prlog(PR_ERR,"ERROR: Invalid pkcs7 size %zd\n", pkcs7_size);
		return AUTH_FAIL;
	}
	
	prlog(PR_INFO, "\tAuth File Size = %zd\n\t  -Auth/PKCS7 Data Size = %zd\n\t  -ESL Size = %zd\n", buflen, authSize, buflen - authSize);

	if( verbose >= PR_INFO){
		prlog(PR_INFO, "\tTimestamp: ");
		printTimestamp(auth->timestamp);
	}
	// validate pkcs7
	rc = validatePKCS7(auth->auth_info.cert_data, pkcs7_size);
	if (rc) {
		prlog(PR_ERR,"ERROR: PKCS7 FAILED\n");
		return rc;
	}
	
	// now validate appended ESL 
	// if no ESL appended then print warning and continue, could be a delete key update
	if (authSize == buflen) {
		prlog(PR_WARNING, "WARNING: appended ESL is empty, (valid key reset file)...\n");
	}
	else {
		rc = validateESL(authBuf + authSize, buflen - authSize, key);
		if (rc) {
			prlog(PR_ERR,"ERROR: ESL FAILED\n");
			return rc;
		}
	}
	
	return rc;	
}

// inspired by secvar/backend/edk2-compat-process.c by Nayna Jain
/**
 *returns only size of auth->auth_info.hdr.cert_data
 *auth->auth_info.hdr.dw_length is size of .cert_data and .hdr so we remove .hdr sizes
 */
 size_t get_pkcs7_len(const struct efi_variable_authentication_2 *auth)
{
	uint32_t dw_length;
	size_t size;
	if (auth == NULL) {
		return 0;
	}
	dw_length = auth->auth_info.hdr.dw_length;
	size = dw_length - (sizeof(auth->auth_info.hdr.dw_length)
	                    + sizeof(auth->auth_info.hdr.w_revision)
	                    + sizeof(auth->auth_info.hdr.w_certificate_type)
	                    + sizeof(auth->auth_info.cert_type));
	
	return size;
}

/**
 *calls Nayna Jain's pkcs7 functions to validate the pkcs7 inside of the given auth struct
 *@param auth, pointer to auth struct data containing the pkcs7 in auth->auth_info.hdr.cert_data
 *@return PKCS7_FAIL if something goes wrong, SUCCESS if everything is correct
 */
int validatePKCS7(const unsigned char *cert_data, size_t len) 
{
	mbedtls_x509_crt *pkcs7cert = NULL;
	mbedtls_pkcs7 *pkcs7 = NULL;
	int rc;

	prlog(PR_INFO, "VALIDATING PKCS7:\n");
	pkcs7 = malloc(sizeof(struct mbedtls_pkcs7));
	if (!pkcs7){
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	mbedtls_pkcs7_init(pkcs7);
	rc = mbedtls_pkcs7_parse_der(cert_data, len, pkcs7);
	if (rc != MBEDTLS_PKCS7_SIGNED_DATA) {	// if pkcs7 parsing fails, then try new signed data format 
			prlog(PR_ERR, "ERROR: parsing pkcs7 failed mbedtls error #%04x\n", rc);
			goto out;	
	}
	// make sure digest alg is sha246
	if (memcmp(pkcs7->signed_data.digest_alg_identifiers.p, MBEDTLS_OID_DIGEST_ALG_SHA256, strlen(MBEDTLS_OID_DIGEST_ALG_SHA256) )!= 0) {
		prlog(PR_ERR, "ERROR: PKCS7 data is not signed with SHA256\n");
		goto out;
	}
	prlog(PR_INFO, "\tDigest Alg: SHA256\n");
	// print info on all siging certificates
	pkcs7cert = &pkcs7->signed_data.certs;
	do {
		prlog(PR_INFO, "VALIDATING SIGNING CERTIFIATE:\n");
		rc = validateCert(pkcs7cert->raw.p, pkcs7cert->raw.len, NULL);
		if (rc) {
			prlog(PR_ERR,"ERROR: failure to parse x509 signing certificate\n");
			goto out;
		}
		
		pkcs7cert = pkcs7cert->next;
	}
	while (pkcs7cert);
	mbedtls_pkcs7_free(pkcs7);
	free(pkcs7);
	return SUCCESS;

out:
	mbedtls_pkcs7_free(pkcs7);
	free(pkcs7);
	pkcs7 = NULL;
	
	return PKCS7_FAIL;
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
	size_t  eslsize = 0;
	int count = 0, offset = 0, rc;
	prlog(PR_INFO, "VALIDATING ESL:\n");
	while (eslvarsize > 0) {
		rc = validateSingularESL(&eslsize, eslBuf + offset, eslvarsize, key);
		// verify current esl to ensure it is a valid sigList, if 1 is returned break or error
		if (rc) { 
			prlog(PR_ERR, "ERROR: Sig List #%d is not structured correctly\n", count);
			// if there is one good esl just leave the loop
			if (count) break;	
			else return rc;
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
static int validateSingularESL(size_t* bytesRead, const unsigned char* esl, size_t eslvarsize, const char *varName) 
{
	ssize_t cert_size;
	int rc;
	size_t eslsize;
	unsigned char *cert = NULL;
	EFI_SIGNATURE_LIST *sigList;
	
	*bytesRead = 0;
	// verify struct to ensure it is a valid sigList, if 1 is returned break
	if (eslvarsize < sizeof(EFI_SIGNATURE_LIST)) { 
		prlog(PR_ERR, "ERROR: ESL has %zd bytes and is smaller than an ESL (%zd bytes), remaining data not parsed\n", eslvarsize, sizeof(EFI_SIGNATURE_LIST));
		return ESL_FAIL;
	}
	// Get sig list
	sigList = get_esl_signature_list((const char *)esl, eslvarsize);
	// check size info is logical 
	if (sigList->SignatureListSize > 0) {
		if ((sigList->SignatureSize <= 0 && sigList->SignatureHeaderSize <= 0) 
			|| sigList->SignatureListSize < sigList->SignatureHeaderSize + sigList->SignatureSize) {
			/*printf("Sig List : %d , sig Header: %d, sig Size: %d\n",list.SignatureListSize,list.SignatureHeaderSize,list.SignatureSize);*/
			prlog(PR_ERR,"ERROR: Sig List is not structured correctly, defined size and actual sizes are mismatched\n");
			return ESL_FAIL;
		}	
	}
	if (verbose >= PR_INFO) printESLInfo(sigList);
	if (sigList->SignatureListSize  > eslvarsize || sigList->SignatureHeaderSize > eslvarsize || sigList->SignatureSize > eslvarsize) {
		prlog(PR_ERR, "ERROR: Expected Sig List Size %d + Header size %d + Signature Size is %d larger than actual size %zd\n", sigList->SignatureListSize, sigList->SignatureHeaderSize, sigList->SignatureSize, eslvarsize);
		return ESL_FAIL;
	}
	else if ((int)sigList->SignatureListSize <= 0){
		prlog (PR_ERR, "ERROR: Sig List has incorrect size %d \n", sigList->SignatureListSize);
		return ESL_FAIL;
	}
	eslsize = sigList->SignatureListSize;
	// if eslsize is greater than remaining buffer size, error
	if (eslsize > eslvarsize) {
		prlog(PR_ERR, "ERROR: Sig list size is greater than remaining data size: %zd > %zd\n", eslsize, eslvarsize);
		return ESL_FAIL;
	}
	
	// if dbx expect some type of SHA
	if (varName && !strcmp(varName, "dbx")) {
		if ( strncmp(getSigType(sigList->SignatureType), "SHA", 3) != 0 ){
			prlog(PR_ERR, "ERROR: dbx has wrong guid type, expected a SHA function found %s\n", getSigType(sigList->SignatureType));
			return ESL_FAIL;
		}
	}
	// else expect x509
	else if (strcmp(getSigType(sigList->SignatureType), "X509") != 0) {
		prlog(PR_ERR, "ERROR: Sig list is not X509 format\n");
		return ESL_FAIL;
	}
	// get certificate
	cert_size = get_esl_cert((const char *)esl, sigList, (char **)&cert); // puts sig data in cert
	if (cert_size <= 0) {
		prlog(PR_ERR, "\tERROR: Signature Size was too small, no data \n");
		return ESL_FAIL;
	}
	// if dbx, make sure it is 32 bytes if SHA256, 64 for SHA512 etc, and skip x509 validation
	if (varName && !strcmp(varName, "dbx")) {
		if ( !validate_hash(sigList->SignatureType, cert_size)){
			prlog(PR_ERR, "ERROR: dbx data of type %s and number of bytes %zd, is invalid\n", getSigType(sigList->SignatureType), cert_size);
			rc = HASH_FAIL;
		}
		else rc = SUCCESS;

		if (verbose >= PR_INFO) {
			prlog(PR_INFO, "\tHash: ");
			printHex(cert, cert_size);
		}
	}
	else {
		rc = validateCert(cert, cert_size, varName);
	}
	free(cert);
	*bytesRead = eslsize;

	return rc;
}

// from edk2-compat-process.c
static bool validate_hash(uuid_t type, size_t size)
{
	//loop through all known hashes
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
	char *x509_info = NULL;
	mbedtls_x509_crt *x509;
	int rc;

	if (buflen == 0) {
		prlog(PR_ERR, "ERROR: Length %zd is invalid\n", buflen);
		return CERT_FAIL;
	}
	x509 = malloc(sizeof(*x509));
	if (!x509){
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	rc = parseX509(x509, certBuf, buflen);
	if (rc) {
		rc = CERT_FAIL;
		goto out;
	}
	// check raw cert data has data
	if (x509->raw.len <= 0) {	
		prlog(PR_ERR, "ERROR: X509 has no data\n");
		rc = CERT_FAIL;
		goto out;
	}
	// check raw certificate body has data type defined
	if (x509->tbs.len <= 0) { 
		prlog(PR_ERR,"ERROR: X509 certificate has no data\n");
		rc = CERT_FAIL;
		goto out;
	}
	// check if version is something other than 1,2,3
	if (x509->version < 1 || x509->version > 3) { 
		prlog(PR_ERR,"ERROR: X509 version %d is not valid\n", x509->version );
		rc = CERT_FAIL;
		goto out;
	}
	// if public key type is not in range of asn1 pk type enum
	if ((int)(x509->pk.pk_info->type) < 0 || x509->pk.pk_info->type > 6 ) { 
		prlog(PR_ERR,"ERROR: public key type not supported\n");
		rc = CERT_FAIL;
		goto out;
	}
	// if sig doesnt have data
	if (x509->sig.len <= 0) { 
		prlog(PR_ERR, "ERROR: X509 has no signature data\n");
		rc = CERT_FAIL;
		goto out;
	}
	
	//if x509 for db then signature can be RSA 4096 or other (since it won't be signing anything else)
	//this addresses OS's that release certificates with non RSA-2048 (ex: RHEL)
	if (varName == NULL || strncmp(varName, "db", strlen(varName))) {
		if ( x509->sig_md != MBEDTLS_MD_SHA256 
		|| strncmp((const char *)x509->sig_oid.p, MBEDTLS_OID_PKCS1_SHA256, x509->sig_oid.len) 
		|| (int) mbedtls_pk_get_bitlen( &x509->pk ) != 2048 
		|| x509->sig.len != 256) { 
			x509_info = malloc(CERT_BUFFER_SIZE);
			if (!x509_info){
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				rc = CERT_FAIL;
				goto out;
			}
			rc = mbedtls_x509_sig_alg_gets(x509_info, CERT_BUFFER_SIZE, &x509->sig_oid,
                       x509->sig_pk, x509->sig_md, x509->sig_opts );
			prlog(PR_ERR,"ERROR: Wanted Cert with RSA 2048 and SHA-256. Discovered %s with key size %d and signature length %zd\n", x509_info, (int)mbedtls_pk_get_bitlen( &x509->pk ), x509->sig.len);
			free(x509_info);
			goto out;
		}
	}
	
	// This part is to print out certificate info
	if (verbose >= PR_INFO) {
		rc = printCertInfo(x509);
		if (rc) {
			rc = CERT_FAIL;
			goto out;
		}
	}

out:
	mbedtls_x509_crt_free(x509);
	if (x509) 
		free(x509);

	return rc;
}

/**
 *parses x509 certficate buffer (PEM or DER) into certificate struct
 *@param x509, returned x509, expected to be allocated mbedtls_x509_crt struct,
 *@param certBuf pointer to certificate data
 *@param buflen length of certBuf
 *@return CERT_FAIL if certificate cant be parsed
 *@return SUCCESS if certificate is valid
 */
int parseX509(mbedtls_x509_crt *x509, const unsigned char *certBuf, size_t buflen) 
{
	int failures;
	unsigned char *generatedDER = NULL;
	size_t generatedDERSize;
	if ((ssize_t)buflen <= 0) {
		prlog(PR_ERR, "ERROR: Certificate has invalid length %zd, cannot validate\n", buflen);
		return CERT_FAIL;
	}
	mbedtls_x509_crt_init(x509);
	// puts cert data into x509_Crt struct and returns number of failed parses
	failures = mbedtls_x509_crt_parse(x509, certBuf, buflen); 
	if (failures) {
		prlog(PR_INFO, "Failed to parse cert as DER mbedtls err#%d, trying PEM...\n", failures);
		// if failed, maybe input is PEM and so try converting PEM to DER, if conversion fails then we know it was DER and it failed
		if (convert_pem_to_der(certBuf, buflen, &generatedDER, &generatedDERSize)) {
			prlog(PR_ERR, "Parsing x509 as PEM format failed mbedtls err#%d \n", failures);
			return CERT_FAIL;
		}
		// if success then try to parse into x509 struct again
		failures = mbedtls_x509_crt_parse(x509, generatedDER, generatedDERSize); 
		if (failures) {
			prlog(PR_ERR, "Parsing x509 from PEM failed with MBEDTLS exit code: %d \n", failures);
			return CERT_FAIL;
		}
	}
	if (generatedDER) 
		free(generatedDER);

	return SUCCESS;
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
		prlog(PR_ERR,"ERROR: TS variable does not contain data on all the variables, expected %ld bytes of data, found %zd\n", sizeof(struct efi_time) * (ARRAY_SIZE(variables) - 1), size);
		return INVALID_TIMESTAMP;
	}
	for (pointer = (char *)data; size > 0; pointer += sizeof(struct efi_time), size -= sizeof(struct efi_time)){
		tmpStamp = (struct efi_time *) pointer; 
		rc = validateTime(tmpStamp);
		if (rc) goto out;
		if (verbose >= PR_INFO){
			prlog(PR_INFO, "\t%s:\t", variables[(ARRAY_SIZE(variables) - 1) - (size / sizeof(struct efi_time))]);
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


int validateTime(struct efi_time *time) 
{
	if (time->year < 0 || time->year > 9999) {
		prlog(PR_ERR,"ERROR: Invalid Timestamp value for year: %d\n", time->year);
		return INVALID_TIMESTAMP;
	}
	
	if (time->month < 0 || time->month > 12){
		prlog(PR_ERR,"ERROR: Invalid Timestamp value for month: %d\n", time->month );
		return INVALID_TIMESTAMP;
	}
	
	if (time->day < 0 || time->day > 31){
		prlog(PR_ERR,"ERROR: Invalid Timestamp value for day: %d\n", time->day);
		return INVALID_TIMESTAMP;
	}
		
	if (time->hour < 0 || time->hour > 24){
		prlog(PR_ERR,"ERROR: Invalid Timestamp value for hour: %d\n", time->hour);
		return INVALID_TIMESTAMP;
	}
		
	if (time->minute < 0 || time->minute > 60){
		prlog(PR_ERR,"ERROR: Invalid Timestamp value for minute: %d\n", time->minute);
		return INVALID_TIMESTAMP;
	}
	
	if (time->second < 0 || time->second > 60){
		prlog(PR_ERR,"ERROR: Invalid Timestamp value for second: %d\n", time->second);
		return INVALID_TIMESTAMP;
	}

	return SUCCESS;	
}

void printTimestamp(struct efi_time t)
{
	// NOTE: if auth is made with sign-efi-sig-list, year will be actual year+1 (see https:// blog.hansenpartnership.com/updating-pk-kek-db-and-x-in-user-mode/), 
	// also month could be one less bc months are 0-11 not 1-12
	printf("%04d-%02d-%02d %02d:%02d:%02d\n", t.year,t.month,t.day, t.hour, t.minute, t.second); 
}
