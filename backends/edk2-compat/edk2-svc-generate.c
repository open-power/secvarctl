#ifndef NO_CRYPTO
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> // for timestamp
#include <ctype.h> // for isspace
#include <mbedtls/md.h>     /* generic interface */
#include <mbedtls/platform.h> /*mbedtls functions*/
#include "../../extraMbedtls/include/pkcs7.h" // for PKCS7 OID
#include "include/endian.h"
#include "include/edk2-svc.h"
#include "include/edk2-compat-process.h" // work on factoring this out





struct Arguments {
	int helpFlag, inpValid, signKeyCount, signCertCount;
	const char *inFile, *outFile, 
	**signCerts, **signKeys,
	*inForm, *outForm, *varName, *hashAlg;
	char **currentVars;
	struct efi_time *time;
}; 
static int parseArgs(int argc, char *argv[], struct Arguments *args);

static int generateHash(const char* data, size_t size, struct Arguments *args, const struct hash_funct *alg, char** outHash, size_t* outHashSize);
static int validateHashAndAlg(size_t size, const struct hash_funct *alg);
static int toESL(const char* data, size_t size, const uuid_t guid, char** outESL, size_t* outESLSize);
static int getHashFunction(const char* name, struct hash_funct **returnFunct);
static int toPKCS7ForSecVar(const char* newData, size_t dataSize, struct Arguments *args, int hashFunct, char** outBuff, size_t* outBuffSize);
static int toAuth(const char* newESL, size_t eslSize, struct Arguments *args, int hashFunct, char** outBuff, size_t* outBuffSize);
static int generateESL(const char* buff, size_t size, struct Arguments *args, const struct hash_funct *hashFunct, char** outBuff, size_t* outBuffSize);
static int generateAuthOrPKCS7(const char* buff, size_t size, struct Arguments *args, const struct hash_funct *hashFunct, char** outBuff, size_t* outBuffSize);
static int getTimestamp(struct efi_time *ts);
static int getOutputData (const char *buff, size_t size, struct Arguments *args, const struct hash_funct *hashFunction, char **outBuff, size_t *outBuffSize);
static int authToESL(const char *in, size_t inSize, char **out, size_t *outSize);
static void usage()
{
	printf("USAGE:\n\t"
		"$ secvarctl generate <inputFormat>:<outputFormat> [OPTIONS] -i <inputFile> -o <outputFile>\n"
		"OPTIONS:\n\t-v\t\tverbose, give process progress\n"
		"\t-n <keyName>\tname of secure boot variable, used when generating an Auth file\n\t" 
		"\t\talso when an ESL or Auth file contains hashed data use '-n dbx'\n\t"
		"\t\tcurrently accepted for <keyName>: {'PK','KEK','db','dbx'}\n"
		"\t-h <hashAlg>\thash function, use when '[h]ash' is input/output format\n\t"
		"\t\tcurrently accepted for <hashAlg>:\n\t"
		"\t\t\t{'SHA256', 'SHA224', 'SHA1', 'SHA384', 'SHA512'}\n"
		"\t-k <keyFile>\tprivate RSA key (PEM), used when signing data for PKCS7/Auth files\n"
		"\t\t\tmust have a corresponding 'c <crtFile>'\n\t"
		"\t\tyou can also use multiple signers by declaring several '-k <> -c <>' pairs\n"
		"\t-c <crtFile>\tx509 cetificate (PEM), used when signing data for PKCS7/Auth files\n"
		"\t-t <time>\twhere time is of the format 'y-m-d h:m:s'.\n\t"
		"\t\tcreates a custom timestamp used when generating an auth or PKCS7 file,\n\t"
		"\t\tif not given then current time is used\n"
		"\t-f\t\tforce, does not do prevalidation on the input file, assumes format is correct\n"
		"\treset\t\tgenerates a valid variable reset file\n"
		"\t\t\treplaces <inputFormat>:<outputFormat>\n"
		"\t\t\tthis file is just an auth file with an empty ESL.\n"
		"\t\t\trequired arguments are output file, signer crt/key pair and variable name.\n"
		"\t\t\tno input file required.\n"
		"\t\t\tuse this flag to delete a variable\n"
		"Accepted <inputFormat>:"
		"\n\t[h]ash\tA file containing only hashed data\n\t"
		"\tuse -h <hashAlg> to specifify the function used (default SHA256)\n"
		"\t[c]ert\tAn x509 certificate (PEM format)\n"
		"\t[e]sl\tAn EFI Signature List, must specify if dbx update w '-n dbx'\n"
		"\t[p]kcs7\tA PKCS7 file containing signed data only used as input type when generating a hash\n"
		"\t[a]uth\tA signed authenticated file containing a PKCS7 and the new data\n"
		"\t\tused as input type when output type is hash or esl'\n"
		"\t[f]ile\tAny file type, Warning: no format validation will be done\n\n"
		"Accepted <outputFormat>:\n"
		"\t[h]ash\tA file containing only hashed data\n\t"
		"\tuse -h <hashAlg> to specifify the function to use (default SHA256)\n"
		"\t[e]sl\tAn EFI Signature List\n"
		"\t[p]kcs7\tA PKCS7 file containing signed data,\n\t"
		"\tmust specify secure variable name and public and private key to use for signing\n"
		"\t[a]uth\tA signed authenticated file containing a PKCS7 and the new data,\n\t"
		"\tmust specify the key name and public and private key to use for signing\n"
		"\n\n");
}


static void help()
{
	printf( "HELP:\n\t"
		"The purpose of this command is to generate various files related to updating\n\t" 
		"secure boot variables.\n"
		"Typical commands:\n"
		"\tto create an ESL from a binary file, use SHA512 on the file and store it in an ESL:\n"
		"\t\t'secvarctl generate f:e -i <file> -o <file> -h SHA512'\n" 
		"\tto create an ESL from an x509 certificate:\n"
		"\t\t'secvarctl generate c:e -i <file> -o <file>'\n"
		"\tto create a signed auth file from an ESL, the resulting file is a valid key update file:\n"
		"\t\t'secvarctl generate e:a -k <file> -c <file> -n <keyName> -i <file> -o <file>'\n"
		"\tto create a signed auth file from an x509, the resulting file is a valid key update file:\n"
		"\t\t'secvarctl generate c:a -k <file> -c <file> -n <keyName> -i <file> -o <file>'\n"
		"\tto create a valid dbx update (auth) file from a binary file:\n"
		"\t\t'secvarctl generate f:a -h <hashAlg> -k <file> -c <file> -n dbx -i <file> -o <file>'\n"
		"\tto retrieve the ESL from an auth file:\n"
		"\t\t'secvarctl generate a:e -i <file> -o <file>'\n"
		"\tto create a signed auth file for a key reset, the resulting file is a valid key reset file:\n"
		"\t\t'secvarctl generate reset -k <file> -c <file> -n <keyName> -o <file>'\n");

	usage();
}


/*
 *called from main()
 *handles argument parsing for generate command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int performGenerateCommand(int argc,char* argv[])
{
	int rc;
	size_t outBuffSize, size;
	struct hash_funct *hashFunction;
	char *buff = NULL, *outBuff = NULL;
	struct Arguments args = {	
		.helpFlag = 0, .inpValid = 0, .signKeyCount = 0, .signCertCount = 0,
		.inFile = NULL, .outFile = NULL,  
		.signCerts = NULL, .signKeys = NULL, .inForm = NULL, .outForm = NULL, .varName = NULL, 
		.hashAlg = NULL, .time = NULL
	};

	rc = parseArgs(argc, argv, &args);
	if (rc || args.helpFlag)
		goto out;
	
	if (args.varName && isVariable(args.varName)) {
		prlog(PR_ERR, "ERROR: %s is not a valid variable name\n", args.varName);
		rc = ARG_PARSE_FAIL;
		goto out;
	}		
	// if in:out did not parse right then quit
	if (args.inForm == NULL || args.outForm == NULL) {
		prlog(PR_ERR, "ERROR: Operation is invalid, see usage below...\n");
		usage();
		rc = ARG_PARSE_FAIL;
		goto out;
	}
	//output file must be defined
	if (args.outFile == NULL) {
		prlog(PR_ERR, "ERROR: No output file given, see usage below...\n");
		usage();
		rc = ARG_PARSE_FAIL;
		goto out;
	} 

	// input file must exist if not a reset key
	if (args.inForm[0] != 'r' && (args.inFile == NULL || isFile(args.inFile) )) {
		prlog(PR_ERR, "ERROR: Input File is invalid, see usage below...\n");
		usage();
		rc = ARG_PARSE_FAIL;
		goto out;
	}
	// if signing each signer needs a certificate
	if (args.signCertCount != args.signKeyCount) {
		prlog(PR_ERR, "ERROR: Number of certificates does not equal number of keys, %d != %d\n",args.signCertCount, args.signKeyCount);
		rc = ARG_PARSE_FAIL;
		goto out;
	}
	prlog(PR_INFO, "Input file is %s of type %s , output file is %s of type %s\n", args.inFile, args.inForm, args.outFile, args.outForm);
	
	//if reset key than don't look for a input file
	if (args.inForm[0] == 'r') 
		size = 0;
	else {
		// get data from input file
		buff = getDataFromFile(args.inFile, &size);
		if (buff == NULL){
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

	prlog(PR_INFO, "Writing %zd bytes to %s\n", outBuffSize, args.outFile);
	// write data to new file
	rc = createFile(args.outFile, outBuff, outBuffSize);
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
	if (rc) 
		printf("RESULT: FAILURE\n");
	else 
		printf("RESULT: SUCCESS\n");
	
	return rc;
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
		if (argv[i][0] == '-') {
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
			// set verbose flag
			else if (!strcmp(argv[i], "-v")) {
				verbose = PR_DEBUG; 
			}
			//  set input is valid flag
			else if (!strcmp(argv[i], "-f"))
				args->inpValid = 1;	
			// set private key signer	
			else if (!strcmp(argv[i], "-k")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect private key flag, see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->signKeyCount++;
					args->signKeys = realloc(args->signKeys, args->signKeyCount * sizeof(char*));
					args->signKeys[args->signKeyCount - 1] = argv[i];
				}
			}
			// set public key signer
			else if(!strcmp(argv[i], "-c")) {	
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for public key flag, use 'c <cert>', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->signCertCount++;
					args->signCerts = realloc(args->signCerts, args->signCertCount * sizeof(char*));
					args->signCerts[args->signCertCount - 1] = argv[i];
				}
			}
			// set input file
			else if (!strcmp(argv[i], "-i")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect flag '-i', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->inFile = argv[i];
				}
			}
			// set output file 
			else if (!strcmp(argv[i], "-o")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect flag '-o', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->outFile = argv[i];
				}
			}
			// set variable name
			else if (!strcmp(argv[i], "-n")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect flag '-n', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->varName = argv[i];
				}
			}
			// set hash alg
			else if (!strcmp(argv[i], "-h")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect flag '-h', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->hashAlg = argv[i];
				}
			}
			// set custom timestamp
			else if (!strcmp(argv[i], "-t")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-' || i+2 >=argc || argv[i+2][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect flag '-t', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->time = calloc(1, sizeof(*args->time));
					if (!args->time){
						prlog(PR_ERR, "ERROR: failed to allocate memory\n");
						rc = ALLOC_FAIL;
						goto out;
					}
					// make sure timestamp is correct format
					if (sscanf(argv[i++],"%hd-%hhd-%hhd", &args->time->year, &args->time->month, &args->time->day) != 3
						|| sscanf(argv[i], "%hhd:%hhd:%hhd", &args->time->hour, &args->time->minute, &args->time->second) != 3) {
						prlog(PR_ERR, "ERROR: Could not parse given timestamp, make sure it is in format 'y-m-d h:m:s'\n ");
						rc = ARG_PARSE_FAIL;
						goto out;
					}		
					else {
						rc = validateTime(args->time);
						if (rc) goto out;
					}
				}
			}
				
		}
		//check if reset key is desired
		else if (!strcmp(argv[i], "reset")) {
			args->inForm = "reset";
			args->inFile = "empty";
			args->outForm = "auth";
		}
		// else set input and output formats
		else {
				args->inForm = strtok(argv[i], ":");
				args->outForm = strtok(NULL, ":");
				if (args->inForm == NULL || args->outForm == NULL) {
					prlog(PR_ERR, "ERROR: Incorrect '<inputFormat>:<outputFormat>', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
		}
	}
		
out:
	if (rc) {
		prlog(PR_ERR, "Failed during argument parsing\n");
		usage();
	}
	return rc;
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
static int getOutputData (const char *buff, size_t size, struct Arguments *args, const struct hash_funct *hashFunction, char **outBuff, size_t *outBuffSize) 
{
	int rc;
	// once here it is time to plan the course of action depending on the output type desired
	switch (args->outForm[0]) {
		case 'c':
			rc = CERT_FAIL;  // cannot generate a cert
			break;
		case 'h':
			rc = generateHash(buff, size, args, hashFunction, outBuff, outBuffSize);
			break;
		case 'a':
			//intentional flow into pkcs7
		case 'p':
			// if no time is given then get curent time
			if (!args->time) {
				args->time = calloc(1, sizeof(*args->time));
				if (!args->time){
					prlog(PR_ERR, "ERROR: failed to allocate memory\n");
					rc = ALLOC_FAIL;
					goto out;
				}
				rc = getTimestamp(args->time);
				if (rc) goto out;
			}
			rc = generateAuthOrPKCS7(buff, size, args, hashFunction, outBuff, outBuffSize);
			break;
		case 'e':
			rc = generateESL(buff, size, args, hashFunction, outBuff, outBuffSize);
			break;
		default:
			prlog(PR_ERR, "ERROR: Unkown output format %s , see usage below...\n", args->outForm);
			usage();
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
static int generateAuthOrPKCS7(const char* buff, size_t size, struct Arguments *args, const struct hash_funct *hashFunct, char** outBuff, size_t* outBuffSize)
{
	int rc;
	size_t intermediateBuffSize, inpSize = size; 
	char *intermediateBuff = NULL, **inpPtr;
	inpPtr = (char **) &buff;
	
	switch (args->inForm[0]) {
		case 'f':
			//intentional flow
		case 'h':
			//intentional flow	
		case 'c': 
			rc = generateESL(buff, size, args, hashFunct, &intermediateBuff, &intermediateBuffSize);
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
				if (rc){
					prlog(PR_ERR, "ERROR: Could not validate ESL\n");
					break;
				}
			}
			rc = SUCCESS;
			break;
		case 'r':
			//if creating a reset key, ensure input is NULL and size of zero
			if (inpSize == 0 && *inpPtr == NULL)
				rc = SUCCESS;
			else {
				printf("ERROR: Input data must be empty for generation of reset file\n");
				rc = INVALID_FILE;
				break;
			}
			break;
		default:
			prlog(PR_ERR, "ERROR: Unknown input format %s for generating %s file , see usage below...\n", args->inForm, (args->outForm[0] == 'a' ? "an Auth" : "a PKCS7"));
			usage();
			rc = ARG_PARSE_FAIL;
	}
	if (rc) {
		prlog(PR_ERR, "Failed to validate input format\n");
		goto out;
	}
	
	if (args->outForm[0] == 'a')
		rc = toAuth(*inpPtr, inpSize, args, hashFunct->mbedtls_funct, outBuff, outBuffSize);
	else
		rc = toPKCS7ForSecVar(*inpPtr, inpSize, args, hashFunct->mbedtls_funct, outBuff, outBuffSize);

	if (rc) {
		prlog(PR_ERR,"Failed to generate %s file\n", args->outForm[0] == 'a' ? "Auth" : "PKCS7");
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
static int generateESL(const char* buff, size_t size, struct Arguments *args, const struct hash_funct *hashFunct, char** outBuff, size_t* outBuffSize)
{
	int rc;
	size_t intermediateBuffSize, inpSize = size; 
	char *intermediateBuff = NULL , **inpPtr;
	uuid_t const* eslGUID = &EFI_CERT_X509_GUID;
	inpPtr = (char **) &buff;

	switch (args->inForm[0]) {
		case 'f':
			rc = toHash(buff, size, hashFunct->mbedtls_funct, &intermediateBuff, &intermediateBuffSize);
			if (rc) {
				prlog(PR_ERR,"Failed to generate hash from file\n");
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
					prlog(PR_ERR,"Failed to validate input hash data\n");
					break;
				}
			}
			rc = SUCCESS;
			eslGUID = hashFunct->guid;
			break;
		case 'c': 
			// two intermediate buffers needed, one for input -> DER and one for DER -> ESL,
			prlog(PR_INFO, "Converting x509 from PEM to DER...\n");
			rc = convert_pem_to_der(*inpPtr, inpSize, (unsigned char **)&intermediateBuff, &intermediateBuffSize);
			if (rc) {
				prlog(PR_ERR, "ERROR: Could not convert PEM to DER mbedtls error #%d\n", rc);
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
			prlog(PR_ERR, "ERROR: Unkown input format %s for generating an ESL, see usage below...\n", args->inForm);
			usage();
			rc = ARG_PARSE_FAIL;

	}
	if (rc) {
		prlog(PR_ERR, "Failed to validate input format\n");
		goto out;
	}
	//if input file is auth than extract it
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
	if (intermediateBuff) free(intermediateBuff);
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
static int generateHash(const char* data, size_t size, struct Arguments *args, const struct hash_funct *alg, char** outHash, size_t* outHashSize)
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
				prlog(PR_ERR, "ERROR: Unkown input format %s for generating a hash, see usage below...\n", args->inForm);
				usage();
				rc = ARG_PARSE_FAIL;
		}	
		if (rc) {
			prlog(PR_ERR, "Failed to validate input format of input file when generating hash, try again with -f to skip format validation of input\n");
			return rc;
		}	
	}
	rc = toHash(data, size, alg->mbedtls_funct, outHash, outHashSize);
	if (rc) {
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
		prlog(PR_ERR, "ERROR: length of hash data does not equal expected size of hash %s, expected %zd found %zd bytes\n", alg->name, alg->size, size);
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
static int toESL(const char* data, size_t size, const uuid_t guid, char** outESL, size_t* outESLSize)
{
	EFI_SIGNATURE_LIST esl;
	size_t offset = 0;

	prlog(PR_INFO, "Creating ESL from %s... Adding:\n", getSigType(guid));
	esl.SignatureType = guid;
	if (verbose >= PR_INFO) { 
		prlog(PR_INFO,"\t%s Guid - ", getSigType(guid));
		printGuidSig(&guid);
	}

	esl.SignatureListSize = sizeof(esl) + sizeof(uuid_t) + size;
	prlog(PR_INFO, "\tSig List Size - %d\n", esl.SignatureListSize);
	// for some reason we are using header size is zero in all our files
	esl.SignatureHeaderSize = 0;
	esl.SignatureSize = size + sizeof(uuid_t);
	prlog(PR_INFO, "\tSignature Data Size - %d\n", esl.SignatureSize);

	/*ESL Structure:
		-ESL header - 28 bytes
		-ESL Owner uuid - 16 bytes
		-data
	*/
	// add ESL header stuff
	*outESL = calloc(1,esl.SignatureListSize);
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
static int authToESL(const char *in, size_t inSize, char **out, size_t *outSize) { 
	int rc;
	size_t length, auth_buffer_size, offset = 0, pkcs7_size;
	const struct efi_variable_authentication_2 *auth;

	auth = (struct efi_variable_authentication_2 *)in;
	length = auth->auth_info.hdr.dw_length;
	if (length <= 0 || length > inSize) { // if total size of header and pkcs7
		prlog(PR_ERR,"ERROR: Invalid auth size %zd\n", length);
		return AUTH_FAIL;
	}
	pkcs7_size = get_pkcs7_len(auth);
	/*pkcs7_size=length-(sizeof(auth->auth_info.hdr)+sizeof(auth->auth_info.cert_type));*/ // =sizeof cert_data[] AKA pkcs7 data
	// if total size of header and pkcs7
	if (pkcs7_size <= 0 || pkcs7_size > length) { 
		prlog(PR_ERR,"ERROR: Invalid pkcs7 size %zd\n", pkcs7_size);
		return PKCS7_FAIL;
	}
	/*
	 * efi_var_2->auth_info.data = auth descriptor + new ESL data.
	 * We want only only the auth descriptor/pkcs7 from .data.
	 */
	auth_buffer_size = sizeof(auth->timestamp) + sizeof(auth->auth_info.hdr)+ sizeof(auth->auth_info.cert_type) + pkcs7_size;
	if (auth_buffer_size > inSize) { // If no ESL DATA attatched
		prlog(PR_ERR,"ERROR: No data to verify, no attatched ESL\n");
		return ESL_FAIL;
	}
	prlog(PR_NOTICE,"\tAuth File Size = %zd\n\t  -Auth/PKCS7 Data Size = %zd\n\t  -ESL Size = %zd\n", inSize, auth_buffer_size, inSize - auth_buffer_size);
	
	// skips over entire pkcs7 in cert_datas
	offset = sizeof(auth->timestamp) + length; 
	if (offset == inSize){
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
static int getHashFunction(const char* name, struct hash_funct **returnFunct)
{
	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
		if (!strcmp(name, hash_functions[i].name)) {
			*returnFunct = (struct hash_funct *)&hash_functions[i];
			return SUCCESS;
		}
	}
	prlog(PR_ERR, "ERROR: Invalid hash algorithm %s , hint: use -h { ", name);
	//loop through all known hashes
  	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
  		if (i == sizeof(hash_functions) / sizeof(struct hash_funct) - 1)
  			prlog(PR_ERR, "%s }\n", hash_functions[i].name);
  		else
  			prlog(PR_ERR, "%s, ", hash_functions[i].name);
  	}

	return ARG_PARSE_FAIL;
}

/*
 *gets current time and puts into an efi_time struct
 *@param ts, the outputted current time
 *@return SUCCESS or errno if generated timestamp is incorrect
 */
static int getTimestamp(struct efi_time *ts) {
	time_t epochTime;
	struct tm *t;

	time(&epochTime);	
	t = localtime(&epochTime);
	ts->year = 1900 + t->tm_year;
    ts->month = t->tm_mon + 1; // makes 1-12 not 0-11
    ts->day = t->tm_mday;
   	ts->hour = t->tm_hour;
   	ts->minute = t->tm_min;
  	ts->second = t->tm_sec;

  	return validateTime(ts);	
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

	for (i = 0; i < keylen*2; key++) {
		str[i++] = *key;
		str[i++] = '\0';
	}

	return str;
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
static int toPKCS7ForSecVar(const char* newData, size_t dataSize, struct Arguments *args, int hashFunct, char** outBuff, size_t* outBuffSize)
{
	int rc;
	size_t totalSize, varlen; 
	char *actualData = NULL, *ptr = NULL;
	le32 attr = cpu_to_le32(SECVAR_ATTRIBUTES);
	char *wkey = NULL;
	uuid_t guid;

	if (!args->varName) {
		prlog(PR_ERR, "ERROR: No key given... use -n <keyName> option\n");
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "Timestamp is : ");
		printTimestamp(*args->time);
	}
	
	// some parts taken from edk2-compat-process.c
	if (key_equals(args->varName, "PK")
	    || key_equals(args->varName, "KEK"))
		guid = EFI_GLOBAL_VARIABLE_GUID;
	else if (key_equals(args->varName, "db")
	    || key_equals(args->varName, "dbx"))
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
	totalSize = varlen + sizeof(guid) + sizeof(attr) + sizeof(struct efi_time) + dataSize;
	actualData = malloc(totalSize);
	if (!actualData){
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = ALLOC_FAIL;
		goto out;
	}
	ptr = actualData;
	memcpy(ptr, wkey, varlen);
	ptr += varlen;
	memcpy(ptr, &guid, sizeof(guid));
	ptr += sizeof(guid);
	memcpy(ptr, &attr, sizeof(attr));
	ptr += sizeof(attr);
	memcpy(ptr , args->time, sizeof(struct efi_time));
	ptr += sizeof(*args->time);
	memcpy(ptr, newData, dataSize);


	// get pkcs7 and size
	rc = toPKCS7((unsigned char **)outBuff, outBuffSize, actualData, totalSize, args->signCerts, args->signKeys, args->signKeyCount, MBEDTLS_MD_SHA256 );
	if (rc) {
		prlog(PR_ERR,"ERROR: making PKCS7 failed\n");
		rc = PKCS7_FAIL;
		goto out;
	}

out:
	if (wkey) 
		free(wkey);
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
static int toAuth(const char* newESL, size_t eslSize, struct Arguments *args, int hashFunct, char** outBuff, size_t* outBuffSize) 
{
	int rc;
	size_t pkcs7Size, offset = 0;
	char *pkcs7 = NULL; 
	struct efi_variable_authentication_2 authHeader;

	// generate PKCS7
	rc = toPKCS7ForSecVar(newESL, eslSize, args, hashFunct,  &pkcs7, &pkcs7Size);
	if (rc) {
		prlog(PR_ERR, "Cannot generate Auth File, failed to generate PKCS7\n");
		goto out;
	}
	//  create Auth header
	authHeader.timestamp = *args->time;
	authHeader.auth_info.hdr.dw_length = sizeof(authHeader.auth_info.hdr) + sizeof(authHeader.auth_info.cert_type) + pkcs7Size;
	authHeader.auth_info.hdr.w_revision = cpu_to_be16(WIN_CERT_TYPE_PKCS_SIGNED_DATA);
	// ranges from f0 -ff, but all files Ive seen have f10e
	authHeader.auth_info.hdr.w_certificate_type = cpu_to_be16(0xf10e); 
	authHeader.auth_info.cert_type = EFI_CERT_TYPE_PKCS7_GUID;

	// now build auth file, = auth header + pkcs7 + new ESL
	*outBuffSize = pkcs7Size + sizeof(authHeader) + eslSize;
	*outBuff = malloc(*outBuffSize);
	if (!outBuff) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = ALLOC_FAIL;
		goto out;
	}
	prlog(PR_INFO, "Combining Auth header, PKCS7 and new ESL:\n");
	memcpy(*outBuff + offset, &authHeader, sizeof(authHeader));
	offset += sizeof(authHeader);
	prlog(PR_INFO, "\t+ Auth Header %ld bytes\n", sizeof(authHeader));
	memcpy(*outBuff + offset, pkcs7, pkcs7Size);
	offset += pkcs7Size;
	prlog(PR_INFO, "\t+ PKCS7 %zd bytes\n", pkcs7Size);
	memcpy(*outBuff + offset, newESL, eslSize);
	offset += eslSize;
	prlog(PR_INFO, "\t+ new ESL %zd bytes\n\t= %zd total bytes\n", eslSize, offset);
	
out:
	if (pkcs7) 
		free(pkcs7);

	return rc;
}
#endif
