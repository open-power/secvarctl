#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include <fcntl.h> // O_RDONLY
#include <unistd.h> // has read/open funcitons
#include <mbedtls/x509_crt.h> // for reading certdata
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "include/secvar.h" // for secvar struct
#include "include/edk2-svc.h"// include last, pragma pack(1) issue



static int readFiles(const char* var, const char* file, int hrFlag, const  char* path);
static void usage();
static void help();
static int printReadable(const char *c , size_t size, const char * key);
static int readFileFromSecVar(const char * path, const char *variable, int hrFlag);
static int readFileFromPath(const char *path, int hrFlag);
static int getSizeFromSizeFile(size_t *returnSize, const char* path);


struct Arguments {
	int helpFlag, printRaw;
	const char *pathToSecVars, *varName, *inFile;
}; 
static int parseArgs(int argc, char *argv[], struct Arguments *args);


/*
 *called from main()
 *handles argument parsing for read command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int performReadCommand(int argc, char* argv[]) 
{
	int rc;
	struct Arguments args = {	
		.helpFlag = 0, .printRaw = 0, 
		.pathToSecVars = NULL, .inFile = NULL, .varName = NULL
	};

	rc = parseArgs(argc, argv, &args);
	if (rc || args.helpFlag)
		return rc;

	rc = readFiles(args.varName, args.inFile, !args.printRaw, args.pathToSecVars);

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
		if (argv[i][0] != '-') {
			args->varName = argv[i];
			rc = isVariable(args->varName);
			if (rc) {
				prlog(PR_ERR, "ERROR: Invalid variable name %s\n", args->varName);
				goto out;
			}
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
			case 'v':
				verbose = PR_DEBUG;
				break;
			//set path
			case 'p':
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for '-p', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->pathToSecVars= argv[i];
				}
				break;
			//set file path
			case 'f':
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for file flag, use '-f <file>', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->inFile = argv[i];
				}	
				break;
			case 'r':
				args->printRaw = 1;
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
 *Function that recieves arguments to read command and handles getting data, finding paths, iterating through variables to read
 *@param var  string to variable wanted if <variable> option is given, NULL if not
 *@param file string to filename with path if -f option, NULL if not
 *@param hrFLag 1 if -hr for human readable output, 0 for raw data
 *@param path string to path where {PK,KEK,db,dbx,TS} subdirectories are, default SECVARPATH if none given
 *@return succcess if at least one file was successfully read
 */
static int readFiles(const char* var, const char* file, int hrFlag, const char *path) 
{  
	// program is successful if at least one var was able to be read
	int rc, successCount = 0;

	if (file) prlog(PR_NOTICE, "Looking in file %s for ESL's\n", file); 
	else prlog(PR_NOTICE, "Looking in %s for %s variable with %s format\n", path ? path : SECVARPATH, var ? var : "ALL", hrFlag ? "ASCII" : "raw_data");
	
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
			rc = readFileFromSecVar(path, variables[i], hrFlag);
			if (rc == SUCCESS) successCount++;
		}
	}
	else {
		rc = readFileFromPath(file, hrFlag);
		if (rc == SUCCESS) successCount++;
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

	strncpy(fullPath, path, strlen(path) + 1);
	strncat(fullPath, variable, strlen(variable));
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
		}
		else if (strcmp(var->key, "TS") == 0) 
			rc = validateTS(var->data, var->data_size);
		else
			rc = printReadable(var->data, var->data_size, var->key);

		if (rc)
			prlog(PR_WARNING, "ERROR: Could not parse file, continuing...\n");
	}
	else {
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
		if(rc)
			prlog(PR_WARNING,"ERROR: Could not parse file\n");
		else
			rc = SUCCESS; 		
	}
	else {
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
int getSecVar(struct secvar **var, const char* name, const char *fullPath){
	int rc, fptr;
	size_t size;
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
	strncpy(sizePath, fullPath, strlen(fullPath) - strlen("data"));
	//add null terminator so strncat works
	sizePath[strlen(fullPath) - strlen("data")] = '\0';
	strncat(sizePath, "size", strlen("size") + 1); 
	rc = getSizeFromSizeFile(&size, sizePath);
	if (rc < 0) {
		prlog(PR_WARNING, "ERROR: Could not get size of variable, TIP: does %s exist?\n", sizePath);
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
		prlog(PR_WARNING,"-----opening %s failed: %s-------\n\n", fullPath, strerror(errno));
		return INVALID_FILE;
	}
	if (fstat(fptr, &fileInfo) < 0) {
		return INVALID_FILE;
	}
	// if file size is less than expeced size, error
	if (fileInfo.st_size < size) {
		prlog(PR_ERR, "ERROR: expected size (%zd) is less than actual size (%ld)\n", size, fileInfo.st_size);
		return INVALID_FILE;
	}
	prlog(PR_NOTICE,"---opening %s is success: reading %zd bytes---- \n", fullPath, size);
	c = malloc(size);
	if (!c) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;	
	}

	read(fptr, c, size);
	close(fptr);
	if (!c) {
		prlog(PR_ERR, "ERROR: no data in file");
		return INVALID_FILE;
	}

	*var = new_secvar(name, strlen(name) + 1, c, size, 0);
	if (*var == NULL) {
		prlog(PR_ERR, " ERROR: Could not convert data to secvar\n");
		free(c);
		return INVALID_FILE;
	}
	free(c);

	return SUCCESS;
}

void help() 
{
	printf("HELP:\n\t"
		"This program command is created to easily view secure variables. The current variables\n" 
		"\tthat are able to be observed are the PK, KEK, db, db, dbx, TS. If no options are\n" 
		"\tgiven, then the information for the keys in the default path will be printed."
		"\n\tIf the user would like to print the information for another ESL file,\n"
		"\tthen the '-f' command would be appropriate.\n");
	usage();
}

void usage() 
{
	printf("USAGE:\n\t' $ secvarctl read [OPTIONS] [VARIABLES] '\nOPTIONS:"
		"\n\t--usage/--help"
		"\n\t-r\t\t\tprints raw data, default is human readable information"
		"\n\t-f <filename>\t\tnavigates to ESL file from working directiory"
		"\n\t-p <path to vars>\tlooks for key directories {'PK','KEK','db','dbx', 'TS'} in <path>,\n"
		"\t\t\t\tdefault is " SECVARPATH "\n"
		"VARIABLES:\n\t{'PK','KEK','db','dbx', 'TS'}\ttype one of the following to get info on that key,\n"
		"\t\t\t\t\tNOTE does not work when -f option is present\n\n");
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
	size_t  eslsize = 0;
	int count = 0, offset = 0, rc;
	char *cert = NULL;
	EFI_SIGNATURE_LIST *sigList;
	mbedtls_x509_crt *x509 = NULL;

	printf("READING %s :\n", key ? key : "ESL");
	while (eslvarsize > 0) {
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST)) { 
			prlog(PR_ERR, "ERROR: ESL has %zd bytes and is smaller than an ESL (%zd bytes), remaining data not parsed\n", eslvarsize, sizeof(EFI_SIGNATURE_LIST));
			break;
		}
		// Get sig list
		sigList = get_esl_signature_list(c + offset, eslvarsize);
		// check size info is logical 
		if (sigList->SignatureListSize > 0) {
			if ((sigList->SignatureSize <= 0 && sigList->SignatureHeaderSize <= 0) 
				|| sigList->SignatureListSize < sigList->SignatureHeaderSize + sigList->SignatureSize) {
				/*printf("Sig List : %d , sig Header: %d, sig Size: %d\n",list.SignatureListSize,list.SignatureHeaderSize,list.SignatureSize);*/
				prlog(PR_ERR,"ERROR: Sig List is not structured correctly, defined size and actual sizes are mismatched\n");
				break;
			}	
		}
		if (sigList->SignatureListSize  > eslvarsize || sigList->SignatureHeaderSize > eslvarsize || sigList->SignatureSize > eslvarsize) {
			prlog(PR_ERR, "ERROR: Expected Sig List Size %d + Header size %d + Signature Size is %d larger than actual size %zd\n", sigList->SignatureListSize, sigList->SignatureHeaderSize, sigList->SignatureSize, eslvarsize);
			break;
		}
		eslsize = sigList->SignatureListSize;
		printESLInfo(sigList);
		// puts sig data in cert
		cert_size = get_esl_cert(c + offset, sigList, &cert); 
		if (cert_size <= 0) {
			prlog(PR_ERR, "\tERROR: Signature Size was too small, no data \n");
			break;
		}
		if (key && !strcmp(key, "dbx")) {
			printf("\tHash: ");
			printHex(cert, cert_size);
		}
		else {
			x509 = malloc(sizeof(*x509));
			if (!x509) {
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				return ALLOC_FAIL;
			}
			rc = parseX509(x509, cert, (size_t) cert_size);
			if (rc)
				break;
			rc = printCertInfo(x509);
			if (rc)
				break;
			free(cert);
			cert = NULL;
			mbedtls_x509_crt_free(x509);
			free(x509);
			x509 = NULL;
		}
		
		count++;	
		 // we read all eslsize bytes so iterate to next esl	
		offset += eslsize;
		// size left of total file
		eslvarsize -= eslsize;	
	}
	printf("\tFound %d ESL's\n\n", count);
	if (x509) {
		mbedtls_x509_crt_free(x509);
		free(x509);
	}
	if (cert) 
		free(cert);

	if (!count)
		return ESL_FAIL;

	return SUCCESS;
}

//prints info on ESL, nothing on ESL data
void printESLInfo(EFI_SIGNATURE_LIST *sigList) 
{
	printf("\tESL SIG LIST SIZE: %d\n", sigList->SignatureListSize);
	printf("\tGUID is : ");
	printGuidSig(&sigList->SignatureType);
	printf("\tSignature type is: %s\n", getSigType(sigList->SignatureType));
}

//prints info on x509
int printCertInfo(mbedtls_x509_crt *x509)
{
	char *x509_info;
	int failures;

	x509_info = malloc(CERT_BUFFER_SIZE);
	if (!x509_info){
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return CERT_FAIL;
	}
	// failures = number of bytes written, x509_info now has string of ascii data
	failures = mbedtls_x509_crt_info(x509_info, CERT_BUFFER_SIZE, "\t\t", x509); 
	if (failures <= 0) {
		prlog(PR_ERR, "\tERROR: Failed to get cert info, wrote %d bytes when getting info\n", failures);
		return CERT_FAIL;
	}
	printf("\tFOUND %d bytes of certificate info:\n %s", failures, x509_info);
	free(x509_info);

	return SUCCESS;
 }

/** 
 *inspired by secvar/backend/edk2-compat-process.c by Nayna Jain
 *@param c  pointer to start of esl file
 *@param cert empty buffer 
 *@param list current siglist
 *@return size of memory allocated to cert or negative number if allocation fails
 */
ssize_t get_esl_cert(const char *c, EFI_SIGNATURE_LIST *list , char **cert) 
{
	ssize_t size, dataOffset;
	size = list->SignatureSize - sizeof(uuid_t);
	dataOffset = sizeof(EFI_SIGNATURE_LIST) + list->SignatureHeaderSize + 16 * sizeof(uint8_t);
	*cert = malloc(size);
	if (!*cert){
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	// copies size bytes from eslfile-headerstuff and guid into cert
	memcpy(*cert, c + dataOffset, size); 

	return size;
}

/**
 *finds format type given by guid
 *@param type uuid_t of guid of file
 *@return string of format type, "UNKNOWN" if type doesnt match any known formats
 */
const char* getSigType(const uuid_t type) 
{
	//loop through all known hashes
	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
		if (uuid_equals(&type, hash_functions[i].guid)) 
			return hash_functions[i].name;	
	}
	//try other known guids
	if (uuid_equals(&type, &EFI_CERT_X509_GUID)) return "X509";
	else if (uuid_equals(&type, &EFI_CERT_RSA2048_GUID)) return "RSA2048";
	else if (uuid_equals(&type, &EFI_CERT_TYPE_PKCS7_GUID))return "PKCS7";
	
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

/**
 *parses buffer into a EFI_SIG_LIST
 *@param buf pointer to sig list buffer
 *@param buflen length of buffer
 *@return NULL if buflen is smaller than size of sig list stuct or if buff is empty
 *@return EFI_SIG_LIST struct
 */ 
EFI_SIGNATURE_LIST* get_esl_signature_list(const char *buf, size_t buflen)
{
	EFI_SIGNATURE_LIST *list = NULL;
	if (buflen < sizeof(EFI_SIGNATURE_LIST) || !buf) {
		prlog(PR_ERR,"ERROR: SigList does not have enough data to be valid\n");
		return NULL;
	}
	list = (EFI_SIGNATURE_LIST *)buf;

	return list;
}

/*
 *gets the integer value from the ascii file "size"
 *@param size, the returned size of size file
 *@param path , lccation of "size" file
 *@return errror number if fail, <0
 */
static int getSizeFromSizeFile(size_t *returnSize, const char* path)
{
	int fptr, rc;
	ssize_t maxdigits = 8; 
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
	prlog(PR_NOTICE, "----opening %s is success: reading %zd of %zd bytes----\n", path, maxdigits, fileInfo.st_size);
	read(fptr, c, maxdigits);
	close(fptr);
	// turn string into base 10 int
	*returnSize = strtol(c, NULL, 0); 
	//strol likes to return zero if there is no conversion from string to int
	//so we need to differentiate an error from a file that actually contains 0
	if (*returnSize == 0 && c[0] != '0')
		rc = INVALID_FILE;
	else
		rc = SUCCESS;
	free(c);

	return rc;
}




