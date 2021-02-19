#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>// for exit
#include "../../include/secvarctl.h"
#include "include/edk2-svc.h"// import last!!


static void usage();
static void help();
static int updateSecVar(const char *var, const char *authFile, const char *path, int force);

struct Arguments {
	int helpFlag, inpValid;
	const char *pathToSecVars, *varName, *inFile;
}; 
static int parseArgs(int argc, char *argv[], struct Arguments *args);


/*
 *called from main()
 *handles argument parsing for write command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number
*/
int performWriteCommand(int argc, char* argv[])
{
	int rc;
	struct Arguments args = {	
		.helpFlag = 0, .inpValid = 0, 
		.pathToSecVars = NULL, .inFile = NULL, .varName = NULL
	};

	rc = parseArgs(argc, argv, &args);
	if (rc || args.helpFlag)
		goto out;

	if (!args.inFile || !args.varName ) {
		usage();
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	rc = updateSecVar(args.varName, args.inFile, args.pathToSecVars, args.inpValid);	
out:
	if (rc) 
		printf("RESULT: FAILURE\n");
	else 
		printf("RESULT: SUCCESS\n");

	return rc;	
}

static void usage()
{
	printf("USAGE:\n\t' $ secvarctl write [OPTIONS] <variable> <authFile>'"
		"\n\tOPTIONS:\n"
		"\t\t--help/--usage\n"
		"\t\t-v\t\tverbose, print process info"
		"\n\t\t-f\t\tforce update, skips validation of file\n\t\t"
		"-p <path>\tlooks for .../<var>/update file in <path>,\n"
		"\t\t\t\tshould contain expected var subdirectories {'PK','KEK','db','dbx'},\n"
		"\t\t\t\tdefault is " SECVARPATH "\n"
		"\tVariable:\n\t\tone of the following {PK, KEK, db, dbx}\n\n");
}

static void help()
{
	printf("HELP:\n\tThis function updates a given secure variable with a new key contained in an auth file\n"
		"It is recommended that 'secvarctl verify' is tried on the update file before submitting.\n"
		"\tThis will ensure that the submission will be successful upon reboot.\n");
	usage();
}

/**
 *@param argv , array of command line arguments
 *@param argc, length of argv
 *@param args, struct that will be filled with data from argv
 *@return success or errno
 */
static int parseArgs( int argc, char *argv[], struct Arguments *args) 
{
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
			// set path
			else if (!strcmp(argv[i], "-p")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for '-p', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->pathToSecVars= argv[i];
				}
			}
			// set force flag
			else if (!strcmp(argv[i], "-f"))
				args->inpValid = 1;	
		}
		else {
			if (i + 1 >= argc || argv[i + 1][0] == '-') {		
				prlog(PR_ERR, "ERROR: Incorrect '<var> <authFile>', see usage\n");
				rc = ARG_PARSE_FAIL;
				goto out;
			}
			args-> varName = argv[i++];			
			args-> inFile = argv[i];
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
 *checks to see if string is a valid variable name {db,dbx,pk,kek, TS}
 *@param var variable name
 *@return SUCCESS or error code
 */
int isVariable(const char * var)
{
	for (int i = 0; i < ARRAY_SIZE(variables); i++) {
		if (strcmp(var,variables[i]) == 0)
			return SUCCESS;
	}

	return INVALID_VAR_NAME;
}

/**
 *ensures updating variable is a valid variable, creates full path to ...../update file, verifies auth file is valid
 *@param varName string to varName {PK,KEK,db,dbx}
 *@param authfile string of auth file name
 *@param path string of path to directory containing <varName>/update file
 *@param force 1 for no validation of auth, 0 for validate
 *@return error if variable given is unkown, or issue validating or writing
 */
static int updateSecVar(const char *varName, const char *authFile, const char *path, int force)
{	
	int rc;
	char *buff = NULL;
	size_t size;

	if (isVariable(varName)) {
		prlog(PR_ERR, "ERROR: Unrecognized variable name %s\n", varName);
		usage();
		return INVALID_VAR_NAME;
	}
	if (strcmp(varName, "TS") == 0) {
		prlog(PR_ERR, "ERROR: Cannot update TimeStamp (TS) variable\n");
		usage();
		return INVALID_VAR_NAME;
	}
		
	if (!path) {
		path = SECVARPATH;
	} 

	// get data to write, if force flag then validate the data is an auth file
	buff = getDataFromFile(authFile, &size); 
	// if we are validating and validating fails, quit
	if (!force) { 
		rc = validateAuth(buff, size, varName);
		if (rc) {
			prlog(PR_ERR, "ERROR: validating update file (Signed Auth) failed, not updating\n");
			free(buff);
			return rc;
		}
	}
	rc = updateVar(path, varName, buff, size);

	if (rc) 
		prlog(PR_ERR, "ERROR: issue writing to file: %s\n", strerror(errno));
	free(buff);

	return rc;
}

/*
 *updates a secure variable by writing data in buf to the <path>/<var>/update
 *@param path, path to sec vars
 *@param var, one of  {db,dbx, KEK, Pk}
 *@param buff , auth file data
 *@param size , size of buff
 *@return whatever returned by writeData, SUCCESS or errno
 */
int updateVar(const char *path, const char *var, const char *buff, size_t size)
{	
	int commandLength, rc; 
	char *fullPathWithCommand = NULL;

	commandLength = strlen(path) + strlen(var) + strlen("/update ");
	fullPathWithCommand = malloc(commandLength);
	if (!fullPathWithCommand) { 
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	strcpy(fullPathWithCommand, path);
	strcat(fullPathWithCommand, var);
	strcat(fullPathWithCommand, "/update");

	rc = writeData(fullPathWithCommand, buff, size);
	free(fullPathWithCommand);

	return rc;

}


