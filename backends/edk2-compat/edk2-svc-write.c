// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>// for exit
#include <argp.h>
#include "../../include/secvarctl.h"
#include "include/edk2-svc.h"// import last!!

static int updateSecVar(const char *var, const char *authFile, const char *path, int force);

struct Arguments {
	int helpFlag, inpValid;
	const char *pathToSecVars, *varName, *inFile;
}; 
static int parse_opt(int key, char *arg, struct argp_state *state);


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
	argv[0] = "secvarctl write";

	struct argp_option options[] = 
	{
		{"verbose", 'v', 0, 0, "print more verbose process information"},
		{"force", 'f', 0, 0, "force update, skips validation of file"},
		{"path", 'p', "PATH" ,0, "looks for .../<var>/update file in PATH, default is " SECVARPATH},
		{0}
	};

	struct argp argp = {
		options, parse_opt, "<VARIABLE> <AUTH_FILE>", 
		"This command updates a given secure variable with a new key contained in an auth file"
		" It is recommended that 'secvarctl verify' is tried on the update file before submitting."
		" This will ensure that the submission will be successful upon reboot."
		"\vvalues for <VARIABLE> = type one of {'PK','KEK','db','dbx'}\n"
		"<AUTH_FILE> must be a properly generated authenticated variable file"
	};

	rc = argp_parse( &argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER, 0, &args);
	if (rc || args.helpFlag)
		goto out;


	rc = updateSecVar(args.varName, args.inFile, args.pathToSecVars, args.inpValid);

out:
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
	//this checks to see if help/usage is requested
	//argp can either exit() or raise no errors, we want to go to cleanup and then exit so we need a special flag
	//this becomes extra sticky since --usage/--help never actually get passed to this function
	if (args->helpFlag == 0) {
		if (state->next == 0 && state->next + 1 < state->argc) {
			if (strncmp("--u", state->argv[state->next + 1], strlen("--u")) == 0 
				|| strncmp("--h", state->argv[state->next + 1], strlen("--h")) == 0
				|| strncmp("-?", state->argv[state->next + 1], strlen("-?")) == 0)
				args->helpFlag = 1;
		}
		else if (state->next < state->argc)
			if (strncmp("--u", state->argv[state->next], strlen("--u")) == 0 
				|| strncmp("--h", state->argv[state->next], strlen("--h")) == 0
				|| strncmp("-?", state->argv[state->next], strlen("-?")) == 0)
				args->helpFlag = 1;
	}

	switch (key) {
		case 'p':
			args->pathToSecVars = arg;
			break;
		case 'f':
			args->inpValid = 1;
			break;
		case 'v':
			verbose = PR_DEBUG;
			break;
		case ARGP_KEY_ARG:
			if (args->varName == NULL)
				args->varName = arg;
			else if (args->inFile == NULL)
				args->inFile = arg;
			break;
		case ARGP_KEY_SUCCESS:
			//check that all essential args are given and valid
			if (args->helpFlag)
				break;
			if(!args->varName) 
				prlog(PR_ERR, "ERROR: missing variable, see usage...\n");
			else if (!args->inFile) 
				prlog(PR_ERR, "ERROR: missing input file, see usage...\n");
			else if (isVariable(args->varName)) 
				prlog(PR_ERR, "ERROR: Unrecognized variable name %s, see usage...\n", args->varName);
			else if (strcmp(args->varName, "TS") == 0) 
				prlog(PR_ERR, "ERROR: Cannot update TimeStamp (TS) variable, see usage...\n");
			else 
				break;
			argp_usage(state);
			rc = args->inFile ? INVALID_VAR_NAME : ARG_PARSE_FAIL;
			break;
	}

	if (rc) 
		prlog(PR_ERR, "Failed during argument parsing\n");

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
 *@return error if variable given is unknown, or issue validating or writing
 */
static int updateSecVar(const char *varName, const char *authFile, const char *path, int force)
{	
	int rc;
	unsigned char *buff = NULL;
	size_t size;
		
	if (!path) {
		path = SECVARPATH;
	} 

	// get data to write, if force flag then validate the data is an auth file
	buff = (unsigned char *)getDataFromFile(authFile, &size); 
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
int updateVar(const char *path, const char *var, const unsigned char *buff, size_t size)
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

	rc = writeData(fullPathWithCommand, (const char *)buff, size);
	free(fullPathWithCommand);

	return rc;

}


