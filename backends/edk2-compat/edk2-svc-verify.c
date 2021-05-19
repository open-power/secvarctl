// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // for exit
#include <fcntl.h> // O_RDONLY
#include <unistd.h> // has read/open functions
#include <argp.h>
#include "external/skiboot/include/opal-api.h"
#include "external/skiboot/libstb/secvar/secvar.h"
#include "backends/edk2-compat/include/edk2-svc.h"

struct Arguments {
	int helpFlag, writeFlag, currVarCount, updateVarCount;
	const char *pathToSecVars, **updateVars;
	char **currentVars;
};

extern struct secvar_backend_driver edk2_compatible_v1;

static int verify(char **currentVars, int currCount, const char **updateVars, int updateCount,
		  const char *path, int writeFlag);
static int validateVarsArg(const char *vars[], int size);
static int getCurrentVars(char **newCurr, int *size, const char *path);
static char *opalErrToString(int rc);
static int parse_opt(int key, char *arg, struct argp_state *state);
static int validateBanks(struct list_head *update_bank, struct list_head *variable_bank);
static int setupBanks(struct list_head *variable_bank, struct list_head *update_bank,
		      char *currentVars[], int currCount, const char *updateVars[], int updateCount,
		      const char *path);
static void printBanks(struct list_head *variable_bank, struct list_head *update_bank);
static int commitUpdateBank(struct list_head *update_bank, const char *path);

/**
*performs verification command, called from main
*@param argc number of items in arg command
*@param argv arguments array
*@return SUCCESS if everything works, error code if not
*/
int performVerificationCommand(int argc, char *argv[])
{
	int rc;
	struct Arguments args = { .helpFlag = 0,
				  .writeFlag = 0,
				  .currVarCount = 0,
				  .updateVarCount = 0,
				  .pathToSecVars = NULL,
				  .updateVars = NULL,
				  .currentVars = 0 };
	// combine command and subcommand for usage/help messages
	argv[0] = "secvarctl verify";

	struct argp_option options[] = {
		{ "verbose", 'v', 0, 0, "print more verbose process information" },
		{ "path", 'p', "PATH", 0,
		  "manually set path to current variables, looks for .../<var>/data file in PATH, default is " SECVARPATH
		  " . Cannot be used with `-c` " },
		{ "current", 'c', "{CURRENT VAR LIST}", 0,
		  "manually set current vars to be contents of CURRENT VAR LIST (see below for format)" },
		{ "write", 'w', 0, 0,
		  "if successful, submit the update to be commited upon reboot. Equivalent to `secvarctl write`" },
		{ 0, 'u', "{UPDATE LIST}", OPTION_HIDDEN,
		  "set update variables (see below for format)" },
		{ "help", '?', 0, 0, "Give this help list", 1 },
		{ "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
		{ 0 }
	};

	struct argp argp = {
		options, parse_opt, "-u {UPDATE LIST}",
		"This command ensures that the proposed variable updates are"
		" correctly signed by the current variables. If successful, then the user can run the same"
		" command with the '-w' flag or use 'secvarctl write' to submit the updates to be"
		" committed upon reboot\v"
		"UPDATE LIST:\nAt least one variable-file pair is required. Formatted as:"
		" ' -u <varName_1> <authFileForVar_1> <varName_2> <authFileForVar_2> ... '"
		" Where <varName> is one of {'PK','KEK','db','dbx'}"
		" and <authFileForVar> is a properly generated authenticated variable file that is"
		" signed by a current variable with priviledges to approve the update\n\n"
		"CURRENT_VAR_LIST:\nOptional, only used when -c is used. Formatted as:"
		" ' -c <varName_1> <eslFileForVar_1> <varName_2> <eslFileForVar_2> ... '"
		" Where <varName> is one of {'PK','KEK','db','dbx', 'TS'} and"
		" <eslFileForVar> is an EFI Signature List."
		" unless variable is TS (in which case it would contain 4 16 byte timestamps)"
	};

	rc = argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
	if (rc || args.helpFlag) {
		goto out;
	}

	rc = verify(args.currentVars, args.currVarCount, args.updateVars, args.updateVarCount,
		    args.pathToSecVars, args.writeFlag);

out:
	if (args.currentVars)
		free(args.currentVars);
	if (args.updateVars)
		free(args.updateVars);
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
	int current, rc = SUCCESS;

	switch (key) {
	case '?':
		args->helpFlag = 1;
		argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
		break;
	case ARGP_OPT_USAGE_KEY:
		args->helpFlag = 1;
		argp_state_help(state, stdout, ARGP_HELP_USAGE);
		break;
	case 'p':
		args->pathToSecVars = arg;
		break;
	case 'w':
		args->writeFlag = 1;
		break;
	case 'v':
		verbose = PR_DEBUG;
		break;
	case 'u':
		if (args->updateVars) {
			prlog(PR_ERR, "ERROR: Update variables defined twice, see usage...\n");
			argp_usage(state);
			rc = ARG_PARSE_FAIL;
			break;
		}
		current = state->next - 1;
		while (state->next != state->argc && state->argv[state->next][0] != '-')
			state->next++;
		args->updateVarCount = (state->next - current);
		args->updateVars = malloc(sizeof(char *) * args->updateVarCount);
		if (!args->updateVars) {
			prlog(PR_ERR, "ERROR: failed to allocate memory\n");
			rc = ALLOC_FAIL;
			break;
		}
		memcpy(args->updateVars, &state->argv[current],
		       args->updateVarCount * sizeof(char *));
		break;
	case 'c':
		if (args->currentVars) {
			prlog(PR_ERR, "ERROR: Current variables defined twice, see usage...\n");
			argp_usage(state);
			rc = ARG_PARSE_FAIL;
			break;
		}
		current = state->next - 1;
		while (state->next != state->argc && state->argv[state->next][0] != '-')
			state->next++;
		args->currVarCount = (state->next - current);
		args->currentVars = malloc(sizeof(char *) * args->currVarCount);
		if (!args->currentVars) {
			prlog(PR_ERR, "ERROR: failed to allocate memory\n");
			rc = ALLOC_FAIL;
			break;
		}
		memcpy(args->currentVars, &state->argv[current],
		       args->currVarCount * sizeof(char *));
		break;
	case ARGP_KEY_SUCCESS:
		// check that all essential args are given and valid
		if (args->helpFlag)
			break;
		if (!args->updateVarCount || args->updateVarCount <= 1)
			prlog(PR_ERR,
			      "ERROR: No update variables/files given, use -u <varName_1> <authFileForVar_1>...\n\t\t"
			      "Where <varName> is one of {'PK','KEK','db','dbx'} and <authFileForVar> is "
			      "a properly generated authenticated variable file\n");
		else if (validateVarsArg(args->updateVars, args->updateVarCount))
			prlog(PR_ERR,
			      "ERROR: Update vars list not in right format: "
			      "-u <varName_1> <authFileForVar_1> <varName_2> <authFileForVar_2> ...\n\t\t"
			      "Where <varName> is one of {'PK','KEK','db','dbx'} and <authFileForVar> is "
			      "a properly generated authenticated variable file\n");
		else if (args->currVarCount) {
			if (args->writeFlag)
				prlog(PR_ERR,
				      "ERROR: Cannot update files if current variable files are given. remove -w\n");
			else if (validateVarsArg((const char **)args->currentVars,
						 args->currVarCount))
				prlog(PR_ERR,
				      "ERROR: Current vars list not in right format: "
				      "<varName_1> <eslFileForVar_1> <varName_2> <eslFileForVar_2> ...\n\t\t"
				      "Where <varName> is one of {'PK','KEK','db','dbx', 'TS'} and <eslFileForVar> is an"
				      " EFI Signature List file (unless TS variable)\n");
			else
				break;
		} else
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
 *runs actual verification process
 *@param currentVars holds content of -c argument/or null if no -c
 *@param currCount length of currentVars
 *@param updateVars holds content of -u argument
 *@param updateCount length of updateVars
 *@param path holds path if -p option or null if no -p
 *@param writeFlag 0 if -w no given, 1 if given
 *@return SUCCESS or error value
 */
static int verify(char *currentVars[], int currCount, const char *updateVars[], int updateCount,
		  const char *path, int writeFlag)
{
	int rc;
	struct list_head update_bank, variable_bank, update_bank_copy;
	list_head_init(&variable_bank);
	list_head_init(&update_bank);
	list_head_init(&update_bank_copy);
	// set default path if no path chosen
	if (!path) {
		path = SECVARPATH;
	}
	rc = setupBanks(&variable_bank, &update_bank, currentVars, currCount, updateVars,
			updateCount, path);
	if (rc) {
		prlog(PR_ERR, "ERROR:Could not initialize banks\n");
		goto out;
	}
	rc = validateBanks(&update_bank, &variable_bank);
	if (rc) {
		prlog(PR_ERR, "ERROR:Could not validate data in banks\n");
		goto out;
	}
	// run preprocess
	rc = edk2_compatible_v1.pre_process(&variable_bank, &update_bank);
	if (rc) {
		prlog(PR_ERR, "ERROR: Failed in preprocessing OPAL ERR = %d = %s\n", rc,
		      opalErrToString(rc));
		goto out;
	}
	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "PRE PROCESSING BANKS:\n");
		printBanks(&variable_bank, &update_bank);
	}
	// create copy of update_bank (it changes after process) and if we write, we are going to want to have original auth's
	if (writeFlag)
		copy_bank_list(&update_bank_copy, &update_bank);
	// run process
	rc = edk2_compatible_v1.process(&variable_bank, &update_bank);
	if (rc) {
		prlog(PR_ERR, "ERROR: Failed in processing OPAL ERR = %d = %s\n", rc,
		      opalErrToString(rc));
		goto out;
	}
	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "POST PROCESSING BANKS:\n");
		printBanks(&variable_bank, &update_bank);
	}
	// if -w argument given then submit the update
	if (writeFlag) {
		rc = commitUpdateBank(&update_bank_copy, path);
		if (rc) {
			prlog(PR_ERR, "ERROR: Failed in submitting update #%d\n", rc);
			goto out;
		}
	}

out:
	clear_bank_list(&variable_bank);
	clear_bank_list(&update_bank);
	clear_bank_list(&update_bank_copy);
	return rc;
}

/**
 *parses arrays into banks with appropriate data
 *@param variable_bank will be filled with data depending on currentVars
 *@param update_bank will be filled with data dependent on updateVars
 *@param currentVars holds content of -c argument/or null if no -c
 *@param currCount length of currentVars
 *@param updateVars holds content of -u argument
 *@param updateCount length of updateVars
 *@param path holds path to current vars
 *@return SUCCESS or error value
 */
static int setupBanks(struct list_head *variable_bank, struct list_head *update_bank,
		      char *currentVars[], int currCount, const char *updateVars[], int updateCount,
		      const char *path)
{
	int defaultVarsFlag = 0;
	size_t len;
	struct secvar *tmp = NULL;
	char *c;

	// if current vars string is given, check it. if not, get default/path vars
	if (!currentVars) {
		defaultVarsFlag = 1;
		// max length of this array is #OfVars *2 b/c max contents= {Pk, path/pk/data, KEK, path/kek/data,etc}
		currentVars = calloc(1, sizeof(char *) * ARRAY_SIZE(variables) * 2);
		if (!currentVars) {
			prlog(PR_ERR, "ERROR: failed to allocate memory\n");
			return ALLOC_FAIL;
		}
		// unlikely fail, if alloc fails
		if (getCurrentVars(currentVars, &currCount, path)) {
			prlog(PR_ERR, "Could not get current variables from path %s\n", path);
			return INVALID_FILE;
		}
	}

	// once here, strings should be ready, it is time to fill banks
	// fill update bank with all updates
	for (int i = 0; i < updateCount; i += 2) {
		c = getDataFromFile((char *)updateVars[i + 1], &len);
		if (c) {
			list_add_tail(update_bank, &new_secvar(updateVars[i],
							       strlen(updateVars[i]) + 1, c, len, 0)
							    ->link);
			free(c);
		} else
			prlog(PR_INFO, "Failed to open %s, not adding it to list\n",
			      updateVars[i + 1]);
	}
	// fill variable bank with current vars
	for (int i = 0; i < currCount; i += 2) {
		if (defaultVarsFlag) {
			// if getting secvar successful add tmp to list
			if (!getSecVar(&tmp, currentVars[i], currentVars[i + 1]))
				list_add_tail(variable_bank, &tmp->link);

		} else {
			c = getDataFromFile((char *)currentVars[i + 1], &len);
			if (c) {
				list_add_tail(variable_bank,
					      &new_secvar(currentVars[i],
							  strlen(currentVars[i]) + 1, c, len, 0)
						       ->link);
				free(c);
			} else
				prlog(PR_INFO, "Failed to open %s, not adding it to list\n",
				      currentVars[i + 1]);
		}
	}
	// cleanup because of dynamically allocated memory of default paths, need to cleanup pointer to array and pointer to strings
	if (defaultVarsFlag) {
		for (int i = 0; i < currCount; i++)
			free(currentVars[i]);
		free(currentVars);
		currentVars = NULL;
	}

	return SUCCESS;
}

/**
 *runs validation function on data in banks, esl validation for variable bank and auth validation for update bank
 *@param variable_bank list of secvar's of current variables
 *@param update_bank list of secvar's of update variables
 *@return SUCCESS or error value if any files fail
 */
static int validateBanks(struct list_head *update_bank, struct list_head *variable_bank)
{
	int rc = SUCCESS;
	struct secvar *var = NULL;

	// validate all data in both banks using efi-validate
	list_for_each (update_bank, var, link) {
		prlog(PR_INFO, "----VALIDATING UPDATE FOR %s----\n", var->key);
		// return early if they try to update TS
		if (strcmp(var->key, "TS") == 0) {
			rc = INVALID_VAR_NAME;
			prlog(PR_ERR,
			      "ERROR: Invalid variable %s, cannot update Timestamp variable\n",
			      var->key);
			return rc;
		}
		rc = validateAuth((unsigned char *)var->data, var->data_size, var->key);
		if (rc) {
			prlog(PR_ERR, "ERROR: failed to validate Auth file for %s, returned %d\n",
			      var->key, rc);
			return rc;
		}
	}

	// if no PK then were in setup mode so skip vallidation of current keys
	if (find_secvar("PK", 3, variable_bank)) {
		list_for_each (variable_bank, var, link) {
			prlog(PR_INFO, "----VALIDATING CURRENT VAR: %s----\n", var->key);
			if (strcmp(var->key, "TS") == 0)
				rc = validateTS((unsigned char *)var->data, var->data_size);
			else
				rc = validateESL((unsigned char *)var->data, var->data_size,
						 var->key);
			if (rc) {
				prlog(PR_ERR,
				      "ERROR: failed to validate data file for %s,returned %d\n",
				      var->key, rc);
				return rc;
			}
		}
	} else
		prlog(PR_WARNING,
		      "WARNING: No PK, entering setup mode, no validation on current keys will be done\n");

	// print current contents of banks
	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "Current Variables are : ");
		list_for_each (variable_bank, var, link) {
			prlog(PR_INFO, "%s ", var->key);
		}
		prlog(PR_INFO, "\n");
		prlog(PR_INFO, "Update Variables are : ");
		list_for_each (update_bank, var, link) {
			prlog(PR_INFO, "%s ", var->key);
		}
		prlog(PR_INFO, "\n");
	}

	return rc;
}

/**
 *ensures the strings are in right format: <key> <file> <key> <file>
 *@param vars , array of strings from argument -c/-u
 *@param size, size of vars array
 *@return SUCCESS or error code if ordering or format is wrong
 */
static int validateVarsArg(const char *vars[], int size)
{
	if (size % 2) {
		prlog(PR_ERR,
		      "ERROR: when parsing variable list, expected every variable name to have exactly one corresponding file\n");
		return ARG_PARSE_FAIL;
	}
	for (int i = 0; i < size; i++) {
		// if odd number expect file name, not a var name
		if (i % 2) {
			if (!isVariable(vars[i])) {
				prlog(PR_ERR,
				      "ERROR: when parsing variable list argument, found variable name %s, when file name was expected\n",
				      vars[i]);
				return ARG_PARSE_FAIL;
			}
		}
		// if even number, expect variable name
		else {
			if (isVariable(vars[i])) {
				prlog(PR_ERR,
				      "ERROR: when parsing variable list argument, found unrecognized variable name %s, when variable name was expected\n",
				      vars[i]);
				return ARG_PARSE_FAIL;
			}
		}
	}

	return SUCCESS;
}

/**
 *called if -c not used, tries to find the variables in the path/default path
 *@param newCurr , empty array of strings to be filled
 *@param size , pointer to integer to be filled with length of newCurr
 *@param path , path to the location of the subdirectories {"PK", "KEK", "db", "dbx", "TS"}
 *@return the return of the validation of newCurr, SUCCESS if everything is ordered and formated right
 */
static int getCurrentVars(char *newCurr[], int *size, const char *path)
{
	int lenCtr = 0, i, offset = 0;
	char *ext = "/data";
	char *fullPath = NULL;
	for (i = 0; i < ARRAY_SIZE(variables); i++) {
		fullPath = malloc(strlen(path) + strlen(variables[i]) + strlen(ext) + 1);
		if (!fullPath) {
			prlog(PR_ERR, "ERROR: failed to allocate memory\n");
			return ALLOC_FAIL;
		}
		strcpy(fullPath, path);
		offset += strlen(path);
		strncpy(fullPath + offset, variables[i], strlen(variables[i]));
		offset += strlen(variables[i]);
		strncpy(fullPath + offset, ext, strlen(ext) + 1);
		// if it is a file then add variable name and data file to newCurr
		if (!isFile(fullPath)) {
			newCurr[lenCtr] = malloc(strlen(variables[i]) + 1);
			if (!newCurr[lenCtr]) {
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				free(fullPath);
				return ALLOC_FAIL;
			}
			strncpy(newCurr[lenCtr++], variables[i], strlen(variables[i]) + 1);
			newCurr[lenCtr] = malloc(strlen(fullPath) + 1);
			if (!newCurr[lenCtr]) {
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				free(fullPath);
				return ALLOC_FAIL;
			}

			strcpy(newCurr[lenCtr++], fullPath);
		}
		offset = 0;
		free(fullPath);
		fullPath = NULL;
	}
	*size = lenCtr;

	return validateVarsArg((const char **)newCurr, *size);
}

/**
 *prints the name and size of each secvar in the banks
 *@param variable_bank list of secvar's of current variables
 *@param update_bank list of secvar's of update variables
 */
static void printBanks(struct list_head *variable_bank, struct list_head *update_bank)
{
	struct secvar *var = NULL;
	printf("----CONTENTS OF UPDATE BANK----\n");
	list_for_each (update_bank, var, link) {
		printf("SecVar for %s contains %zd bytes of data\n", var->key, var->data_size);
	}

	printf("----CONTENTS OF VARIABLE BANK----\n");
	list_for_each (variable_bank, var, link) {
		printf("SecVar for %s contains %zd bytes of data\n", var->key, var->data_size);
	}
}

/**
 *calls the write function for every secvar in the update bank
 *@param update_bank list of secvar's of update variables
 *@param path , path to the location of the variables
 *@return SUCCESS or error depending if write function was successful for every variable
 */
static int commitUpdateBank(struct list_head *update_bank, const char *path)
{
	int rc = INVALID_FILE;
	struct secvar *var = NULL;
	list_for_each (update_bank, var, link) {
		prlog(PR_INFO, "Writing new %s with %zd bytes of data to %s%s/update\n", var->key,
		      var->data_size, path, var->key);
		rc = updateVar(path, var->key, (unsigned char *)var->data, var->data_size);
		if (rc) {
			prlog(PR_ERR, "ERROR: issue writing to file #%d\n",
			      rc); // consider continuing
			return rc;
		}
	}

	return rc;
}

/*
 *will return a string describing the returned opal return code 
 *@rc, the return code
 *@return, a string describing the return error
 */
static char *opalErrToString(int rc)
{
	switch (rc) {
	case OPAL_NO_MEM:
		return "Memory Allocation Failure";
	case OPAL_EMPTY:
		return "Empty List Error";
	case OPAL_PERMISSION:
		return "Permissions Error";
	case OPAL_INTERNAL_ERROR:
		return "Backend Internal Error";
	case OPAL_PARAMETER:
		return "Invalid Input Data";
	default:
		return "Unknown OPAL Error";
	}
}
