// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "prlog.h"
#include "secvarctl.h"

int verbose = PR_WARNING;
static struct backend *getBackend();

static struct backend backends[] = {
	{ .name = "ibm,edk2-compat-v1",
	  .countCmds = sizeof(edk2_compat_command_table) / sizeof(struct command),
	  .commands = edk2_compat_command_table },
};

void usage()
{
	printf("USAGE: \n\t$ secvarctl [COMMAND]\n"
	       "COMMANDs:\n"
	       "\t--help/--usage\n\t"
	       "read\t\tprints info on secure variables,\n\t\t\t"
	       "use 'secvarctl read --usage/help' for more information\n\t"
	       "write\t\tupdates secure variable with new auth,\n\t\t\t"
	       "use 'secvarctl write --usage/help' for more information"
	       "\n\tvalidate\tvalidates format of given esl/cert/auth,\n\t\t\t"
	       "use 'secvarctl validate --usage/help' for more information\n\t"
	       "verify\t\tcompares proposed variable to the current variables,\n\t\t\t"
	       "use 'secvarctl verify --usage/help' for more information\n"
#ifndef NO_CRYPTO
	       "\tgenerate\tcreates relevant files for secure variable management,\n\t\t\t"
	       "use 'secvarctl generate --usage/help' for more information\n"
#endif
	);
}
void help()
{
	printf("HELP:\n\t"
	       "A command line tool for simplifying the reading and writing of secure boot variables.\n\t"
	       "Commands are:\n\t\t"
	       "read - print out information on their current secure vaiables\n\t\t"
	       "write - update the given variable's key value, committed upon reboot\n\t\t"
	       "validate  -  checks format requirements are met for the given file type\n\t\t"
	       "verify - checks that the given files are correctly signed by the current variables\n"
#ifndef NO_CRYPTO
	       "\t\tgenerate - create files that are relevant to the secure variable management process\n"
#endif
	);
	usage();
}

int main(int argc, char *argv[])
{
	int rc, i;
	char *subcommand = NULL;
	struct backend *backend = NULL;

	if (argc < 2) {
		usage();
		return ARG_PARSE_FAIL;
	}
	argv++;
	argc--;
	for (; argc > 0 && *argv[0] == '-'; argc--, argv++) {
		if (!strcmp(*argv, "--usage")) {
			usage();
			return SUCCESS;
		} else if (!strcmp(*argv, "--help")) {
			help();
			return SUCCESS;
		}
		if (!strcmp(*argv, "-v")) {
			verbose = PR_DEBUG;
		}
	}
	if (argc <= 0) {
		prlog(PR_ERR, "ERROR: No command found\n");
		return ARG_PARSE_FAIL;
	}

	// if backend is not edk2-compat print continuing despite some funtionality not working
	backend = getBackend();
	if (!backend) {
		prlog(PR_WARNING,
		      "WARNING: Unsupported backend detected, assuming ibm,edk2-compat-v1 backend\nRead/write may not work as expected\n");
		backend = &backends[0];
	}

	// next command should be one of main subcommands
	subcommand = *argv;

	rc = UNKNOWN_COMMAND;
	for (i = 0; i < backend->countCmds; i++) {
		if (!strncmp(subcommand, backend->commands[i].name, 32)) {
			rc = backend->commands[i].func(argc, argv);
			break;
		}
	}
	if (rc == UNKNOWN_COMMAND) {
		prlog(PR_ERR, "ERROR:Unknown command %s\n", subcommand);
		usage();
	}

	return rc;
}

/*
 *Checks what backend the platform is running, CURRENTLY ONLY KNOWS EDK2
 *@return type of backend, or NULL if file could not be found or contained wrong contents,
 */
static struct backend *getBackend()
{
	char *buff = NULL, *secVarFormatLocation = "/sys/firmware/secvar/format";
	size_t buffSize;
	struct backend *result = NULL;
	// if file doesnt exist then print warning and keep going
	if (isFile(secVarFormatLocation)) {
		prlog(PR_WARNING, "WARNING!! Platform does not support secure variables\n");
		goto out;
	}
	buff = getDataFromFile(secVarFormatLocation, &buffSize);
	if (!buff) {
		prlog(PR_WARNING,
		      "WARNING!! Could not extract data from %s , assuming platform does not support secure variables\n",
		      secVarFormatLocation);
		goto out;
	}
	// loop through all known backends
	for (int i = 0; i < sizeof(backends) / sizeof(struct backend); i++) {
		if (!strncmp(buff, backends[i].name, strlen(backends[i].name))) {
			prlog(PR_NOTICE, "Found Backend %s\n", backends[i].name);
			result = &backends[i];
			goto out;
		}
	}
	prlog(PR_WARNING, "WARNING!! %s  does not contain known backend format.\n",
	      secVarFormatLocation);

out:
	if (buff)
		free(buff);

	return result;
}
