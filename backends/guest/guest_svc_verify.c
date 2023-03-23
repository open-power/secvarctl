/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "err.h"
#include "prlog.h"
#include "common/verify.h"
#include "guest_svc_backend.h"

/*
 * @param key , every option that is parsed has a value to identify it
 * @param arg, if key is an option than arg will hold its value ex: -<key> <arg>
 * @param state,  argp_state struct that contains useful information about the current parsing state
 * @return success or errno
 */
static int
parse_options (int key, char *arg, struct argp_state *state)
{
  struct verify_args *args = state->input;
  int rc = SUCCESS;

  switch (key)
    {
      case '?':
        args->help_flag = 1;
        argp_state_help (state, stdout, ARGP_HELP_STD_HELP);
        break;
      case ARGP_OPT_USAGE_KEY:
        args->help_flag = 1;
        argp_state_help (state, stdout, ARGP_HELP_USAGE);
        break;
      case 'p':
        args->variable_path = arg;
        break;
      case 'w':
        args->write_flag = 1;
        break;
      case 'v':
        verbose = PR_DEBUG;
        break;
      case 'u':
        if (args->update_variable)
          {
            prlog (PR_ERR,
                   "ERROR: update variables defined twice, see usage...\n");
            argp_usage (state);
            return ARG_PARSE_FAIL;
          }

        rc = parse_variable_arguments (state, &args->update_variable, &args->update_variable_size);
        if (rc != SUCCESS)
          return rc;
        break;
      case 'c':
        if (args->current_variable)
          {
            prlog (PR_ERR,
                   "ERROR: current variables defined twice, see usage...\n");
            argp_usage (state);
            return ARG_PARSE_FAIL;
          }

        rc = parse_variable_arguments (state, &args->current_variable, &args->current_variable_size);
        if (rc != SUCCESS)
          return rc;
        break;
      case ARGP_KEY_SUCCESS:
        if (args->help_flag)
          break;
        else if ((rc = validate_variables_arguments (args)) != SUCCESS)
          return rc;
        break;
        argp_usage (state);
        rc = ARG_PARSE_FAIL;
        break;
    }

  if (rc)
    prlog (PR_ERR, "failed during argument parsing\n");

  return rc;
}

/*
 * performs verification command, called from main
 *
 * @param argc number of items in arg command
 * @param argv arguments array
 * @return SUCCESS if everything works, error code if not
 */
int
guest_verify_command (int argc, char *argv[])
{
  int rc;
  struct verify_args args = { .help_flag = 0,
                              .write_flag = 0,
                              .variable_path = NULL,
                              .update_variable = NULL,
                              .current_variable = NULL,
                              .update_variable_size = 0,
                              .current_variable_size = 0
                            };

  /* combine command and subcommand for usage/help messages */
  argv[0] = "secvarctl -m guest verify";

  struct argp_option options[] = {
    { "verbose", 'v', 0, 0, "print more verbose process information" },
    { "path", 'p', "PATH", 0,
      "manually set path to current variables, looks for .../<var>/data file "
      "in PATH, default is " SECVARPATH " . Cannot be used with `-c` " },
    { "current", 'c', "{CURRENT VAR LIST}",
      0, "manually set current vars to be contents of CURRENT VAR LIST (see below for format)" },
    { "write", 'w', 0, 0, "if successful, submit the update to be commited upon reboot."
      " quivalent to `secvarctl -m guest write`" },
    { 0, 'u', "{UPDATE LIST}", OPTION_HIDDEN, "set update variables (see below for format)" },
    { "help", '?', 0, 0, "Give this help list", 1 },
    { "usage", ARGP_OPT_USAGE_KEY, 0, 0, "Give a short usage message", -1 },
    { 0 }
  };

  struct argp argp = {
    options, parse_options, "-u {UPDATE LIST}",
    "This command ensures that the proposed variable updates are"
    " correctly signed by the current variables. If successful, then the user "
    "can run the same"
    " command with the '-w' flag or use 'secvarctl write' to submit the "
    "updates to be"
    " committed upon reboot\v"
    "UPDATE LIST:\nAt least one variable-file pair is required. Formatted as:"
    " ' -u <var_name 1> <var_auth_file 1>...<var_name N> <var_auth_file N> '"
    " Where <var_name> is one of Guest secure boot variable"
    " and <var_auth_file> is a properly generated authenticated variable file "
    "that is"
    " signed by a current variable with priviledges to approve the update\n\n"
    "CURRENT_VAR_LIST:\nOptional, only used when -c is used. formatted as:"
    " ' -c <var_name 1> < var_ESL_file 1>...<var_name N> <var_ESL_file N> '"
    " Where <var_name> is one of Guest secure boot variable and"
    " <var_ESL_file> is an EFI Signature List file."
  };

  rc = argp_parse (&argp, argc, argv, ARGP_NO_EXIT | ARGP_IN_ORDER | ARGP_NO_HELP, 0, &args);
  if (rc == SUCCESS)
    rc = verify_variables (&args);

  if (args.current_variable != NULL)
    free (args.current_variable);

  if (args.update_variable != NULL)
    free (args.update_variable);

  if (!args.help_flag)
    printf ("RESULT: %s\n", (rc != DELETE_EVERYTHING && rc != SUCCESS ? "FAILURE" : "SUCCESS"));

  return rc;
}
