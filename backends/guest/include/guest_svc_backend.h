/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023 IBM Corp.
 */
#ifndef GUEST_BACKEND_H
#define GUEST_BACKEND_H

#include <stdio.h>
#include <stdint.h>
#include "generic.h"

/*
 * called from main()
 * handles argument parsing for validate command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
 */
int guest_validation_command(int argc, char *argv[]);

/*
 * called from main()
 * handles argument parsing for read command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
 */
int guest_read_command(int argc, char *argv[]);

/*
 * called from main()
 * handles argument parsing for generate command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
 */
int guest_generate_command(int argc, char *argv[]);

/*
 * performs verification command, called from main
 *
 * @param argc number of items in arg command
 * @param argv arguments array
 * @return SUCCESS if everything works, error code if not
 */
int guest_verify_command(int argc, char *argv[]);

/*
 * handles argument parsing for write command
 *
 * @param argc, number of argument
 * @param arv, array of params
 * @return SUCCESS or err number
*/
int guest_write_command(int argc, char *argv[]);

extern int verbose;
extern struct command guest_command_table[5];

#endif
