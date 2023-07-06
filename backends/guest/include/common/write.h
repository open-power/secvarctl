/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023 IBM Corp.
 */
#ifndef WRITE_H
#define WRITE_H

#include <stdint.h>
#include "common/read.h"

struct write_args {
	int help_flag;
	int input_valid;
	const char *path;
	const char *variable_name;
	const char *input_file;
};

/*
 * ensures updating variable is a valid variable, creates full path to
 * .../update file, verifies auth file is valid
 *
 * @param variable_name, Guest secure boot variable name
 * @param auth_file, auth file name
 * @param path,  path to Guest secure boot variables directory
 * @param force, 1 for no validation of auth, 0 for validate
 * @return error if variable given is unknown, or issue validating or writing
 */
int write_variable(const uint8_t *variable_name, const uint8_t *auth_file, const uint8_t *path,
		   int force);

/*
 * updates a secure variable by writing data in buffer to the
 * <path>/<variable name>/update
 *
 * @param path, path to sec vars
 * @param variable_name, one of Guest secure boot variable
 * @param buffer , auth data
 * @param buffer_size , size of auth data
 * @return whatever returned by writeData, SUCCESS or errno
 */
int write_to_variable(const char *path, const char *variable_name, const uint8_t *buffer,
		      const size_t buffer_size);

#endif
