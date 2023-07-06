/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023 IBM Corp.
 */
#ifndef VERIFY_H
#define VERIFY_H

#include <stdint.h>
#include <argp.h>
#include "pseries.h"
#include "common/read.h"

struct verify_args {
	int help_flag;
	int write_flag;
	int update_variable_size;
	int current_variable_size;
	const char *variable_path;
	const char **update_variable;
	const char **current_variable;
};

int verify_variables(struct verify_args *args);

int parse_variable_arguments(struct argp_state *state, const char ***variables, int *variable_size);

int validate_variables_arguments(struct verify_args *args);

#endif
