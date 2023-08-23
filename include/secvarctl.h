/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 IBM Corp.
 */
#ifndef SECVARCTL_H
#define SECVARCTL_H

#include <stdint.h>
#include "err.h"
#include "prlog.h"

struct backend {
	char format[32];
	size_t countCmds;
	struct command *commands;
};

extern int verbose;

#endif
