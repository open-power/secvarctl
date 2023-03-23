/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 IBM Corp.
 */
#ifndef SECVARCTL_H
#define SECVARCTL_H

#include <stdint.h>
#include "err.h"
#include "prlog.h"

enum backends
{
  UNKNOWN_BACKEND = 0,
  BACKEND_FOUND
};

struct backend
{
  char name[32];
  size_t countCmds;
  struct command *commands;
};

extern int verbose;

#endif
