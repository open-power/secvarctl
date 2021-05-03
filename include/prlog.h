// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef PRLOG_H
#define PRLOG_H
#include <stdio.h>
extern int verbose;
#define MAXLEVEL verbose
#define PR_EMERG 0
#define PR_ALERT 1
#define PR_CRIT 2
#define PR_ERR 3
#define PR_WARNING 4
#define PR_NOTICE 5
#define PR_PRINTF PR_NOTICE
#define PR_INFO 6
#define PR_DEBUG 7
#define prlog(l, ...)                                                          \
	do {                                                                   \
		if (l <= MAXLEVEL)                                             \
			fprintf((l <= PR_ERR) ? stderr : stdout,               \
				##__VA_ARGS__);                                \
	} while (0)
#endif