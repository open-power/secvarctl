/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 IBM Corp.
 */
#ifndef GENERIC_H
#define GENERIC_H

#include <stdint.h>
#include <stddef.h>

#define ARGP_OPT_USAGE_KEY 0x100

struct command {
	char name[32];
	int (*func)(int, char **);
};

uint8_t *get_data_from_file(const char *file, size_t max_size, size_t *size);
int write_data_to_file(const char *file, const char *buff, size_t size);
int create_file(const char *file, const uint8_t *buff, size_t size);
void print_raw(const uint8_t *c, size_t size);
int is_file(const char *path);
void print_hex(const uint8_t *data, size_t length);
int realloc_array(void **arr, size_t new_length, size_t size_each);

#endif
