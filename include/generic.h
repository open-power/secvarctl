/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 IBM Corp.
 */
#ifndef GENERIC_H
#define GENERIC_H

#define ARGP_OPT_USAGE_KEY 0x100

struct command {
	char name[32];
	int (*func)(int, char **);
};

char *get_data_from_file(const char *file, size_t max_size, size_t *size);
int write_data_to_file(const char *file, const char *buff, size_t size);
int create_file(const char *file, const char *buff, size_t size);
void print_raw(const char *c, size_t size);
int is_file(const char *path);
size_t get_leading_whitespace(unsigned char *data, size_t dataSize);
void print_hex(unsigned char *data, size_t length);
int realloc_array(void **arr, size_t new_length, size_t size_each);

#endif
