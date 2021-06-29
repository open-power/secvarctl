// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef GENERIC_H
#define GENERIC_H

struct command {
	char name[32];
	int (*func)(int, char **);
};

char *getDataFromFile(const char *file, size_t max_size, size_t *size);
int writeData(const char *file, const char *buff, size_t size);
int createFile(const char *file, const char *buff, size_t size);
void printRaw(const char *c, size_t size);
int isFile(const char *path);
size_t getLeadingWhitespace(unsigned char *data, size_t dataSize);
void printHex(unsigned char *data, size_t length);
int reallocArray(void **arr, size_t new_length, size_t size_each);
#endif