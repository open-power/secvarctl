/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "err.h"
#include "prlog.h"
#include "generic.h"

/*
 * determines if given file currently exists
 * @param path , full path wih file name
 * @return SUCCESS if it exists, error otherwise
 */
int is_file(const char *path)
{
	int fptr;

	fptr = open(path, O_RDONLY);
	if (fptr < 0)
		return INVALID_FILE;

	close(fptr);

	return SUCCESS;
}

void print_hex(const uint8_t *data, size_t length)
{
	int i;

	for (i = 0; i < length - 1; i++)
		printf("%02x:", data[i]);

	printf("%02x\n", data[i]);
}

/*
 * prints raw data of the given buffer
 * @param c pointer to buffer
 * @param size length of buffer
 */
void print_raw(const char *c, size_t size)
{
	for (int i = 0; i < size; i++)
		printf("%c", *(c + i));
	printf("\n\n");
}

/*
 * This Function returns a pointer to allocated memory that holds the data from the file
 * @param fullPath string of file with path
 * @param max number of bytes to read or SIZE_MAX for read entire file
 * @param size address of unitialized int memory that will be filled with length of returned char*
 * @return NULL if cannot open file or read file
 * @return char* to allocted data of file
 * NOTE:REMEMBER TO UNALLOCATE RETURNED DATA
 */
char *get_data_from_file(const char *fullPath, size_t max_bytes, size_t *size)
{
	int fptr;
	char *buffer = NULL;
	struct stat fileInfo;
	ssize_t read_size;

	fptr = open(fullPath, O_RDONLY);
	if (fptr < 0) {
		prlog(PR_WARNING, "----opening %s failed : %s----\n", fullPath, strerror(errno));
		return buffer;
	}

	if (fstat(fptr, &fileInfo) < 0)
		goto out;

	if (fileInfo.st_size <= 0)
		prlog(PR_WARNING, "WARNING: file %s is empty\n", fullPath);

	if (max_bytes > fileInfo.st_size)
		max_bytes = fileInfo.st_size;

	prlog(PR_NOTICE, "----opening %s is success: reading %zu bytes----\n", fullPath, max_bytes);

	buffer = malloc(max_bytes);
	if (!buffer) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		goto out;
	}

	read_size = read(fptr, buffer, max_bytes);
	if (read_size > max_bytes) {
		prlog(PR_ERR, "ERROR: failed to read whole contents of %s in one go\n", fullPath);
		free(buffer);
		buffer = NULL;
		goto out;
	} else
		*size = read_size;

out:
	close(fptr);

	return buffer;
}

/*
 * writes size bytes of buff to
 * @param file string to file
 * @param authBuf pointer to auth data
 * @param size length of data
 * @return negative int, error if opening/writing to .../update file
 * @return 0 for success or error number
 */
int write_data_to_file(const char *file, const char *buff, size_t size)
{
	int rc, fptr;

	fptr = open(file, O_WRONLY | O_TRUNC);
	if (fptr == -1) {
		prlog(PR_ERR, "ERROR: Opening %s failed: %s\n", file, strerror(errno));
		return INVALID_FILE;
	}

	rc = write(fptr, buff, size);
	if (rc < 0) {
		prlog(PR_ERR, "ERROR: Writing data to %s failed\n", file);
		return FILE_WRITE_FAIL;
	} else if (rc == 0)
		prlog(PR_WARNING, "End of file reached, not all of file was written to %s\n", file);
	else
		prlog(PR_NOTICE, "%d/%zu bytes successfully written from file to %s\n", rc, size,
		      file);

	close(fptr);

	return SUCCESS;
}

/*
 * writes size bytes of buff to new file
 * @param file string to file
 * @param authBuf pointer to auth data
 * @param size length of data
 * @return negative int, error if opening/writing to .../update file
 * @return 0 for success or error number
 */
int create_file(const char *file, const char *buff, size_t size)
{
	int rc, fptr;

	/* create and set permissions */
	fptr = open(file, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fptr == -1) {
		prlog(PR_ERR, "ERROR: Opening %s failed: %s\n", file, strerror(errno));
		return INVALID_FILE;
	}

	rc = write(fptr, buff, size);
	if (rc < 0) {
		prlog(PR_ERR, "ERROR: Writing data to %s failed: %s\n", file, strerror(errno));
		return FILE_WRITE_FAIL;
	} else if (rc == 0)
		prlog(PR_WARNING, "End of file reached, not all of file was written to %s\n", file);
	else
		prlog(PR_NOTICE, "%d/%zu bytes successfully written from file to %s\n", rc, size,
		      file);

	close(fptr);

	return SUCCESS;
}

/*
 * returns a new pointer to an array with new length
 * @param arr , a pointer to the array, will be reallocated to have new_length*size_each bytes
 *              or NULL if error
 * @param new_length , the desired number of elements
 * @param size_each , size of each elements
 * @return 0 for success or ALLOC_FAIL if fail (memory will be freed in this case)
 */
int realloc_array(void **arr, size_t new_length, size_t size_each)
{
	void *old_arr;
	size_t new_size;

	/* if realloc returns null it does not free memory so we must keep a pointer to it */
	old_arr = *arr;
	/* check if requested size is too big */
	if (__builtin_mul_overflow(new_length, size_each, &new_size)) {
		prlog(PR_ERR, "ERROR: Invalid size to alloc %zu * %zu\n", new_length, size_each);
		goto out;
	}

	*arr = realloc(*arr, size_each * new_length);
	if (*arr == NULL)
		goto out;

	return SUCCESS;

out:
	free(old_arr);

	return ALLOC_FAIL;
}
