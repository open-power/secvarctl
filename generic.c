// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <stdio.h>
#include <string.h>
#include <errno.h> // strerror
#include <stdlib.h>
#include <fcntl.h> // O_WRONLY
#include <unistd.h> // has read/open funcitons
#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include "err.h"
#include "prlog.h"

/**
 *determines if given file currently exists
 *@param path , full path wih file name
 *@return SUCCESS if it exists, error otherwise
 */
int isFile(const char *path)
{
	int fptr;

	fptr = open(path, O_RDONLY);
	if (fptr < 0) {
		return INVALID_FILE;
	}
	close(fptr);

	return SUCCESS;
}

size_t getLeadingWhitespace(unsigned char *data, size_t dataSize)
{
	size_t whiteSpaceSize = 0;

	while ((whiteSpaceSize < dataSize) && data[whiteSpaceSize] == 0x00)
		whiteSpaceSize++;

	return whiteSpaceSize;
}
void printHex(unsigned char *data, size_t length)
{
	int i;
	for (i = 0; i < length - 1; i++)
		printf("%02x:", data[i]);
	printf("%02x\n", data[i]);
}

/**
 *prints raw data of the given buffer
 *@param c pointer to buffer
 *@param size length of buffer
 */
void printRaw(const char *c, size_t size)
{
	for (int i = 0; i < size; i++)
		printf("%c", *(c + i));
	printf("\n\n");
}

/**
 *This Function returns a pointer to allocated memory that holds the data from the file 
 *@param fullPath string of file with path
 *@param size address of unitialized int memory that will be filled with length of returned char*
 *@return NULL if cannot open file or read file
 *@return char* to allocted data of file with one extra '\0' for good measure
 *NOTE:REMEMBER TO UNALLOCATE RETURNED DATA
 **/
char *getDataFromFile(const char *fullPath, size_t *size)
{
	int fptr;
	char *c = NULL;
	struct stat fileInfo;
	ssize_t read_size;
	fptr = open(fullPath, O_RDONLY);
	if (fptr < 0) {
		prlog(PR_WARNING, "----opening %s failed : %s----\n", fullPath, strerror(errno));
		return NULL;
	}
	if (fstat(fptr, &fileInfo) < 0) {
		goto out;
	}
	if (fileInfo.st_size <= 0) {
		prlog(PR_WARNING, "WARNING: file %s is empty\n", fullPath);
	}
	prlog(PR_NOTICE, "----opening %s is success: reading %ld bytes----\n", fullPath,
	      fileInfo.st_size);
	c = malloc(fileInfo.st_size);
	if (!c) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		goto out;
	}
	read_size = read(fptr, c, fileInfo.st_size);
	if (read_size != fileInfo.st_size) {
		prlog(PR_ERR, "ERROR: failed to read whole contents of %s in one go\n", fullPath);
		free(c);
		c = NULL;
		goto out;
	}
	*size = fileInfo.st_size;
out:
	close(fptr);

	return c;
}

/*
 *writes size bytes of buff to 
 *@param file string to file
 *@param authBuf pointer to auth data
 *@param size length of data
 *@return negative int, error if opening/writing to .../update file
 *@return 0 for success or error number
 */
int writeData(const char *file, const char *buff, size_t size)
{
	int rc, fptr = open(file, O_WRONLY | O_TRUNC);
	if (fptr == -1) {
		prlog(PR_ERR, "ERROR: Opening %s failed: %s\n", file, strerror(errno));
		return INVALID_FILE;
	}
	rc = write(fptr, buff, size);
	if (rc < 0) {
		prlog(PR_ERR, "ERROR: Writing data to %s failed\n", file);
		return FILE_WRITE_FAIL;
	} else if (rc == 0) {
		prlog(PR_WARNING, "End of file reached, not all of file was written to %s\n", file);
	} else
		prlog(PR_NOTICE, "%d/%zd bytes successfully written from file to %s\n", rc, size,
		      file);
	close(fptr);

	return SUCCESS;
}

/*
 *writes size bytes of buff to new file
 *@param file string to file
 *@param authBuf pointer to auth data
 *@param size length of data
 *@return negative int, error if opening/writing to .../update file
 *@return 0 for success or error number
 */
int createFile(const char *file, const char *buff, size_t size)
{
	int rc;
	// create and set permissions
	int fptr = open(file, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fptr == -1) {
		prlog(PR_ERR, "ERROR: Opening %s failed: %s\n", file, strerror(errno));
		return INVALID_FILE;
	}
	rc = write(fptr, buff, size);
	if (rc < 0) {
		prlog(PR_ERR, "ERROR: Writing data to %s failed: %s\n", file, strerror(errno));
		return FILE_WRITE_FAIL;
	} else if (rc == 0) {
		prlog(PR_WARNING, "End of file reached, not all of file was written to %s\n", file);
	} else
		prlog(PR_NOTICE, "%d/%zd bytes successfully written from file to %s\n", rc, size,
		      file);
	close(fptr);

	return SUCCESS;
}

/*
 *returns a new pointer to an array with new length
 *@param arr , a pointer to the array, will be reallocated to have new_length*size_each bytes or NULL if error
 *@param new_length , the desired number of elements
 *@param size_each , size of each elements
 *@return 0 for success or ALLOC_FAIL if fail (memory will be freed in this case)
 */
int reallocArray(void **arr, size_t new_length, size_t size_each)
{
	void *old_arr;
	size_t new_size;
	//if realloc returns null it does not free memory so we must keep a pointer to it
	old_arr = *arr;
	//check if requested size is too big
	if (__builtin_mul_overflow(new_length, size_each, &new_size)) {
		prlog(PR_ERR, "ERROR: Invalid size to alloc %zd * %zd\n", new_length, size_each);
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
