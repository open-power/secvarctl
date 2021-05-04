// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#ifndef __SECVAR_EDK2_COMPAT_PROCESS__
#define __SECVAR_EDK2_COMPAT_PROCESS__

#ifndef pr_fmt
#define pr_fmt(fmt) "EDK2_COMPAT: " fmt
#endif

/*#include <opal.h>*/
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <ccan/endian/endian.h>
/*#include <mbedtls/error.h>
#include <device.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "external/skiboot/libstb/secvar/backend/edk2.h"
#include "opal-api.h"*/
#include "../secvar.h"
/*#include "../secvar_devtree.h"*/

//added by nick child/dja
#include <ccan/short_types/short_types.h>
#include "external/skiboot/include/opal-api.h"
//#include "external/extraMbedtls/include/pkcs7.h"
#include "external/skiboot/libstb/secvar/backend/edk2.h"
#include <compiler.h>

//ADDED BY NICK CHILD
#define PR_ERR		3
#define PR_WARNING	4
#define PR_NOTICE	5
#define PR_PRINTF	PR_NOTICE
#define PR_INFO		6
#define PR_DEBUG	7
#define CERT_BUFFER_SIZE        2048
//NICK CHILD, ABSTRACTING CRYPTO LIB
//#define MBEDTLS_ERR_BUFFER_SIZE 1024	
#define CRYPTO_ERR_BUFFER_SIZE 1024
#define zalloc(...) calloc(1,__VA_ARGS__)

#define EDK2_MAX_KEY_LEN        SECVAR_MAX_KEY_LEN
#define key_equals(a,b) (!strncmp(a, b, EDK2_MAX_KEY_LEN))
#define uuid_equals(a,b) (!memcmp(a, b, UUID_SIZE))

extern bool setup_mode;
extern struct list_head staging_bank;

/* Update the variable in the variable bank with the new value. */
int update_variable_in_bank(struct secvar *update_var, const char *data,
			    uint64_t dsize, struct list_head *bank);

/* This function outputs the Authentication 2 Descriptor in the
 * auth_buffer and returns the size of the buffer. Please refer to
 * edk2.h for details on Authentication 2 Descriptor
 */
int get_auth_descriptor2(const void *buf, const size_t buflen,
			 void **auth_buffer);

/* Check the format of the ESL */
int validate_esl_list(const char *key, const char *esl, const size_t size);

/* Update the TS variable with the new timestamp */
int update_timestamp(const char *key, const struct efi_time *timestamp, char *last_timestamp);

/* Check the new timestamp against the timestamp last update was done */
int check_timestamp(const char *key, const struct efi_time *timestamp, char *last_timestamp);

/* Check the GUID of the data type */
bool is_pkcs7_sig_format(const void *data);

/* Process the update */
int process_update(const struct secvar *update, char **newesl,
		   int *neweslsize, struct efi_time *timestamp,
		   struct list_head *bank, char *last_timestamp);


/* Functions used by external secvarctl */

/**
 * Parse a buffer into a EFI_SIGNATURE_LIST structure
 * @param buf pointer to a buffer containing an ESL
 * @param buflen length of buffer
 * @return NULL if buflen is smaller than size of sig list struct or if buf is NULL
 * @return EFI_SIGNATURE_LIST struct
 */
EFI_SIGNATURE_LIST* get_esl_signature_list(const char *buf, size_t buflen);

/**
 * Copies the certificate from the ESL into cert buffer and returns the size
 * of the certificate.
 * @param c Buffer containing an EFI Signature List
 * @param size size of buffer c
 * @param cert pointer to destination. Memory will be allocated for the certificate
 * @return size of memory allocated to cert or negative number if allocation fails
 */
int get_esl_cert(const char *buf, const size_t buflen, char **cert);

/*
 * Extracts size of the PKCS7 signed data embedded in the
 * struct Authentication 2 Descriptor Header.
 */
size_t get_pkcs7_len(const struct efi_variable_authentication_2 *auth);

#endif
