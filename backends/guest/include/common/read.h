/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023 IBM Corp.
 */
#ifndef READ_H
#define READ_H

#include <stdint.h>
#include "common/util.h"

#define SECVARPATH "/sys/firmware/secvar/vars/"

struct read_args {
	int help_flag;
	int print_raw;
	const char *path;
	const char *variable_name;
	const char *input_file;
	enum file_types input_form;
};

sv_esl_t *extract_esl_signature_list(const uint8_t *buf, size_t buflen);

/*
 * Copies the certificate from the ESL into cert buffer and returns the size
 * of the certificate
 */
int extract_esl_cert(const uint8_t *buf, const size_t buflen, uint8_t **cert);

/*
 * parses x509 certficate buffer (PEM or DER) into certificate struct
 *
 * @param x509, returned pointer to address of x509,
 * @param certBuf pointer to certificate data
 * @param buflen length of certBuf
 * @return CERT_FAIL if certificate cant be parsed
 * @return SUCCESS if certificate is valid
 * NOTE: Remember to unallocate the returned x509 struct!
 */
int parse_x509_cert(crypto_x509_t **x509, const unsigned char *certBuf, size_t buflen);

/*
 * prints guid id
 * @param sig pointer to uuid_t
 */
void print_signature_type(const void *sig);

/* prints info on ESL, nothing on ESL data */
void print_esl_info(sv_esl_t *sig_list);

/* prints info on x509 */
int print_cert_info(crypto_x509_t *x509);

void print_timestamp(timestamp_t t);

/*
 * prints human readable data in of ESL buffer
 *
 * @param c , buffer containing ESL data
 * @param size , length of buffer
 * @param key, variable name {"db","dbx","KEK", "PK"} b/c dbx is a different format
 * @return SUCCESS or error number if failure
 */
int print_variables(const uint8_t *buffer, size_t buffer_size, const char *var_name);

#endif
