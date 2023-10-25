/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <esl.h> // libstb-secvar
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "util.h"
#include "common/util.h"
#include "common/read.h"

sv_esl_t *extract_esl_signature_list(const uint8_t *buf, size_t buflen)
{
	sv_esl_t *list = NULL;

	if (buflen < sizeof(sv_esl_t) || !buf) {
		prlog(PR_ERR, "ERROR: SigList does not have enough data to be valid\n");
		return NULL;
	}

	list = (sv_esl_t *)buf;

	return list;
}

/*
 * Copies the certificate from the ESL into cert buffer and returns the size
 * of the certificate
 */
int extract_esl_cert(const uint8_t *buf, const size_t buflen, uint8_t **cert)
{
	size_t sig_data_offset;
	size_t size;
	sv_esl_t *list = extract_esl_signature_list(buf, buflen);

	if (!list || cert == NULL)
		return -1;

	size = le32_to_cpu(list->signature_size) - sizeof(uuid_t);
	sig_data_offset =
		sizeof(sv_esl_t) + le32_to_cpu(list->signature_header_size) + 16 * sizeof(uint8_t);
	if (sig_data_offset > buflen)
		return -1;

	*cert = zalloc(size);
	if (!(*cert))
		return ALLOC_FAIL;

	/*
   * since buf can have more than one ESL, copy only the size calculated
   * to return single ESL
   */
	memcpy(*cert, buf + sig_data_offset, size);

	return size;
}

/*
 * prints guid id
 * @param sig pointer to uuid_t
 */
void print_signature_type(const void *sig)
{
	const unsigned char *p = sig;
	for (int i = 0; i < UUID_SIZE; i++)
		printf("%02hhx", p[i]);

	printf("\n");
}

/* prints info on ESL, nothing on ESL data */
void print_esl_info(sv_esl_t *sig_list)
{
	printf("\tESL SIG LIST SIZE: %u\n", sig_list->signature_list_size);
	printf("\tGUID is : ");
	print_signature_type(&sig_list->signature_type);
	printf("\tSignature type is: %s\n", get_signature_type_string(sig_list->signature_type));
}

/* prints info on x509 */
int print_cert_info(crypto_x509_t *x509)
{
	char *x509_info = NULL;
	int bytes_out;

	x509_info = calloc(1, CERT_BUFFER_SIZE);
	if (!x509_info) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return CERT_FAIL;
	}

	bytes_out = crypto_x509_get_long_desc(x509_info, CERT_BUFFER_SIZE, "\t\t", x509);
	if (bytes_out <= 0) {
		prlog(PR_ERR, "\tERROR: failed to get cert info,rc = %d\n", bytes_out);
		return CERT_FAIL;
	}

	printf("\tFound certificate info\n %s \n", x509_info);
	free(x509_info);

	return SUCCESS;
}

/*
 * prints ESDs inside an ESL buffer in human readable form
 *
 * @param esl, pointer to the beginning of valid esl data. NOTE: caller is responsible for validation
 * @param esl_size, size of the esl data buffer
 * @param sig_type, signature type enum as extracted from e.g. get_signature_type
 * @return SUCCESS or propogates error code
 */
static int print_esd_from_esl_buffer(const uint8_t *esl, size_t esl_size,
				     enum signature_type sig_type)
{
	crypto_x509_t *x509 = NULL;
	int rc;
	size_t esd_data_size, esd_count = 0;
	uuid_t esd_owner;
	union {
		const uint8_t *raw;
		sv_esd_t *esd;
	} curr_esd;
	curr_esd.raw = NULL;

	rc = next_esd_from_esl(esl, &curr_esd.raw, &esd_data_size, &esd_owner);
	if (rc) {
		prlog(PR_ERR, "Error reading esd from esl, rc = %d\n", rc);
		return rc;
	}

	while (curr_esd.esd != NULL) {
		esd_count++;
		switch (sig_type) {
		case ST_HASHES_START ... ST_HASHES_END:
			printf("\tData-%zu: ", esd_count);
			print_hex(curr_esd.raw, esd_data_size);
		case ST_X509:
			x509 = crypto_x509_parse_der(curr_esd.raw, esd_data_size);
			if (!x509)
				break;
			printf("\tCertificate-%zu: ", esd_count);
			rc = print_cert_info(x509);

			// we're done with the x509, free it immediately
			crypto_x509_free(x509);
			x509 = NULL;

			// ...then bail if there was an error printing the cert
			if (rc)
				return rc;

			break;
		case ST_SBAT:
			printf("\tData: ");
			print_raw((char *)curr_esd.raw, esd_data_size);
			break;
		case ST_DELETE:
			printf("\tDELETE-MSG: ");
			print_raw((char *)curr_esd.raw, esd_data_size);
			break;
		default:
			prlog(PR_ERR, "ERROR: unknown signature type = %d\n", sig_type);
			break;
		}

		rc = next_esd_from_esl(esl, &curr_esd.raw, &esd_data_size, &esd_owner);
		if (rc) {
			prlog(PR_ERR, "Error reading next esd (%zu), rc = %d\n", esd_count, rc);
			return rc;
		}
	}

	return SUCCESS;
}

/*
 * prints human readable data in of ESL buffer
 *
 * @param vuffer , buffer containing ESL data
 * @param buffer_size , length of buffer
 * @param var_name, secure boot variable name
 * @return SUCCESS or error number if failure
 */
int print_esl_buffer(const uint8_t *buffer, size_t buffer_size, const char *var_name)
{
	int rc;
	size_t esl_data_size = 0;
	size_t esl_count = 0;
	enum signature_type sig_type;

	union {
		const uint8_t *raw;
		sv_esl_t *esl;
	} curr_esl;
	curr_esl.raw = NULL;

	rc = next_esl_from_buffer(buffer, buffer_size, &curr_esl.raw, &esl_data_size);
	if (rc) {
		prlog(PR_ERR, "Error reading from esl buffer: %d\n", rc);
		return rc;
	}

	while (curr_esl.esl != NULL) {
		esl_count++;
		printf("ESL %zu:\n", esl_count);
		print_esl_info(curr_esl.esl);

		sig_type = get_signature_type(curr_esl.esl->signature_type);
		rc = print_esd_from_esl_buffer(curr_esl.raw, esl_data_size, sig_type);
		if (rc)
			return rc;

		rc = next_esl_from_buffer(buffer, buffer_size, &curr_esl.raw, &esl_data_size);
		if (rc) {
			prlog(PR_ERR, "Error reading next esl (%zu) from buffer: %d\n", esl_count,
			      rc);
			return rc;
		}
	}

	printf("\tFound %zu ESL's\n\n", esl_count);

	return SUCCESS;
}
