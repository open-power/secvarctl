/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "util.h"
#include "common/util.h"
#include "common/read.h"

void print_timestamp(timestamp_t t)
{
	printf("%04d-%02d-%02d %02d:%02d:%02d UTC\n", t.year, t.month, t.day, t.hour, t.minute,
	       t.second);
}

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
	printf("\tESL SIG LIST SIZE: %d\n", sig_list->signature_list_size);
	printf("\tGUID is : ");
	print_signature_type(&sig_list->signature_type);
	printf("\tSignature type is: %s\n", get_signature_type(sig_list->signature_type));
}

/* prints info on x509 */
int print_cert_info(crypto_x509_t *x509)
{
	char *x509_info = NULL;
	int failures;

	x509_info = calloc(1, CERT_BUFFER_SIZE);
	if (!x509_info) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return CERT_FAIL;
	}

	failures = crypto.read_x509_certificate_info("\t\t", x509, CERT_BUFFER_SIZE, &x509_info);
	if (failures != 0) {
		prlog(PR_ERR,
		      "\tERROR: failed to get cert info, wrote %d bytes when getting info\n",
		      failures);
		return CERT_FAIL;
	}

	printf("\tFound certificate info\n %s \n", x509_info);
	free(x509_info);

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
int print_variables(const uint8_t *buffer, size_t buffer_size, const uint8_t *var_name)
{
	int rc;
	ssize_t esl_data_size = buffer_size, cert_size;
	size_t esl_size = 0, next_esl_size = 0, data_size = 0;
	size_t sig_offset = 0, signature_size = 0, count = 0, offset = 0;
	uint8_t *cert = NULL, *signature_type = NULL, *esl_data = (uint8_t *)buffer;
	sv_esl_t *sig_list;
	sv_esd_t *esd = NULL;
	crypto_x509_t *x509 = NULL;

	while (esl_data_size > 0) {
		if (esl_data_size < sizeof(sv_esl_t)) {
			prlog(PR_ERR,
			      "ERROR: ESL has %zd bytes and is smaller than an ESL (%zd bytes),"
			      " remaining data not parsed\n",
			      esl_data_size, sizeof(sv_esl_t));
			break;
		}

		/* Get sig list */
		sig_list = extract_esl_signature_list(buffer + offset, esl_data_size);
		esl_size = sig_list->signature_list_size;
		signature_size = cpu_to_le32(sig_list->signature_size);
		signature_type = get_signature_type(sig_list->signature_type);

		if (esl_size < sizeof(sv_esl_t) || esl_size > esl_data_size) {
			prlog(PR_ERR, "ERROR: invalid ESL size (%lu)\n", esl_size);
			break;
		}

		print_esl_info(sig_list);
		next_esl_size = esl_size;
		offset = sizeof(sv_esl_t) + cpu_to_le32(sig_list->signature_header_size);
		esl_size = esl_size - offset;
		sig_offset = 0;

		/* reads the esd from esl */
		while (esl_size > 0) {
			esd = (sv_esd_t *)(esl_data + (offset + sig_offset));
			data_size = signature_size - sizeof(sv_esd_t);
			cert = esd->signature_data;
			cert_size = data_size;

			if (is_hash(signature_type)) {
				printf("\tData-%zu: ", count);
				print_hex(cert, cert_size);
			} else if (is_cert(signature_type)) {
				rc = crypto.get_x509_certificate(cert, cert_size, &x509);
				if (rc)
					break;
				printf("\tCertificate-%zu: ", count);
				rc = print_cert_info(x509);
				if (rc)
					break;

				crypto.release_x509_certificate(x509);
				x509 = NULL;
			} else if (is_sbat(signature_type)) {
				printf("\tData: ");
				print_raw((char *)cert, cert_size);
			} else if (is_delete(signature_type)) {
				printf("\tDELETE-MSG: ");
				print_raw((char *)cert, cert_size);
			} else {
				prlog(PR_ERR, "ERROR: invalid signature type\n");
				break;
			}

			count++;
			esl_size -= signature_size;
			sig_offset += signature_size;
		}

		/* we read all esl_size bytes so iterate to next esl */
		esl_data += next_esl_size;
		esl_data_size -= next_esl_size;
	}

	printf("\tFound %zu ESL's\n\n", count);

	if (x509)
		crypto.release_x509_certificate(x509);

	return SUCCESS;
}
