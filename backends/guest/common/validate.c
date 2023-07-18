/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "prlog.h"
#include "err.h"
#include "generic.h"
#include "util.h"
#include "common/util.h"
#include "common/read.h"
#include "common/validate.h"

/*
 * validates that the size of the hash buffer is equal to the expected,
 * only real check we can do on a hash
 *
 * @param size , length of hash to be validated
 * @param hashFunct, array of hash function information
 * @return SUCCESS or err number
 */
int validate_hash_alg(size_t size, const hash_func_t *alg)
{
	if (size != alg->size) {
		prlog(PR_ERR,
		      "ERROR: length of hash data does not equal expected size of hash "
		      "%s, expected %zu found %zu bytes\n",
		      alg->name, alg->size, size);
		return HASH_FAIL;
	}

	return SUCCESS;
}

/*
 * ensures that timestamp values are  in correct ranges
 *
 * @param time , pointer to an efi_time struct
 * return SUCCESS or INVALID_TIMESTAMP if not valid
 */
int validate_time(timestamp_t *time)
{
	if (time->year < 1900 || time->year > 9999) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for year: %d\n", time->year);
		return INVALID_TIMESTAMP;
	}

	if (time->month < 1 || time->month > 12) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for month: %d\n", time->month);
		return INVALID_TIMESTAMP;
	}

	if (time->day < 1 || time->day > 31) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for day: %d\n", time->day);
		return INVALID_TIMESTAMP;
	}

	if (time->hour < 0 || time->hour > 23) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for hour: %d\n", time->hour);
		return INVALID_TIMESTAMP;
	}

	if (time->minute < 0 || time->minute > 59) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for minute: %d\n", time->minute);
		return INVALID_TIMESTAMP;
	}

	if (time->second < 0 || time->second > 60) {
		prlog(PR_ERR, "ERROR: Invalid Timestamp value for second: %d\n", time->second);
		return INVALID_TIMESTAMP;
	}

	return SUCCESS;
}

/*
 * validates the hash by using size of hash and its type
 *
 * @param type, hash type 
 * @return true if found hash guid type and size from known hashes, else false
 */
bool validate_hash(uuid_t type, size_t size)
{
	int i = 0;

	for (i = 0; i < sizeof(hash_functions) / sizeof(hash_func_t); i++) {
		if (uuid_equals(&type, hash_functions[i].guid) && (size == hash_functions[i].size))
			return true;
	}

	for (i = 0; i < sizeof(x509_hash_functions) / sizeof(hash_func_t); i++) {
		if (uuid_equals(&type, x509_hash_functions[i].guid) &&
		    (size == x509_hash_functions[i].size))
			return true;
	}

	return false;
}

/*
 * checks fields of the struct to ensure that the buffer was correctly into a sig list
 * for now, only checks that sizes of field are valid
 *
 * @param bytesRead will be filled with the number of bytes read during this function (eslsize)
 * @param esl, pointer to start of esl
 * @param eslvarsize, remaining size of eslbuf
 * @return SUCCESS if cetificate and header info is valid, errno otherwise
 */
static int validate_single_esl(const uint8_t *esl_data, size_t esl_data_size, size_t *next_esl)
{
	ssize_t cert_size;
	int rc;
	uint8_t *cert = NULL, *signature_type = NULL;
	sv_esl_t *sig_list;

	*next_esl = 0;

	/* verify struct to ensure it is a valid sig_list, if 1 is returned break */
	if (esl_data_size < sizeof(sv_esl_t)) {
		prlog(PR_ERR,
		      "ERROR: ESL has %zu bytes and is smaller than an ESL (%zu bytes),"
		      "remaining data not parsed\n",
		      esl_data_size, sizeof(sv_esl_t));
		return ESL_FAIL;
	}

	/* Get sig list */
	sig_list = extract_esl_signature_list(esl_data, esl_data_size);
	if (sig_list->signature_list_size > 0) {
		if ((sig_list->signature_size <= 0 && sig_list->signature_header_size <= 0) ||
		    sig_list->signature_list_size <
			    (sig_list->signature_header_size + sig_list->signature_size)) {
			prlog(PR_ERR, "ERROR: signature list is not structured correctly, defined "
				      "size and actual sizes are mismatched\n");
			return ESL_FAIL;
		}
	}

	if (verbose >= PR_INFO)
		print_esl_info(sig_list);

	if (sig_list->signature_list_size > esl_data_size ||
	    sig_list->signature_header_size > esl_data_size ||
	    sig_list->signature_size > esl_data_size) {
		prlog(PR_ERR,
		      "ERROR: expected signature list size %u + header size %u + "
		      "signature size is %u larger than actual size %zu\n",
		      sig_list->signature_list_size, sig_list->signature_header_size,
		      sig_list->signature_size, esl_data_size);
		return ESL_FAIL;
	} else if ((int)sig_list->signature_list_size <= 0) {
		prlog(PR_ERR, "ERROR: signature list has incorrect size %u \n",
		      sig_list->signature_list_size);
		return ESL_FAIL;
	}

	signature_type = get_signature_type(sig_list->signature_type);
	if (!validate_signature_type(signature_type)) {
		prlog(PR_ERR, "ERROR: signature list is not a valid format\n");
		return ESL_FAIL;
	}

	/* get certificate */
	cert_size = extract_esl_cert(esl_data, esl_data_size, &cert);
	if (cert_size <= 0) {
		prlog(PR_ERR, "ERROR: signature size was too small, no data \n");
		return ESL_FAIL;
	}

	if (is_hash(signature_type)) {
		if (!validate_hash(sig_list->signature_type, cert_size)) {
			prlog(PR_ERR, "ERROR: type %s and number of bytes %zd, is invalid\n",
			      get_signature_type(sig_list->signature_type), cert_size);
			rc = HASH_FAIL;
		} else
			rc = SUCCESS;

		if (verbose >= PR_INFO) {
			prlog(PR_INFO, "\tHash: ");
			print_hex(cert, cert_size);
		}
	} else if (is_cert(signature_type))
		rc = validate_cert(cert, cert_size);
	else if (is_sbat(signature_type)) {
		if (!validate_sbat(cert, cert_size)) {
			prlog(PR_ERR, "ERROR: SBAT data format is invalid\n");
			rc = INVALID_SBAT;
		} else
			rc = SUCCESS;

		if (verbose >= PR_INFO) {
			prlog(PR_INFO, "\tSBAT: ");
			print_raw((char *)cert, cert_size);
		}
	} else if (is_delete(signature_type)) {
		if (verbose >= PR_INFO) {
			prlog(PR_INFO, "\tDELETE-MSG: ");
			print_raw((char *)cert, cert_size);
		}
		rc = SUCCESS;
	} else {
		prlog(PR_ERR, "ERROR: invalid signature type\n");
		rc = ESL_FAIL;
	}

	free(cert);
	*next_esl = sig_list->signature_list_size;

	return rc;
}

/*
 * gets ESL from ESL data buffer and validates ESL fields and contained certificates,
 * expects chained esl's each with one certificate
 *
 * @param esl_data, pointer to ESL all ESL data, could be appended ESL's
 * @param esl_data_len, size of esl data
 * @return ESL_FAIL if the less than one ESL could be validated
 * @return CERT_FAIL if validateCertificate fails
 * @return SUCCESS if at least one ESL validates
 */
int validate_esl(const uint8_t *esl_data, size_t esl_data_len)
{
	ssize_t esl_data_size = esl_data_len;
	size_t esl_size = 0;
	int count = 0, offset = 0, rc = SUCCESS;

	prlog(PR_INFO, "VALIDATING ESL:\n");

	while (esl_data_size > 0) {
		rc = validate_single_esl(esl_data + offset, esl_data_size, &esl_size);
		/* verify current esl to ensure it is a valid sig_list, if 1 is returned break or error */
		if (rc) {
			prlog(PR_ERR, "ERROR: sig List #%d is not structured correctly\n", count);
			if (count)
				break;
			else
				return rc;
		}

		count++;
		/* we read all eslsize bytes so iterate to next esl */
		offset += esl_size;
		esl_data_size -= esl_size;
	}

	prlog(PR_INFO, "\tFound %d ESL's\n\n", count);

	if (!count)
		return ESL_FAIL;

	return rc;
}

/*
 * calls pkcs7 functions to validate the pkcs7 inside of the given auth struct
 *
 * @param auth, pointer to auth struct data containing the pkcs7 in
 * auth->auth_cert.hdr.cert_data
 * @return PKCS7_FAIL if something goes wrong, SUCCESS if everything is correct
 */
int validate_pkcs7(const uint8_t *cert_data, size_t cert_data_len)
{
	int rc = SUCCESS, cert_num = 0;
	crypto_x509_t *x509 = NULL;
	crypto_pkcs7_t *pkcs7 = NULL;

	prlog(PR_INFO, "VALIDATING PKCS7:\n");

	rc = crypto.get_pkcs7_certificate(cert_data, cert_data_len, &pkcs7);
	if (rc != SUCCESS) {
		prlog(PR_ERR, "ERROR: parsing of pkcs7 certificate is failed (%d)\n", rc);
		return rc;
	}

	prlog(PR_INFO, "\tDigest Alg: SHA256\n");

	while (rc == SUCCESS &&
	       crypto.get_signing_cert_from_pkcs7(pkcs7, cert_num, &x509) == SUCCESS) {
		prlog(PR_INFO, "VALIDATING SIGNING CERTIFICATE:\n");

		rc = crypto.validate_x509_certificate(x509);
		if (rc != SUCCESS)
			prlog(PR_ERR, "ERROR: pkcs7 signing certificate %d is invalid (%d)\n",
			      cert_num, rc);

		if (rc == SUCCESS && verbose >= PR_INFO)
			rc = print_cert_info(x509);

		cert_num++;
	}

	crypto.release_pkcs7_certificate(pkcs7);

	return SUCCESS;
}

/*
 * parses x509 certficate buffer into certificate and verifies it
 *
 * @param cert_data pointer to certificate data
 * @param cert_data_len size of certtificate data
 * @return CERT_FAIL if certificate had incorrect data
 * @return SUCCESS if certificate is valid else 
 */
int validate_cert(const uint8_t *cert_data, size_t cert_data_len)
{
	int rc;
	crypto_x509_t *x509;
#ifdef SECVAR_CRYPTO_WRITE_FUNC
	uint8_t *cert = NULL;
	size_t cert_size = 0;
#endif

	rc = crypto.get_x509_certificate(cert_data, cert_data_len, &x509);
	if (rc) {
		/*
       * if here, parsing cert in der failed
       * check if we have compiled with pkcs7_write functions
       * if so we can try to convert pem to der and try again
       */
#ifdef SECVAR_CRYPTO_WRITE_FUNC
		prlog(PR_INFO, "failed to parse x509 as DER, trying PEM...\n");
		rc = crypto.get_der_from_pem(cert_data, cert_data_len, &cert, &cert_size);
		if (rc) {
			prlog(PR_ERR,
			      "ERROR: failed to parse x509 (tried DER and PEM formats). \n");
			return CERT_FAIL;
		}

		rc = crypto.get_x509_certificate(cert, cert_size, &x509);
		free(cert);
		if (rc)
			return rc;
#else
		prlog(PR_INFO, "ERROR: failed to parse x509. Make sure file is in DER not PEM\n");
		return rc;
#endif
	}

	rc = crypto.validate_x509_certificate(x509);
	if (rc)
		prlog(PR_ERR, "ERROR: x509 certificate is invalid (%d)\n", rc);

	if (!rc && verbose >= PR_INFO)
		rc = print_cert_info(x509);

	crypto.release_x509_certificate(x509);

	return rc;
}

/*
 * given an pointer to auth data, determines if containing fields, pkcs7,esl and certs are valid
 *
 * @param auth_data, pointer to auth file data
 * @param auth_data_len, size of auth data
 * @return succcess if auth is valid
 */
int validate_auth(const uint8_t *auth_data, size_t auth_data_len)
{
	int rc;
	size_t auth_size, pkcs7_size, append_flag;
	uint8_t *signature_type = NULL;
	auth_info_t *auth = NULL;

	prlog(PR_INFO, "VALIDATING AUTH FILE:\n");

	append_flag = extract_append_header(auth_data, auth_data_len);

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "\tAPPEND HEADER :\n");
		printf("\t   Append Flag : %zu\n", append_flag);
	}

	auth_data_len -= APPEND_HEADER_LEN;
	auth = (auth_info_t *)(auth_data + APPEND_HEADER_LEN);
	if (auth == NULL) {
		prlog(PR_ERR, "ERROR: auth file is empty to be valid auth file\n");
		return AUTH_FAIL;
	}

	if (auth_data_len < sizeof(auth_info_t)) {
		prlog(PR_ERR, "ERROR: auth file is too small to be valid auth file\n");
		return AUTH_FAIL;
	}

	/* total size of auth and pkcs7 data (appended ESL not included) */
	auth_size = auth->auth_cert.hdr.da_length + sizeof(auth->timestamp);
	/* if expected length is greater than the actual length or not a valid size, return fail */
	if ((ssize_t)auth_size <= 0 || auth_size > auth_data_len) {
		prlog(PR_ERR, "ERROR: invalid auth size, expected %zu found %zu\n", auth_size,
		      auth_data_len);
		return AUTH_FAIL;
	}

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "\tGuid code is : ");
		print_signature_type(&auth->auth_cert.cert_type);
	}

	signature_type = get_signature_type(auth->auth_cert.cert_type);
	/* make sure guid is PKCS7 */
	if (!is_pkcs7(signature_type)) {
		prlog(PR_ERR, "ERROR: Auth file does not contain PKCS7 guid\n");
		return AUTH_FAIL;
	}

	prlog(PR_INFO, "\tType: PKCS7\n");

	pkcs7_size = extract_pkcs7_len(auth);
	/* ensure pkcs7 size is valid length */
	if ((ssize_t)pkcs7_size <= 0 || pkcs7_size > auth_size) {
		prlog(PR_ERR, "ERROR: Invalid pkcs7 size %zu\n", pkcs7_size);
		return AUTH_FAIL;
	}

	prlog(PR_INFO,
	      "\tAuth File Size = %zu\n\t  -Auth/PKCS7 Data Size = %zu\n\t  -ESL Size = %zu\n",
	      auth_data_len, auth_size, auth_data_len - auth_size);

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "\tTimestamp: ");
		print_timestamp(auth->timestamp);
	}

	/* validate pkcs7 */
	rc = validate_pkcs7(auth->auth_cert.cert_data, pkcs7_size);
	if (rc) {
		prlog(PR_ERR, "ERROR: PKCS7 FAILED\n");
		return rc;
	}

	/* now validate appended ESL */
	if (auth_size == auth_data_len) {
		prlog(PR_WARNING, "WARNING: appended ESL is empty, (valid key reset file)...\n");
		rc = SUCCESS;
	} else {
		rc = validate_esl(auth_data + APPEND_HEADER_LEN + auth_size,
				  auth_data_len - auth_size);
		if (rc) {
			prlog(PR_ERR, "ERROR: ESL FAILED\n");
			return rc;
		}
	}

	return rc;
}
