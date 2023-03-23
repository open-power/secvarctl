/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023 IBM Corp.
 */
#ifndef VALIDATE_H
#define VALIDATE_H

#include <stdint.h>
#include "common/util.h"

struct validate_args
{
  int help_flag;
  const char *input_file;
  enum file_types input_form;
};

/*
 * validates the hash by using size of hash and its type
 *
 * @param type, hash type
 * @return true if found hash guid type and size from known hashes, else false
 */
bool
validate_hash (uuid_t type, size_t size);

/*
 * validates that the size of the hash buffer is equal to the expected,
 * only real check we can do on a hash
 *
 * @param size , length of hash to be validated
 * @param hashFunct, array of hash function information
 * @return SUCCESS or err number
 */
int
validate_hash_alg (size_t size, const hash_func_t *alg);

/*
 * ensures that efi_time values are  in correct ranges
 *
 * @param time , pointer to an efi_time struct
 * return SUCCESS or INVALID_TIMESTAMP if not valid
 */
int
validate_time (timestamp_t *time);

/*
 * given an pointer to auth data, determines if containing fields, pkcs7,esl and certs are valid
 *
 * @param authBuf pointer to auth file data
 * @param buflen length of buflen
 * @return PKCS7_FAIL if validate validatePKCS7 returns PKCS7_FAIL
 * @return whatever is returned from validateESl
 */
int
validate_auth (const uint8_t *auth_data, size_t auth_data_len);

/*
 * calls pkcs7 functions to validate the pkcs7 inside of the given auth struct
 *
 * @param auth, pointer to auth struct data containing the pkcs7 in
 * auth->auth_cert.hdr.cert_data
 * @return PKCS7_FAIL if something goes wrong, SUCCESS if everything is correct
 */
int
validate_pkcs7 (const uint8_t *cert_data, size_t cert_data_len);

/*
 * gets ESL from ESL data buffer and validates ESL fields and contained
 * certificates, expects chained esl's each with one certificate
 *
 * @param eslBuf pointer to ESL all ESL data, could be appended ESL's
 * @param buflen length of eslBuf
 * @return ESL_FAIL if the less than one ESL could be validated
 * @return CERT_FAIL if validateCertificate fails
 * @return SUCCESS if at least one ESL validates
 */
int
validate_esl (const uint8_t *esl_data, size_t esl_data_len);

/*
 * parses x509 certficate buffer into certificate and verifies it
 *
 * @param certBuf pointer to certificate data
 * @param buflen length of certBuf
 * @return CERT_FAIL if certificate had incorrect data
 * @return SUCCESS if certificate is valid
 */
int
validate_cert (const uint8_t *cert_data, size_t cert_data_len);

#endif
