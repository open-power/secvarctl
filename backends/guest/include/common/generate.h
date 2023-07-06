/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023 IBM Corp.
 */
#ifndef GENERATE_H
#define GENERATE_H

#include <stdio.h>
#include <stdint.h>
#include "pseries.h"
#include "common/read.h"

enum pkcs7_gen_methods {
	W_PRIVATE_KEYS = 0, /* for -k <key> option */
	W_EXTERNAL_GEN_SIG, /* for -s <sig> option */
	NO_PKCS7_GEN_METHOD /* default, when not generating a pkcs7/auth */
};

typedef enum pkcs7_gen_methods pkcs7_method_t;

struct generate_args {
	int append_flag;
	int help_flag;
	int input_valid;
	int sign_key_count;
	int sign_cert_count;
	const char *input_file;
	const char *output_file;
	const char **sign_certs;
	const char **sign_keys;
	const char *input_form;
	const char *output_form;
	const char *variable_name;
	const char *hash_alg;
	timestamp_t *time;
	pkcs7_method_t pkcs7_gen_method;
};

/*
 * parses a '-t YYYY-MM-DDThh:mm:ss>' argument into the timestamp_t
 *
 * @param timestamp, the allocated timestamp_t, to be filled with data
 * @param time_str,  the given timestamp string
 * @return SUCCESS or errno if failed to extract data
 */
int parse_custom_timestamp(timestamp_t *timestamp, const char *time_str);

/*
 * gets current time and puts into an timestamp_t
 *
 * @param timstamp, the outputted current time
 * @return success or errno if generated timestamp is incorrect
 */
int get_timestamp(timestamp_t *timestamp);

/*
 * generates esl from input data, esl will have guid specified by guid
 *
 * @param data, data to be added to esl
 * @param data_size , length of data
 * @param guid, guid of data type of data
 * @param out_esl, the resulting esl file, note: remember to unalloc this memory
 * @param out_esl_size, the length of outbuff
 * @return success or err number
 */
int create_esl(const uint8_t *data, const size_t data_size, const uuid_t guid, uint8_t **out_esl,
	       size_t *out_esl_size);

/*
 * actually performs the extraction of the esl from the authfile
 *
 * @param in , in buffer, auth buffer
 * @param insize, length of auth buffer
 * @param out , out esl, esl buffer
 * @param out_size, length of esl
 * note: this allocates memory for output buffer, free later
 * @return success or error number
 */
int extract_esl_from_auth(const uint8_t *in, const size_t insize, uint8_t **out, size_t *out_size);

/*
 * generates presigned hashed data, this accepts an esl and all metadata, it performs a sha hash
 *
 * @param esl, esl data buffer
 * @param esl_size , length of esl
 * @param args, struct containing command line info and lots of other important information
 * @param out_buffer, the resulting hashed data, note: remember to unalloc this memory
 * @param out_buffer_size, the length of hashed data (should be 32 bytes)
 * @return success or err number
 */
int create_presigned_hash(const uint8_t *esl, const size_t esl_size,
			  const struct generate_args *args, const uuid_t guid, uint8_t **out_buffer,
			  size_t *out_buffer_size);
/*
 * generates a pkcs7 that is compatable with secure variables aka the data to be hashed will be
 * varname + timestamp +attr etc. etc ... + newdata
 *
 * @param new_data, data to be added to be used in digest
 * @param new_data_size , length of newdata
 * @param args,  struct containing important information for generation
 * @param out_buffer, the resulting pkcs7, newdata not appended, note: remember to unalloc this memory
 * @param out_buffer_size, the length of outbuff
 * @return success or err number
 */
int create_pkcs7(const uint8_t *new_data, const size_t new_data_size,
		 const struct generate_args *args, const uuid_t guid, uint8_t **out_buffer,
		 size_t *out_buffer_size);

/*
 * create an auth message and its size and return a success or negative number (error)
 *
 * @param new_esl, data to be added to auth, it must be of the same type as specified by inform
 * @param new_esl_size , length of newesl
 * @param args, struct containing important command line info
 * @param out_buffer, the resulting auth file, note: remember to unalloc this memory
 * @param out_buffer_size, the length of outbuff
 * @return success or err number
 */
int create_auth_msg(const uint8_t *new_esl, const size_t new_esl_size,
		    const struct generate_args *args, const uuid_t guid, uint8_t **out_buffer,
		    size_t *out_buffer_size);

/*
 * convert x509 from PEM to DER and validate the certificate
 *
 * @param buffer, data to be added to ESL, it must be of the same type as specified by inform
 * @param buffer_size , length of buffer
 * @param cert_data, the certificate data
 * @param cert_data_size, the length of certificate data
 * @return SUCCESS or err number
 */
int is_x509certificate(const uint8_t *buffer, const size_t buffer_size, uint8_t **cert_data,
		       size_t *cert_data_size);

/*
 * generate the hash data using input data
 *
 * @param buffer, data to be added to ESL, it must be of the same type as specified by inform
 * @param buffer_size , length of buffer
 * @param hash_funct, array of hash function information to use for ESL GUID,
 *                   also helps in prevalation, if inform is '[c]ert' then this doesn't matter
 * @param hash_data, the generated hash data
 * @param hash_data_size, the length of hash data
 * @param esl_guid, signature type of ESL
 * @return SUCCESS or err number
 */
int get_hash_data(const uint8_t *buffer, const size_t buffer_size, hash_func_t **hash_funct,
		  uint8_t *hash_data, size_t *hash_data_size);

#endif
