/*
 * spdx-license-identifier: apache-2.0
 * copyright 2022-2023 ibm corp.
 */
#include <string.h>
#include <stdlib.h>
#define __USE_XOPEN
#include <time.h>
#include <ctype.h>
#include "err.h"
#include "prlog.h"
#include "crypto.h"
#include <endian.h>
#include "common/util.h"
#include "common/generate.h"
#include "common/validate.h"

/*
 * converts the time in a current timestamp to the equivalent timestamp_t
 *
 * @param timestamp , a pointer to an allocated timestamp_t to be filled with data
 * @param current_time , the current timestamp
 */
static void convert_timestamp(timestamp_t *timestamp, struct tm *current_time)
{
	timestamp->year = 1900 + current_time->tm_year;
	timestamp->month = current_time->tm_mon + 1;
	timestamp->day = current_time->tm_mday;
	timestamp->hour = current_time->tm_hour;
	timestamp->minute = current_time->tm_min;
	timestamp->second = current_time->tm_sec;
}

/*
 * parses a '-t YYYY-MM-DDThh:mm:ss>' argument into the timestamp_t
 *
 * @param timestamp, the allocated timestamp_t, to be filled with data
 * @param time_str,  the given timestamp string
 * @return SUCCESS or errno if failed to extract data
 */
int parse_custom_timestamp(timestamp_t *timestamp, const char *time_str)
{
	struct tm current_time;
	char *ret = NULL;

	memset(&current_time, 0, sizeof(current_time));
	ret = strptime(time_str, "%FT%T", &current_time);
	if (ret == NULL)
		return INVALID_TIMESTAMP;
	else if (*ret != '\0') {
		prlog(PR_ERR, "ERROR: failed to parse timestamp value at %s\n", ret);
		return INVALID_TIMESTAMP;
	}

	convert_timestamp(timestamp, &current_time);

	return SUCCESS;
}

/*
 * gets current time and puts into an timestamp_t
 *
 * @param timstamp, the outputted current time
 * @return success or errno if generated timestamp is incorrect
 */
int get_timestamp(timestamp_t *timestamp)
{
	time_t epochtime;
	struct tm *current_time;

	time(&epochtime);
	current_time = gmtime(&epochtime);
	convert_timestamp(timestamp, current_time);

	return validate_time(timestamp);
}

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
	       size_t *out_esl_size)
{
	sv_esl_t esl;
	size_t offset = 0;

	prlog(PR_INFO, "creating esl from %s... adding:\n", get_signature_type_string(guid));

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "\t%s guid - ", get_signature_type_string(guid));
		print_signature_type(&guid);
	}

	esl.signature_type = guid;
	esl.signature_list_size = sizeof(esl) + sizeof(uuid_t) + data_size;
	prlog(PR_INFO, "\tsig list size - %u\n", esl.signature_list_size);
	esl.signature_header_size = 0;
	esl.signature_size = data_size + sizeof(uuid_t);
	prlog(PR_INFO, "\tsignature data size - %u\n", esl.signature_size);

	/*esl structure:
      -esl header - 28 bytes
      -esl owner uuid - 16 bytes
      -data
  */
	*out_esl = calloc(1, esl.signature_list_size);
	if (*out_esl == NULL) {
		prlog(PR_ERR, "error: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	prlog(PR_INFO, "\tcombining header info and data\n");
	memcpy(*out_esl, &esl, sizeof(esl));
	offset += sizeof(esl);

	/* add owner guid here, leave blank for now */
	offset += sizeof(uuid_t);
	memcpy(*out_esl + offset, data, data_size);
	*out_esl_size = esl.signature_list_size;
	prlog(PR_INFO, "esl generation successful...\n");

	return SUCCESS;
}

/*
 * actually performs the extraction of the esl from the authfile
 *
 * @param in , in buffer, auth buffer
 * @param insize, length of auth buffer
 * @param out , out esl, esl buffer
 * @param outsize, length of esl
 * note: this allocates memory for output buffer, free later
 * @return success or error number
 */
int extract_esl_from_auth(const uint8_t *data, const size_t data_size, uint8_t **out,
			  size_t *out_size)
{
	size_t length, auth_buffer_size, offset = 0, pkcs7_size;
	const auth_info_t *auth;

	auth = (auth_info_t *)data;
	length = auth->auth_cert.hdr.da_length;
	if (length == 0 || length > data_size) { /* if total size of header and pkcs7 */
		prlog(PR_ERR, "error: invalid auth size %zu\n", length);
		return AUTH_FAIL;
	}

	pkcs7_size = extract_pkcs7_len(auth);
	if (pkcs7_size == 0 || pkcs7_size > length) {
		prlog(PR_ERR, "error: invalid pkcs7 size %zu\n", pkcs7_size);
		return PKCS7_FAIL;
	}

	/*
   * efi_var_2->auth_info.data = auth descriptor + new esl data.
   * we want only only the auth descriptor/pkcs7 from .data.
   */
	auth_buffer_size = sizeof(auth->timestamp) + sizeof(auth->auth_cert.hdr) +
			   sizeof(auth->auth_cert.cert_type) + pkcs7_size;
	if (auth_buffer_size > data_size) {
		prlog(PR_ERR, "error: no data to verify, no attatched esl\n");
		return ESL_FAIL;
	}

	prlog(PR_NOTICE,
	      "\tauth file size = %zu\n\t  -auth/pkcs7 data size = %zu\n\t"
	      "  -esl size = %zu\n",
	      data_size, auth_buffer_size, data_size - auth_buffer_size);

	/* skips over entire pkcs7 in cert_datas */
	offset = sizeof(auth->timestamp) + length;
	if (offset == data_size) {
		prlog(PR_WARNING, "warning: esl is empty\n");
	}

	*out_size = data_size - offset;
	*out = malloc(*out_size);
	if (*out == NULL) {
		prlog(PR_ERR, "error: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	memcpy(*out, data + offset, *out_size);

	return SUCCESS;
}

/*
 * generates data that is ready to be hashed and eventually signed for secure
 * variables more specifically this accepts an esl and preprends metadata
 *
 * @param outdata, the outputted data with prepended data / remember to unalloc
 * @param outsize, length of output data
 * @param esl, the new esl data
 * @param esl_size, length of esl buffer
 * @param args, struct containing imprtant metadata info
 * @return, success or error number
 */
static int create_prehash(const uint8_t *esl, const size_t esl_size,
			  const struct generate_args *args, const uuid_t guid, uint8_t **out_data,
			  size_t *out_data_size)
{
	int rc = SV_SUCCESS;
	uint8_t *ptr = NULL;
	uint8_t *wkey = NULL;
	size_t varlen;
	leint32_t attr =
		cpu_to_le32(SECVAR_ATTRIBUTES | (args->append_flag ? SV_VARIABLE_APPEND_WRITE : 0));

	if (verbose >= PR_INFO) {
		prlog(PR_INFO, "timestamp is : ");
		print_timestamp(*args->time);
	}

	/* expand char name to wide character width */
	varlen = strlen(args->variable_name) * 2;
	wkey = get_wide_character(args->variable_name, strlen(args->variable_name));
	if (wkey == NULL)
		return ALLOC_FAIL;

	*out_data_size = varlen + sizeof(guid) + sizeof(attr) + sizeof(timestamp_t) + esl_size;
	*out_data = malloc(*out_data_size);
	if (*out_data == NULL) {
		prlog(PR_ERR, "error: failed to allocate memory\n");
		free(wkey);
		return ALLOC_FAIL;
	}

	ptr = *out_data;
	memcpy(ptr, wkey, varlen);
	ptr += varlen;
	memcpy(ptr, &guid, sizeof(guid));
	ptr += sizeof(guid);
	memcpy(ptr, &attr, sizeof(attr));
	ptr += sizeof(attr);
	memcpy(ptr, args->time, sizeof(timestamp_t));
	ptr += sizeof(*args->time);
	if (esl)
		memcpy(ptr, esl, esl_size);

	free(wkey);

	return rc;
}

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
			  size_t *out_buffer_size)
{
	int rc;
	uint8_t *prehash = NULL;
	size_t prehash_size;

	rc = create_prehash(esl, esl_size, args, guid, &prehash, &prehash_size);
	if (rc != SV_SUCCESS) {
		prlog(PR_ERR, "failed to generate pre-hash data\n");
		return rc;
	}

	rc = crypto_md_generate_hash(prehash, prehash_size, CRYPTO_MD_SHA256, out_buffer,
				     out_buffer_size);

	if (prehash != NULL)
		free(prehash);

	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_ERR, "failed to generate hash\n");
	} else if (*out_buffer_size != 32) {
		prlog(PR_ERR, "error: size of sha256 is not 32 bytes, found %zu bytes\n",
		      *out_buffer_size);
	} else
		return SUCCESS;

	return HASH_FAIL;
}

/*
 * generates a pkcs7 that is compatable with secure variables aka the data to be
 * hashed will be keyname + timestamp +attr etc. etc ... + newdata
 *
 * @param new_data, data to be added to be used in digest
 * @param new_dat_asize , length of newdata
 * @param args,  struct containing important information for generation
 * @param out_buffer, the resulting pkcs7, newdata not appended, note: remember to
 * unalloc this memory
 * @param out_buffer_size, the length of outbuff
 * @return success or err number
 */
int create_pkcs7(const uint8_t *new_data, const size_t new_data_size,
		 const struct generate_args *args, const uuid_t guid, uint8_t **out_buffer,
		 size_t *out_buffer_size)
{
	int rc;
	size_t total_size;
	uint8_t *actual_data = NULL;

	rc = create_prehash(new_data, new_data_size, args, guid, &actual_data, &total_size);
	if (rc != SV_SUCCESS) {
		prlog(PR_ERR, "ERROR: failed to generate pre-hash data for pkcs7\n");
		return rc;
	}

	/* get pkcs7 and size, if we are already given ths signatures then call appropriate funcion */
	if (args->pkcs7_gen_method) {
		prlog(PR_INFO, "generating pkcs7 with already signed data\n");
		rc = crypto_pkcs7_generate_w_already_signed_data(
			out_buffer, out_buffer_size, actual_data, total_size, args->sign_certs,
			args->sign_keys, args->sign_key_count, CRYPTO_MD_SHA256);
	} else
		rc = crypto_pkcs7_generate_w_signature(out_buffer, out_buffer_size, actual_data,
						       total_size, args->sign_certs,
						       args->sign_keys, args->sign_key_count,
						       CRYPTO_MD_SHA256);

	if (actual_data)
		free(actual_data);

	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_ERR, "ERROR: making pkcs7 failed\n");
		return PKCS7_FAIL;
	}

	return SUCCESS;
}

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
		    size_t *out_buffer_size)
{
	int rc;
	size_t pkcs7_size, offset = 0;
	uint8_t *pkcs7 = NULL, *append_header = NULL;
	auth_info_t auth_header;

	if (out_buffer == NULL) {
		prlog(PR_ERR, "out_buffer was NULL, this is likely a bug");
		return ALLOC_FAIL; // Not entirely true, but there's not a better error for this yet
	}

	rc = create_pkcs7(new_esl, new_esl_size, args, guid, &pkcs7, &pkcs7_size);
	if (rc != SUCCESS) {
		prlog(PR_ERR, "ERROR: cannot generate auth file, failed to generate pkcs7\n");
		return rc;
	}

	append_header = get_append_header(args->append_flag);

	/* create auth header */
	auth_header.timestamp = *args->time;
	auth_header.auth_cert.hdr.da_length = sizeof(auth_header.auth_cert.hdr) +
					      sizeof(auth_header.auth_cert.cert_type) + pkcs7_size;
	auth_header.auth_cert.hdr.a_revision = cpu_to_be16(SV_CERT_TYPE_PKCS_SIGNED_DATA);
	auth_header.auth_cert.hdr.a_certificate_type = cpu_to_be16(0xf10e);
	auth_header.auth_cert.cert_type = AUTH_CERT_TYPE_PKCS7_GUID;

	/* now build auth msg = append header + auth header + pkcs7 + new esl */
	*out_buffer_size = APPEND_HEADER_LEN + sizeof(auth_header) + pkcs7_size + new_esl_size;
	*out_buffer = malloc(*out_buffer_size);
	if (*out_buffer == NULL) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		free(pkcs7);
		return ALLOC_FAIL;
	}

	prlog(PR_INFO, "combining append header, auth header, pkcs7 and new esl:\n");
	memcpy(*out_buffer + offset, append_header, APPEND_HEADER_LEN);
	offset += APPEND_HEADER_LEN;
	prlog(PR_INFO, "\t+ append header %d bytes\n", APPEND_HEADER_LEN);
	memcpy(*out_buffer + offset, &auth_header, sizeof(auth_header));
	offset += sizeof(auth_header);
	prlog(PR_INFO, "\t+ auth header %zu bytes\n", sizeof(auth_header));
	memcpy(*out_buffer + offset, pkcs7, pkcs7_size);
	offset += pkcs7_size;
	prlog(PR_INFO, "\t+ pkcs7 %zu bytes\n", pkcs7_size);
	if (new_esl)
		memcpy(*out_buffer + offset, new_esl, new_esl_size);
	offset += new_esl_size;
	prlog(PR_INFO, "\t+ new esl %zu bytes\n\t= %zu total bytes\n", new_esl_size, offset);

	free(pkcs7);

	return rc;
}

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
		       size_t *cert_data_size)
{
	int rc;
	uint8_t *cert = NULL;
	size_t cert_size = 0;

	/* two intermediate buffers needed, one for input -> DER and one for DER -> ESL, */
	prlog(PR_INFO, "converting x509 from PEM to DER...\n");

	rc = crypto_convert_pem_to_der(buffer, buffer_size, &cert, &cert_size);
	if (rc != CRYPTO_SUCCESS) {
		prlog(PR_WARNING, "WARNING: could not convert PEM to DER, %d\n", rc);
		return CERT_FAIL;
	}

	rc = validate_cert(cert, cert_size);

	*cert_data = cert;
	*cert_data_size = cert_size;

	return rc;
}

/*
 * generate the hash data using input data
 *
 * @param buffer, data to be added to ESL, it must be of the same type as specified by inform
 * @param buffer_size , length of buffer
 * @param hash_funct, index of hash function information to use for ESL GUID,
 *                   also helps in prevalation, if inform is '[c]ert' then this doesn't matter
 * @param hash_data, the generated hash data
 * @param hash_data_size, the length of hash data
 * @param esl_guid, signature type of ESL
 * @return SUCCESS or err number
 */
int get_hash_data(const uint8_t *buffer, const size_t buffer_size, enum signature_type hash_funct,
		  uint8_t *hash_data, size_t *hash_data_size)
{
	int rc = SUCCESS;
	size_t data_size = 0;
	uint8_t *data = NULL;
	enum signature_type x509_hash_func;

	rc = is_x509certificate(buffer, buffer_size, &data, &data_size);
	if (rc == SUCCESS) {
		rc = get_x509_hash_function(get_crypto_alg_name(hash_funct), &x509_hash_func);
		if (rc)
			return rc;

		hash_funct = x509_hash_func;
	} else {
		data_size = buffer_size;
		data = (uint8_t *)buffer;
	}

	rc = crypto_md_generate_hash(data, data_size, get_crypto_alg_id(hash_funct), &hash_data,
				     hash_data_size);

	if (rc != CRYPTO_SUCCESS)
		return HASH_FAIL;

	return SUCCESS;
}
