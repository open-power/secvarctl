#ifndef UTIL_H_
#define UTIL_H_

#include <stdint.h>
#include "pseries.h"

#define CERT_BUFFER_SIZE 2048
#define zalloc(...) calloc(1, __VA_ARGS__)

#define DEFAULT_PK_LEN 31
#define APPEND_HEADER_LEN 8
#define TIMESTAMP_LEN 8
#define PK_VARIABLE (char *)"PK"
#define PK_LEN 2
#define KEK_VARIABLE (char *)"KEK"
#define KEK_LEN 3
#define SBAT_VARIABLE (char *)"sbat"

static const uuid_t PKS_CERT_DELETE_GUID = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

enum file_types { AUTH_FILE, PKCS7_FILE, ESL_FILE, CERT_FILE, UNKNOWN_FILE };

/*
 * creates the append header using append flag
 */
uint8_t *get_append_header(size_t append_flag);

/*
 * extracts the append flag from auth data
 */
size_t extract_append_header(const uint8_t *auth_info, const size_t auth_len);

/*
 * check it whether given signature type is DELETE-ALL or not
 */
bool is_delete(const uint8_t *signature_type);

/*
 * check it whether given signature type is SBAT or not
 */
bool is_sbat(const uint8_t *signature_type);

/*
 * validate the SBAT data format
 */
bool validate_sbat(const uint8_t *sbat_data, size_t sbat_len);

/*
 * given a string, it will return the corresponding hash_funct info array
 *
 * @param name, the name of the hash function {"sha1", "sha246"...}
 * @param returnfunct, the corresponding hash_funct info array
 * @return success or err number if not a valid hash function name
 */
int get_hash_function(const char *name, hash_func_t **returnfunct);

/*
 * given a string, it will return the corresponding x509 hash_funct info array
 *
 * @param name, the name of the hash function {"sha1", "sha246"...}
 * @param returnfunct, the corresponding hash_funct info array
 * @return success or err number if not a valid hash function name
 */
int get_x509_hash_function(const char *name, hash_func_t **returnfunct);

/*
 * check it whether given signature type is hash or not
 */
bool is_hash(const uint8_t *signature_type);

/*
 * check it whether given signature type is x509 or not
 */
bool is_cert(const uint8_t *signature_type);

/*
 * check it whether given signature type is PKCS7 or not
 */
bool is_pkcs7(const uint8_t *signature_type);

/*
 * validates the signature type
 */
bool validate_signature_type(const uint8_t *signature_type);

/*
 * finds format type given by guid
 *
 * @param type uuid_t of guid of file
 * @return string of format type, "UNKNOWN" if type doesnt match any known formats
 */
uint8_t *get_signature_type(const uuid_t type);

/*
 * checks to see if string is a valid variable name
 * @param var variable name
 * @return SUCCESS or error code
 */
bool is_secure_boot_variable(const char *var);

/*
 * expand char to wide character size, since esl's use double wides
 *
 * @param var_name , variable name
 * @param var_name_len, length of variable name
 * @return the new keylen with double length, remember to unalloc
 */
uint8_t *get_wide_character(const uint8_t *var_name, const size_t var_name_len);

/*
 * Extracts size of the PKCS7 signed data embedded in the
 * auth Header.
 */
size_t extract_pkcs7_len(const auth_info_t *auth);

#endif
