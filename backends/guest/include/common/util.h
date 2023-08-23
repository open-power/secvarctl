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

// Enum for each possible signature type
//  Start at 1, so 0 can be reserved for some kind of error type
//  Alias ST_LIST_START as the first value for iteration purposes
enum signature_type {
#define ST_LIST_START ST_X509
	ST_X509 = 1,
	ST_RSA2048,
	ST_PKCS7,
	ST_SBAT,
	ST_DELETE,
#define ST_HASHES_START ST_HASH_SHA1
	ST_HASH_SHA1,
	ST_HASH_SHA224,
	ST_HASH_SHA256,
	ST_HASH_SHA384,
	ST_HASH_SHA512,
#define ST_HASHES_END ST_HASH_SHA512
#define ST_X509_HASHES_START ST_X509_HASH_SHA256
	ST_X509_HASH_SHA256,
	ST_X509_HASH_SHA384,
	ST_X509_HASH_SHA512,
#define ST_X509_HASHES_END ST_X509_HASH_SHA512
	ST_UNKNOWN,
#define ST_LIST_END ST_UNKNOWN
};

struct signature_type_info {
	const char *name;
	const uuid_t *uuid;
    /* the following are only used by ST_HASHES_START -> ST_HASHES_END */
    int crypto_id;
    size_t size;
};

extern const struct signature_type_info signature_type_list[];

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
static inline bool is_delete(enum signature_type st)
{
	return st == ST_DELETE;
};

/*
 * check it whether given signature type is SBAT or not
 */
static inline bool is_sbat(enum signature_type st)
{
	return st == ST_SBAT;
};

/*
 * validate the SBAT data format
 */
bool validate_sbat(const uint8_t *sbat_data, size_t sbat_len);

/*
 * given a string, it will return the corresponding sig_type info index
 *
 * @param name, the name of the hash function {"sha1", "sha246"...}
 * @param returnfunct, the corresponding sig_type info struct
 * @return success or err number if not a valid hash function name
 */
int get_hash_function(const char *name, enum signature_type *returnfunct);

/*
 * given a string, it will return the corresponding x509 sig_type info index
 *
 * @param name, the name of the hash function {"sha1", "sha246"...}
 * @param returnfunct, the corresponding sig_type info index
 * @return success or err number if not a valid hash function name
 */
int get_x509_hash_function(const char *name, enum signature_type *returnfunct);

/*
 * check it whether given signature type is hash or not
 */
static inline bool is_hash(enum signature_type st)
{
	return (ST_HASHES_START <= st) && (st <= ST_X509_HASHES_END);
}

/*
 * check it whether given signature type is x509 or not
 */
static inline bool is_cert(enum signature_type st)
{
	return st == ST_X509;
}

/*
 * check it whether given signature type is PKCS7 or not
 */
static inline bool is_pkcs7(enum signature_type st)
{
	return st == ST_PKCS7;
}

/*
 * validates the signature type
 */
bool validate_signature_type(enum signature_type);

/*
 * finds format type given by guid
 *
 * @param type uuid_t of guid of file
 * @return string of format type, "UNKNOWN" if type doesnt match any known formats
 */
enum signature_type get_signature_type(const uuid_t type);

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
uint8_t *get_wide_character(const char *var_name, const size_t var_name_len);

/*
 * Extracts size of the PKCS7 signed data embedded in the
 * auth Header.
 */
size_t extract_pkcs7_len(const auth_info_t *auth);

/*
 * Get the printable string for a signature type uuid
 *
 * @param uuid
 * @return const human-friendly string corresponding to the uuid
 */
static inline const char *get_signature_type_string(const uuid_t uuid)
{
	return signature_type_list[get_signature_type(uuid)].name;
}

/* Get crypto lib defined ID for MD alg idx of signature_type_list */
static inline int get_crypto_alg_id(enum signature_type idx)
{
    if (idx > ST_HASHES_END || idx < ST_X509_HASHES_START) {
        prlog(PR_ERR, "error: invalid crypto alg key %d\n", idx);
        idx = ST_HASH_SHA256;
    }
    return signature_type_list[idx].crypto_id;
}

/* Get crypto lib defined ID for MD alg idx of signature_type_list */
static inline size_t get_crypto_alg_len(enum signature_type idx)
{
    if (idx > ST_HASHES_END || idx < ST_X509_HASHES_START) {
        prlog(PR_ERR, "error: invalid crypto alg key %d\n", idx);
        idx = ST_HASH_SHA256;
    }
    return signature_type_list[idx].size;
}

/* Get crypto lib defined ID for MD alg idx of signature_type_list */
static inline const char * get_crypto_alg_name(enum signature_type idx)
{
    if (idx > ST_HASHES_END || idx < ST_X509_HASHES_START) {
        prlog(PR_ERR, "error: invalid crypto alg key %d\n", idx);
        idx = ST_HASH_SHA256;
    }
    return signature_type_list[idx].name;
}

/* Get guid from idx of signature_type_list */
static inline const uuid_t *get_uuid(enum signature_type idx)
{
    return signature_type_list[idx].uuid;
}
#endif
