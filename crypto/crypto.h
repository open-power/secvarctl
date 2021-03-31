#ifndef SECVARCTL_CRYPTO_H
#define SECVARCTL_CRYPTO_H

#ifdef OPENSSL

#include <openssl/obj_mac.h>
#define CRYPTO_MD_SHA1 NID_sha1
#define CRYPTO_MD_SHA224 NID_sha224
#define CRYPTO_MD_SHA256 NID_sha256 
#define CRYPTO_MD_SHA384 NID_sha384
#define CRYPTO_MD_SHA512 NID_sha512

#elif defined MBEDTLS

#include <mbedtls/md.h>
#define CRYPTO_MD_SHA1 MBEDTLS_MD_SHA1
#define CRYPTO_MD_SHA224 MBEDTLS_MD_SHA224
#define CRYPTO_MD_SHA256 MBEDTLS_MD_SHA256 
#define CRYPTO_MD_SHA384 MBEDTLS_MD_SHA384
#define CRYPTO_MD_SHA512  MBEDTLS_MD_SHA512

#endif
/**====================PKCS7 Functions ====================**/

/* 
 *checks the pkcs7 struct for using SHA256 as the message digest 
 *@param pkcs7 , a pointer to either an openssl or mbedtls pkcs7 struct
 *@return SUCCESS if message digest is SHA256 else return errno
 */
int crypto_pkcs7_md_is_sha256(void *pkcs7);

/*
 *free's the memory allocated for a pkcs7 structure
 *@param pkcs7 , a pointer to either an openssl or mbedtls pkcs7 struct
 */
void crypto_pkcs7_free(void *pkcs7);

/*
 *parses a buffer into a pointer to a pkcs7 struct. struct allocation is done internally to this func, but not dealloc
 *@param buf, buffer of data containg pkcs7 data
 *@param buflen, length of buf
 *@return if successful, a void pointer to either an openssl or mbedtls pkcs7 struct. else returns NULL
 *NOTE: if successful (returns not NULL), remember to call crypto_free_pkcs7 to unalloc. 
 */
void * crypto_pkcs7_parse_der(const unsigned char *buf, const int buflen);

/*
 *returns one signing ceritficate from the PKKCS7 signing certificate chain
 *@param pkcs7 ,  a pointer to either an openssl or mbedtls pkcs7 struct
 *@param cert_num , the index (starts at 0) of the signing certificate to retrieve
 *@return a pointer to either an openssl or mbedtls X509 Struct
 *NOTE: The returned pointer need not be freed, since it is a reference to memory in pkcs7
 */
void* crypto_get_signing_cert(void *pkcs7, int cert_num);


/**====================X509 Functions ====================**/
int crypto_get_x509_der_len(void *x509);
int crypto_get_tbs_x509_der_len(void *x509);
int crypto_get_x509_version(void *x509);
int crypto_get_x509_sig_len(void *x509);
int crypto_x509_md_is_sha256(void *x509);
int crypto_x509_oid_is_pkcs1_sha256(void *x509);
int crypto_x509_get_pk_bit_len(void *x509);
/*
 *checks the type of the x509 and ensures that it is of type RSA
 *@param x509, a pointer to either an openssl or mbedtls x509 struct
 *@return SUCCESS if RSA or if not, returns the returned type value (differs for openssl and mbedtls)
 */
int crypto_x509_is_RSA(void *x509);

/*
 *returns a short string describing the x509 message digest and encryption algorithms
 *@param x509, a pointer to either an openssl or mbedtls x509 struct
 *@param short_desc ,  already alloc'd pointer to output string
 *@param max_len   , number of bytes allocated to short_desc arg
 */
void crypto_x509_get_short_info(void *x509, char *short_desc, size_t max_len);

/*
 *parses the x509 struct into a human readable informational string
 *@param x509_info , already alloc-d pointer to output string
 *@param max_len , number of bytes allocated to x509_info
 *@param delim  , eachline will start with this, usually indent, when using openssl, the length of this value is the number of 8 spaced tabs
 *@param x509 ,  a pointer to either an openssl or mbedtls x509 struct
 *@return number of bytes written to x509_info
 */
int crypto_x509_get_long_desc(char *x509_info, size_t max_len, char *delim, void *x509);

/*
 *parses a data buffer into an x509 struct 
 *@param x509 , output, a pointer to either an openssl or mbedtls x509 struct, should have already been allocated
 *@param data , pointer to data buffer containing an x509 in DER format
 *@param data_lem , length of data buffer
 */
/*
 *parses a buffer into a pointer to an x509 struct. struct allocation is done internally to this func, but not dealloc
 *@param buf, buffer of data containing x509 data in DER
 *@param buflen, length of buf
 *@return if successful, a void pointer to either an openssl or mbedtls x509 struct. else returns NULL
 *NOTE: if successful (returns not NULL), remember to call crypto_x509_free to unalloc. 
 */
void *crypto_x509_parse_der(const unsigned char *data, size_t data_len);

/*
 *unallocates x509 struct and memory
 *@param x509 ,  a pointer to either an openssl or mbedtls x509 struct, should have already been allocated
 */
void crypto_x509_free(void *x509);

/*
 *attempts to convert PEM data buffer into DER data buffer
 *@param input , PEM data buffer
 *@param ilen , length of input data
 *@param output , pointer to output DER data, not yet allocated
 *@param olen , pointer to length of output data
 *@return SUCCESS or errno if conversion failed
 *Note: Remember to unallocate the output data!
 */
int crypto_convert_pem_to_der(const unsigned char *input, size_t ilen, unsigned char **output, size_t *olen);

#endif