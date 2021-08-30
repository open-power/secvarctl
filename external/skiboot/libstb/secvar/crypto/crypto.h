// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2021 IBM Corp.*/
#ifndef SECVAR_CRYPTO_H
#define SECVAR_CRYPTO_H

#ifdef SECVAR_CRYPTO_OPENSSL

#include <openssl/obj_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define OPENSSL_SUCCESS 0
#define CRYPTO_MD_SHA1 NID_sha1
#define CRYPTO_MD_SHA224 NID_sha224
#define CRYPTO_MD_SHA256 NID_sha256
#define CRYPTO_MD_SHA384 NID_sha384
#define CRYPTO_MD_SHA512 NID_sha512

typedef PKCS7 crypto_pkcs7;
typedef X509 crypto_x509;
typedef EVP_MD_CTX crypto_md_ctx;

#elif defined SECVAR_CRYPTO_MBEDTLS

#include <mbedtls/md.h>
#include <mbedtls/platform.h>
// NICK CHILD was here
//#include "libstb/crypto/pkcs7/pkcs7.h"
#include "external/extraMbedtls/include/pkcs7.h"

#define MBEDTLS_SUCCESS MBEDTLS_EXIT_SUCCESS
#define CRYPTO_MD_SHA1 MBEDTLS_MD_SHA1
#define CRYPTO_MD_SHA224 MBEDTLS_MD_SHA224
#define CRYPTO_MD_SHA256 MBEDTLS_MD_SHA256
#define CRYPTO_MD_SHA384 MBEDTLS_MD_SHA384
#define CRYPTO_MD_SHA512 MBEDTLS_MD_SHA512

typedef struct mbedtls_pkcs7 crypto_pkcs7;
typedef mbedtls_x509_crt crypto_x509;
typedef mbedtls_md_context_t crypto_md_ctx;

#elif defined SECVAR_CRYPTO_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/pkcs7.h>

#define GNUTLS_SUCCESS GNUTLS_E_SUCCESS
#define CRYPTO_MD_SHA1 GNUTLS_DIG_SHA1
#define CRYPTO_MD_SHA224 GNUTLS_DIG_SHA224
#define CRYPTO_MD_SHA256 GNUTLS_DIG_SHA256
#define CRYPTO_MD_SHA384 GNUTLS_DIG_SHA384
#define CRYPTO_MD_SHA512 GNUTLS_DIG_SHA512

//typedef gnutls_pkcs7_t crypto_pkcs7;
/*
 * functions like crypto_pkcs7_get_signing_cert are supposed to return internal pointers
 * gnutls only allows for copies to be returned
 * the unfortunate solution to eventually free this mem is to 
 * treat this memory as internal pointers and free when pkcs7_free is called
 */
struct mem_link_t {
    void *curr;
    struct mem_link_t *next;
};

struct makeshift_pkcs7 {
    gnutls_pkcs7_t pkcs7;
    struct mem_link_t *extra_allocd_crts;
};
typedef struct makeshift_pkcs7 crypto_pkcs7;


typedef gnutls_x509_crt_t crypto_x509;
/** 
 *gnutls does not have a public md context
 *so we just store a copy of the to-be-hashed buffer instead
 **/
struct makeshift_gnutls_md_ctx {
    gnutls_datum_t tbh_buf;
    int hash_type;
};
typedef struct makeshift_gnutls_md_ctx crypto_md_ctx;


#else
#error Define SECVAR_CRYPTO_MBEDTLS or SECVAR_CRYPTO_OPENSSL or SECVAR_CRYPTO_GNUTLS
#endif
/**====================PKCS7 Functions ====================**/

/* 
 *checks the pkcs7 struct for using SHA256 as the message digest 
 *@param pkcs7 , a pointer to either a pkcs7 struct
 *@return SUCCESS if message digest is SHA256 else return errno
 */
int crypto_pkcs7_md_is_sha256(crypto_pkcs7 *pkcs7);

/*
 *free's the memory allocated for a pkcs7 structure
 *@param pkcs7 , a pointer to either a pkcs7 struct
 */
void crypto_pkcs7_free(crypto_pkcs7 *pkcs7);

/*
 *parses a buffer into a pointer to a pkcs7 struct. struct allocation is done internally to this func, but not dealloc
 *@param buf, buffer of data containg pkcs7 data
 *@param buflen, length of buf
 *@return if successful, a pointer to a pkcs7 struct. else returns NULL
 *NOTE: if successful (returns not NULL), remember to call crypto_free_pkcs7 to unalloc. 
 */
crypto_pkcs7 *crypto_pkcs7_parse_der(const unsigned char *buf,
				     const int buflen);

/*
 *returns one signing ceritficate from the PKKCS7 signing certificate chain
 *@param pkcs7 ,  a pointer to a pkcs7 struct
 *@param cert_num , the index (starts at 0) of the signing certificate to retrieve
 *@return a pointer to an X509 struct
 *NOTE: The returned pointer need not be freed, since it is a reference to memory in pkcs7
 */
crypto_x509 *crypto_pkcs7_get_signing_cert(crypto_pkcs7 *pkcs7, int cert_num);

/*
 *determines if signed data in pkcs7 is correctly signed by x509 by signing the hash with the pk and comparing the resulting signature with that in the pkcs7
 *@param pkcs7 , a pointer to a pkcs7 struct
 *@param x509 , a pointer to an x509 struct
 *@param hash , the expected hash
 *@param hash_len , the length of expected hash (ex: SHA256 = 32), if 0 then asssumptions are made based on md in pkcs7
 *@return SUCCESS or error number if resulting hashes are not equal
 */
int crypto_pkcs7_signed_hash_verify(crypto_pkcs7 *pkcs7, crypto_x509 *x509,
				    unsigned char *hash, int hash_len);

/*
 * The following protects against compilation failure due to custom mbedtls config
 * These SECVAR_CRYPTO_WRITE_FUNC should only be set if
 * Mbedtls has been built with MBEDTLS_FS_IO and MBEDTLS_PKCS7_WRITE_C
 * defined
 */
#ifdef SECVAR_CRYPTO_WRITE_FUNC
/*
 *generates a PKCS7 and create signature with private and public keys
 *@param pkcs7, the resulting PKCS7 DER buff, newData not appended, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param pkcs7Size, the length of pkcs7
 *@param newData, data to be added to be used in digest
 *@param dataSize , length of newData
 *@param crtFiles, array of file paths to public keys to sign with(PEM)
 *@param keyFiles, array of file paths to private keys to sign with
 *@param keyPairs, array length of key/crtFiles
 *@param hashFunct, hash function to use in digest, see crypto_hash_funct for values
 *@return SUCCESS or err number
 */
int crypto_pkcs7_generate_w_signature(unsigned char **pkcs7, size_t *pkcs7Size,
				      const unsigned char *newData,
				      size_t newDataSize, const char **crtFiles,
				      const char **keyFiles, int keyPairs,
				      int hashFunct);

/*
 *generates a PKCS7 with given signed data
 *@param pkcs7, the resulting PKCS7, newData not appended, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param pkcs7Size, the length of pkcs7
 *@param newData, data to be added to be used in digest
 *@param dataSize , length of newData
 *@param crtFiles, array of file paths to public keys that were used in signing with(PEM)
 *@param sigFiles, array of file paths to raw signed data files
 *@param keyPairs, array length of crt/signatures
 *@param hashFunct, hash function to use in digest, see crypto_hash_funct for values
 *@return SUCCESS or err number
 */
int crypto_pkcs7_generate_w_already_signed_data(
	unsigned char **pkcs7, size_t *pkcs7Size, const unsigned char *newData,
	size_t newDataSize, const char **crtFiles, const char **sigFiles,
	int keyPairs, int hashFunct);

/*
 *attempts to convert PEM data buffer into DER data buffer
 *@param input , PEM data buffer
 *@param ilen , length of input data
 *@param output , pointer to output DER data, not yet allocated
 *@param olen , pointer to length of output data
 *@return SUCCESS or errno if conversion failed
 *Note: Remember to unallocate the output data!
 */
int crypto_convert_pem_to_der(const unsigned char *input, size_t ilen,
			      unsigned char **output, size_t *olen);
#endif
/**====================X509 Functions ====================**/
int crypto_x509_get_der_len(crypto_x509 *x509);
int crypto_x509_get_tbs_der_len(crypto_x509 *x509);
int crypto_x509_get_version(crypto_x509 *x509);
int crypto_x509_get_sig_len(crypto_x509 *x509);
int crypto_x509_md_is_sha256(crypto_x509 *x509);
int crypto_x509_oid_is_pkcs1_sha256(crypto_x509 *x509);
int crypto_x509_get_pk_bit_len(crypto_x509 *x509);
/*
 *checks the type of the x509 and ensures that it is of type RSA
 *@param x509, a pointer to an x509 struct
 *@return SUCCESS if RSA or if not, returns the returned type value (differs for each crypto lib)
 */
int crypto_x509_is_RSA(crypto_x509 *x509);

/*
 *returns a short string describing the x509 message digest and encryption algorithms
 *@param x509, a pointer to an x509 struct
 *@param short_desc ,  already alloc'd pointer to output string
 *@param max_len   , number of bytes allocated to short_desc arg
 */
void crypto_x509_get_short_info(crypto_x509 *x509, char *short_desc,
				size_t max_len);

/*
 *parses the x509 struct into a human readable informational string
 *@param x509_info , already alloc-d pointer to output string
 *@param max_len , number of bytes allocated to x509_info
 *@param delim  , eachline will start with this, usually indent, when using openssl, the length of this value is the number of 8 spaced tabs
 *@param x509 ,  a pointer to  an x509 struct
 *@return number of bytes written to x509_info
 */
int crypto_x509_get_long_desc(char *x509_info, size_t max_len, const char *delim,
			      crypto_x509 *x509);

/*
 *parses a data buffer into an x509 struct 
 *@param x509 , output, a pointer to an x509 struct, should have already been allocated
 *@param data , pointer to data buffer containing an x509 in DER format
 *@param data_lem , length of data buffer
 */
/*
 *parses a buffer into a pointer to an x509 struct. struct allocation is done internally to this func, but not dealloc
 *@param buf, buffer of data containing x509 data in DER
 *@param buflen, length of buf
 *@return if successful, a void pointer to an x509 struct. else returns NULL
 *NOTE: if successful (returns not NULL), remember to call crypto_x509_free to unalloc. 
 */
crypto_x509 *crypto_x509_parse_der(const unsigned char *data, size_t data_len);

/*
 *unallocates x509 struct and memory
 *@param x509 ,  a pointer to an x509 struct, should have already been allocated
 */
void crypto_x509_free(crypto_x509 *x509);

/**====================General Functions ====================**/

/*
 *accepts an error code from either mbedtls or openssl and returns a string describing it
 *@param rc , the error code
 *@param out_str , an already allocated string, will be filled with string describing the error code
 *@out_max_len , the number of bytes allocated to out_str
 */
void crypto_strerror(int rc, char *out_str, size_t out_max_len);

/**====================Hashing Functions ====================**/
/*
 *Initializes and returns hashing context for the hashing function identified
 *@param ctx , the returned hashing context
 *@param md_id , the id of the hahsing function see above for possible values (CRYPTO_MD_xxx )
 *@return SUCCESS or err if the digest context setup failed
 */
int crypto_md_ctx_init(crypto_md_ctx **ctx, int md_id);

/*
 *can be repeatedly called to add data to be hashed by ctx
 *@param ctx , a pointer to either a hashing context
 *@param data , data to be hashed
 *@param data_len , length of data to be hashed
 *@return SUCCESS or err if additional data could not be added to context
 */
int crypto_md_update(crypto_md_ctx *ctx, const unsigned char *data,
		     size_t data_len);

/*
 *runs the hash over the supplied data (given with crypto_md_update) and returns it in hash
 *@param  ctx , a pointer to a hashing context
 *@param hash, an allocated data blob where the returned hash will be stored
 *@return SUCCESS or err if the hash generation was successful
 */
int crypto_md_finish(crypto_md_ctx *ctx, unsigned char *hash);

/*
 *frees the memory alloacted for the hashing context
 *@param ctx , a pointer to a hashing context
 */
void crypto_md_free(crypto_md_ctx *ctx);

/*
 *given a data buffer it generates the desired hash 
 *@param data, data to be hashed
 *@param size , length of buff
 *@param hashFunct, crypto_md_funct, message digest type
 *@param outBuff, the resulting hash, currently unalloc'd NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *@param outBuffSize, should be alg->size
 *@return SUCCESS or err number 
 *NOTE: outHash is allocated inside this funtion and must be unallocated sometime after calling
 */
int crypto_md_generate_hash(const unsigned char *data, size_t size,
			    int hashFunct, unsigned char **outHash,
			    size_t *outHashSize);
#endif
