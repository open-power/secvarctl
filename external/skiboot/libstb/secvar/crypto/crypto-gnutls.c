// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifdef SECVAR_CRYPTO_GNUTLS
// ^extra precaution to not compile with gnutls unless specified
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // for exit
#include "crypto.h"
#include "include/prlog.h"
#include "include/err.h"

#include <gnutls/x509.h>
#include <gnutls/pkcs7.h>
#include <gnutls/abstract.h>

// gets hash alg and returns digest length
// returns 0 on fail
static size_t get_hash_len(int hash_type) 
{
    size_t len;
    //get hashlen
    switch (hash_type) {
    case CRYPTO_MD_SHA1:
        len = 20;
        break;
    case CRYPTO_MD_SHA224:
        len = 28;
        break;
    case CRYPTO_MD_SHA256:
        len = 32;
        break;
    case CRYPTO_MD_SHA384:
        len = 48;
        break;
    case CRYPTO_MD_SHA512:
        len = 64;
        break;
    default:
        prlog(PR_ERR, "ERROR: Unknown hash alg (%d)\n", hash_type);
        return 0;
    }

    return len;
}
/**====================PKCS7 Functions ====================**/

/* 
 *checks the pkcs7 struct for using SHA256 as the message digest 
 *@param pkcs7 , a pointer to either an openssl or mbedtls pkcs7 struct
 *@return SUCCESS if message digest is SHA256 else return errno
 */
int crypto_pkcs7_md_is_sha256(crypto_pkcs7 *pkcs7)
{
    // could be helpful gnutls_pkcs7_print_signature_info
    int rc, index_to_get = 0;
    gnutls_pkcs7_signature_info_st pkcs7_info;


    rc = gnutls_pkcs7_get_signature_info(pkcs7->pkcs7, index_to_get, &pkcs7_info);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;
    
    if (pkcs7_info.algo != GNUTLS_SIGN_RSA_SHA256)
        rc = PKCS7_FAIL;
    else
        rc = SUCCESS;

    gnutls_pkcs7_signature_info_deinit(&pkcs7_info);
    return rc;
}

/*
 *free's the memory allocated for a pkcs7 structure
 *@param pkcs7 , a pointer to either an openssl or mbedtls pkcs7 struct
 */
void crypto_pkcs7_free(crypto_pkcs7 *pkcs7)
{
    struct mem_link_t *tmp_itr, *prev = NULL;
    gnutls_pkcs7_deinit(pkcs7->pkcs7);
    for (tmp_itr = pkcs7->extra_allocd_crts; tmp_itr != NULL; prev = tmp_itr, tmp_itr = tmp_itr->next) {
        if (prev)
            gnutls_free(prev);
        crypto_x509_free(tmp_itr->curr);
    }
    if (prev)
            gnutls_free(prev);

    gnutls_free(pkcs7);
}

crypto_pkcs7 *crypto_pkcs7_parse_der(const unsigned char *buf,
                     const int buflen)
{
    int rc;
    crypto_pkcs7 *pkcs7 = NULL;
    const gnutls_datum_t data_struct = {.data = (unsigned char *)buf, .size = buflen};
    
    pkcs7 = gnutls_malloc(sizeof(*pkcs7));
    if (!pkcs7) {
        prlog(PR_ERR, "ERROR: Failed to allocate data\n");
        return NULL;
    }
    pkcs7->extra_allocd_crts = NULL;
    /*pkcs7->extra_allocd_crts.curr = NULL;
    pkcs7->extra_allocd_crts.next = NULL;*/

    
    rc = gnutls_pkcs7_init(&pkcs7->pkcs7);
    if (rc != GNUTLS_E_SUCCESS)
        return NULL;

    rc = gnutls_pkcs7_import(pkcs7->pkcs7, &data_struct, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        crypto_pkcs7_free(pkcs7);
        return NULL;
    }

    return pkcs7;
}

crypto_x509 *crypto_pkcs7_get_signing_cert(crypto_pkcs7 *pkcs7, int cert_num)
{
    int rc;
    gnutls_datum_t raw_crt;
    crypto_x509 *crt = NULL;
    struct mem_link_t *new = NULL, *prev = NULL;
    /*
     *So this will actually return a copy of the internal certificate
     *The other crypto libs return internal pointers
     *This means we must manually free it when pkcs_free is called
     */
    rc = gnutls_pkcs7_get_crt_raw2(pkcs7->pkcs7, cert_num, &raw_crt);
    if (rc != GNUTLS_E_SUCCESS)
        return NULL;

    /*crt = gnutls_malloc(sizeof(*crt));
    if (!crt) {
        prlog(PR_ERR, "ERROR: Failed to allocate data\n");
        return NULL;
    }*/
    crt = crypto_x509_parse_der(raw_crt.data, raw_crt.size);
    gnutls_free(raw_crt.data);

    if (!crt)
        return NULL;

    // add new alloc to linked list
    new = pkcs7->extra_allocd_crts;
    while (new != NULL) {
        prev = new;
        new = new->next;
    }
    new = malloc(sizeof(*new));
    if (!new) {
        prlog(PR_ERR, "ERROR: Failed to allocate data\n");
        crypto_x509_free(crt);
        return NULL;
    }
    new->curr = crt;
    new->next = NULL;
    // add it to the chain
    if (prev)
        prev->next = new;
    else
        pkcs7->extra_allocd_crts = new; 

    return crt;
}


int crypto_pkcs7_signed_hash_verify(crypto_pkcs7 *pkcs7, crypto_x509 *x509,
                    unsigned char *hash, int hash_len)
{
    int rc, num_of_sigs;
    gnutls_datum_t hash_struct;
    gnutls_pubkey_t pubkey;
    gnutls_pkcs7_signature_info_st pkcs7_info;

    unsigned verification_flags = GNUTLS_VERIFY_DISABLE_TIME_CHECKS 
                                  | GNUTLS_VERIFY_DISABLE_CA_SIGN 
                                  | GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1 
                                  | GNUTLS_VERIFY_DISABLE_CRL_CHECKS;
    
    // gnutls only has pkcs7 verification functions for prehashed data, our data is already hashed :(
    // so we make our own!

    // get pubkey from x509
    rc = gnutls_pubkey_init(&pubkey);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;
    rc = gnutls_pubkey_import_x509(pubkey, *x509, 0);
    if (rc != GNUTLS_E_SUCCESS)
        goto out;
    num_of_sigs = gnutls_pkcs7_get_signature_count(pkcs7->pkcs7);

    for (int i = 0; i < num_of_sigs; i++) {
        rc = gnutls_pkcs7_get_signature_info(pkcs7->pkcs7, i, &pkcs7_info);
        if (rc != GNUTLS_E_SUCCESS)
            goto out;
        hash_struct.data = hash;
        //if given hash_len is 0 then make assumptions
        hash_struct.size = hash_len > 0 ? hash_len : get_hash_len(gnutls_sign_get_hash_algorithm(pkcs7_info.algo)); 
        rc = gnutls_pubkey_verify_hash2(pubkey, pkcs7_info.algo, verification_flags,
                                         &hash_struct, &pkcs7_info.sig);
        // rc = gnutls_pubkey_verify_hash2(pubkey, GNUTLS_SIGN_RSA_SHA256, verification_flags,
        //                                  &hash_struct, &pkcs7_info.sig);
        gnutls_pkcs7_signature_info_deinit(&pkcs7_info);

        if (rc == GNUTLS_E_SUCCESS)
            break;
    }

out:
    gnutls_pubkey_deinit(pubkey);

    return rc;
}


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
                      int hashFunct)
{
    int rc;
    unsigned char key_id[20], crt_id[20];
    size_t id_len = 20;
    gnutls_datum_t key_PEM = {NULL, 0}, crt_PEM = {NULL, 0}, 
                    new_data = {(unsigned char *)newData, newDataSize}, 
                    out_data;
    gnutls_x509_crt_t crt;
    gnutls_privkey_t key;
    gnutls_x509_privkey_t x509_key;
    gnutls_pkcs7_t pkcs7_st;

    if (keyPairs == 0) {
        prlog(PR_ERR,
              "ERROR: No signers given, cannot generate PKCS7\n");
        return PKCS7_FAIL;
    }

    rc = gnutls_pkcs7_init(&pkcs7_st);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;

    // for every key pair get the data and add the signer to the pkcs7
    for (int i = 0; i < keyPairs; i++) {
        // get data of private keys
        rc = gnutls_load_file(keyFiles[i], &key_PEM);
        if (rc != GNUTLS_E_SUCCESS) {
            prlog(PR_ERR, "ERROR: Failed to read file %s\n", keyFiles[i]);
            goto out;
        }
        //get data from crt
        rc = gnutls_load_file(crtFiles[i], &crt_PEM);
        if (rc != GNUTLS_E_SUCCESS) {
            gnutls_free(key_PEM.data);
            prlog(PR_ERR, "ERROR: Failed to read file %s\n", crtFiles[i]);
            goto out;
        }
        
        // get private x509 key from private key PEM data
        rc = gnutls_x509_privkey_init(&x509_key);
        if (rc != GNUTLS_E_SUCCESS){
            gnutls_free(key_PEM.data);
            gnutls_free(crt_PEM.data);
            goto out;
        }
        rc = gnutls_x509_privkey_import(x509_key, &key_PEM, GNUTLS_X509_FMT_PEM);
        gnutls_free(key_PEM.data);
        if (rc != GNUTLS_E_SUCCESS){
            prlog(PR_ERR,
                  "ERROR: Failed to parse private key into gnutls x509 privkey struct\n");
            gnutls_free(crt_PEM.data);
            gnutls_x509_privkey_deinit(x509_key);
            goto out;
        }
        // get private key from x509 private key
        // apparently point to data insode x509_key still so don't dealloc
        rc = gnutls_privkey_init(&key);
        if (rc != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(x509_key);
            gnutls_free(crt_PEM.data);
            goto out;
        }
        rc = gnutls_privkey_import_x509(key, x509_key, 0);
        if (rc != GNUTLS_E_SUCCESS){
            prlog(PR_ERR,
                  "ERROR: Failed to cast x509 private key struct into gnutls privkey struct\n");
            gnutls_x509_privkey_deinit(x509_key);
            gnutls_privkey_deinit(key);
            gnutls_free(crt_PEM.data);
            goto out;
        }

        // get x509 from cert PEM buff
        rc = gnutls_x509_crt_init(&crt);
        if (rc != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(x509_key);
            gnutls_privkey_deinit(key);
            gnutls_free(crt_PEM.data);
            goto out;
        }
        rc = gnutls_x509_crt_import(crt, &crt_PEM, GNUTLS_X509_FMT_PEM);
        gnutls_free(crt_PEM.data);
        if (rc != GNUTLS_E_SUCCESS) {
            prlog(PR_ERR,
                  "ERROR: Failed to parse x509 PEM data into gnutls x509 struct\n");
            gnutls_x509_privkey_deinit(x509_key);
            gnutls_privkey_deinit(key);
            gnutls_x509_crt_deinit(crt);
            goto out;
        }

        // make sure crt and private key are correlated
        rc = gnutls_x509_crt_get_key_id(crt, GNUTLS_KEYID_USE_SHA1, crt_id,  &id_len);
        if (rc != GNUTLS_E_SUCCESS || id_len != 20){
            prlog(PR_ERR,
                  "ERROR: Failed to get public key ID\n");
            gnutls_x509_privkey_deinit(x509_key);
            gnutls_privkey_deinit(key);
            gnutls_x509_crt_deinit(crt);
            goto out;
        }
        rc = gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA1, key_id,  &id_len);
        if (rc != GNUTLS_E_SUCCESS || id_len != 20){
            prlog(PR_ERR,
                  "ERROR: Failed to get private key ID\n");
            gnutls_x509_privkey_deinit(x509_key);
            gnutls_privkey_deinit(key);
            gnutls_x509_crt_deinit(crt);
            goto out;
        }
        if (memcmp(key_id, crt_id, id_len) != 0){
            rc = INVALID_FILE;
            prlog(PR_ERR,
                  "ERROR: Public and private keys are not correlated\n");
            gnutls_x509_privkey_deinit(x509_key);
            gnutls_privkey_deinit(key);
            gnutls_x509_crt_deinit(crt);
            goto out;
        }

        //add the signature to the pkcs7
        //returns NULL is failure
        // maybe add GNUTLS_PKCS7_INCLUDE_CERT
        rc = gnutls_pkcs7_sign(pkcs7_st, crt, key, &new_data, 0, 0, hashFunct, GNUTLS_PKCS7_INCLUDE_CERT);
        //reset mem
        gnutls_privkey_deinit(key);
        gnutls_x509_privkey_deinit(x509_key);
        gnutls_x509_crt_deinit(crt);

        if (rc != GNUTLS_E_SUCCESS) {
            prlog(PR_ERR,
                  "ERROR: Failed to add signer to the pkcs7 structure\n");
            goto out;
        }
    }

    //convert struct to DER
    rc = gnutls_pkcs7_export2(pkcs7_st, GNUTLS_X509_FMT_DER , &out_data);
    if (rc != GNUTLS_E_SUCCESS) {
        prlog(PR_ERR,
              "ERROR: Failed to convert generate PKCS7 struct to DER data\n");
        goto out;
    }
    
    *pkcs7 = out_data.data;
    *pkcs7Size = out_data.size;

out:
    gnutls_pkcs7_deinit(pkcs7_st);

    return rc;
}

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
    int keyPairs, int hashFunct) 
{
    prlog(PR_ERR,
          "ERROR: Currently unable to support generation of PKCS7 with externally generated signatures when compiling with GNUTLS\n");
    return PKCS7_FAIL;
}

int crypto_convert_pem_to_der(const unsigned char *input, size_t ilen,
                  unsigned char **output, size_t *olen)
{
    int rc;
    const gnutls_datum_t data_struct = {.data = (unsigned char *) input, .size = ilen};
    gnutls_datum_t result;

    rc = gnutls_pem_base64_decode2(NULL, &data_struct, &result);
    if (rc == GNUTLS_E_SUCCESS) {
        *output = result.data;
        *olen = result.size;
    }

    return rc;
}

#endif

/**====================X509 Functions ====================**/
int crypto_x509_get_der_len(crypto_x509 *x509)
{
    int rc;
    gnutls_datum_t data_struct = {NULL, 0};

    rc = gnutls_x509_crt_export2(*x509, GNUTLS_X509_FMT_DER, &data_struct);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;

    // is this a good way to prevent against unsigned -> signed cast issues?
    if (INT_MAX - data_struct.size < 0) {
        gnutls_free(data_struct.data);
        return CERT_FAIL;
    }

    gnutls_free(data_struct.data);
    return data_struct.size;
}

int crypto_x509_get_tbs_der_len(crypto_x509 *x509)
{
    int rc;
    gnutls_datum_t data_struct = {NULL, 0};

    rc = gnutls_x509_crt_get_raw_dn(*x509, &data_struct);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;

    if (INT_MAX - data_struct.size < 0) {
        gnutls_free(data_struct.data);
        return CERT_FAIL;
    }

    gnutls_free(data_struct.data);
    return data_struct.size;
}

int crypto_x509_get_version(crypto_x509 *x509)
{
    return gnutls_x509_crt_get_version(*x509);
}

int crypto_x509_is_RSA(crypto_x509 *x509)
{
    int algo;
    unsigned int bits;

    algo = gnutls_x509_crt_get_pk_algorithm(*x509, &bits);
    if (algo != GNUTLS_PK_RSA)
        return algo;

    return SUCCESS;
}

int crypto_x509_get_sig_len(crypto_x509 *x509)
{
    int bits, rc;
    size_t sig_size;
    bits = crypto_x509_get_pk_bit_len(x509);
    if (bits < 0)
        return bits;

    /*
     *we can request the signature and it will fill in the right size
     *but only if the initial size is at least the actual size.
     *its a bit of a rabbit whole but checkout:
     *gnutls_x509_crt_get_signature -> _gnutls_copy_data
     *bit len will always be greater than bytes so...
     */
    sig_size = bits;
    rc = gnutls_x509_crt_get_signature(*x509, NULL, &sig_size);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;
    if (INT_MAX - sig_size < 0)
        return CERT_FAIL;

    return sig_size;
}

int crypto_x509_md_is_sha256(crypto_x509 *x509)
{
    gnutls_sign_algorithm_t alg = gnutls_x509_crt_get_signature_algorithm (*x509);
    if (alg == GNUTLS_SIGN_RSA_SHA256)
        return SUCCESS;

    return CERT_FAIL;
}

int crypto_x509_oid_is_pkcs1_sha256(crypto_x509 *x509)
{
    // is this lazy?
    return crypto_x509_md_is_sha256(x509);
}


int crypto_x509_get_pk_bit_len(crypto_x509 *x509)
{
    int algo;
    unsigned int bits;

    algo = gnutls_x509_crt_get_pk_algorithm(*x509, &bits);
    // returns negative if failure
    if (algo < 0)
        return algo;  

    return bits;
}


void crypto_x509_get_short_info(crypto_x509 *x509, char *short_desc,
                size_t max_len) 
{
    unsigned int algo, bits;
    const char *name;
    long data_to_copy;

    algo = gnutls_x509_crt_get_pk_algorithm(*x509, &bits);

    name = gnutls_pk_algorithm_get_name(algo);
    data_to_copy = max_len > strlen(name) ? strlen(name) : max_len - 1;
    memcpy(short_desc, name, data_to_copy);

}

int crypto_x509_get_long_desc(char *x509_info, size_t max_len, const char *delim,
                  crypto_x509 *x509)
{
    int rc;
    // gnutls_datum_t data_struct = {.data = NULL, .size = 0};
    gnutls_datum_t data_struct;
    long data_to_copy;
    
    rc = gnutls_x509_crt_print(*x509, GNUTLS_CRT_PRINT_COMPACT, &data_struct);
    if (rc != GNUTLS_E_SUCCESS) {
        gnutls_free(data_struct.data);
        return rc;
    }

    // check to make sure we do not overflow the allocated mem
    data_to_copy = max_len > data_struct.size ? data_struct.size : max_len - 1;
    memcpy(x509_info, data_struct.data, data_to_copy);
    gnutls_free(data_struct.data);

    return data_to_copy;
}


crypto_x509 *crypto_x509_parse_der(const unsigned char *data, size_t data_len)
{
    int rc;
    gnutls_x509_crt_t *crt = NULL;
    const gnutls_datum_t data_struct = {.data = (unsigned char *)data, .size = data_len};

    crt = gnutls_malloc(sizeof(*crt));
    if (!crt) {
        prlog(PR_ERR, "ERROR: Failed to allocate data\n");
        return NULL;
    }

    rc = gnutls_x509_crt_init(crt);
    if (rc != GNUTLS_E_SUCCESS)
        return NULL;

    rc = gnutls_x509_crt_import(*crt, &data_struct, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        crypto_x509_free(crt);
        return NULL;
    }

    return crt;
}


void crypto_x509_free(crypto_x509 *x509)
{
    gnutls_x509_crt_deinit(*x509);
    gnutls_free(x509);
}

/**====================General Functions ====================**/

void crypto_strerror(int rc, char *out_str, size_t out_max_len)
{
    memcpy(out_str, gnutls_strerror(rc), out_max_len);
}

/**====================Hashing Functions ====================**/

int crypto_md_ctx_init(crypto_md_ctx **ctx, int md_id)
{
    // crypto_md_ctx new_ctx = {
    //     .tbh_buf = {
    //         .data = NULL, 
    //         .size = 0 
    //     },
    //     .hash_type = md_id
    // };
    crypto_md_ctx *new_ctx = NULL;
    new_ctx = gnutls_malloc(sizeof(*new_ctx));
    if (!new_ctx) {
        prlog(PR_ERR, "ERROR: Failed to allocate data\n");
        return ALLOC_FAIL;
    }
    new_ctx->tbh_buf.data = NULL;
    new_ctx->tbh_buf.size = 0;
    new_ctx->hash_type = md_id;

    *ctx = new_ctx;
    return GNUTLS_E_SUCCESS;
}

int crypto_md_update(crypto_md_ctx *ctx, const unsigned char *data,
             size_t data_len)
{
    if (!ctx->tbh_buf.data)
        ctx->tbh_buf.data = gnutls_malloc(data_len);
    else
        ctx->tbh_buf.data = gnutls_realloc(ctx->tbh_buf.data, ctx->tbh_buf.size + data_len);

    if (!ctx->tbh_buf.data)
        return ALLOC_FAIL;

    memcpy(ctx->tbh_buf.data + ctx->tbh_buf.size, data, data_len);

    ctx->tbh_buf.size += data_len;
    return GNUTLS_E_SUCCESS;
}


int crypto_md_finish(crypto_md_ctx *ctx, unsigned char *hash)
{    
    size_t exp_hash_size, returned_hash_len;
    int rc;
    
    exp_hash_size = get_hash_len(ctx->hash_type);
    if (exp_hash_size == 0)
        return HASH_FAIL;

    // function uses returned_hash_len to get max len of `hash` and also writes bytes written
    returned_hash_len = exp_hash_size;
    rc = gnutls_fingerprint(ctx->hash_type, &ctx->tbh_buf, hash, &returned_hash_len);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;

    if (returned_hash_len != exp_hash_size)
        return HASH_FAIL;

    return rc;
}


void crypto_md_free(crypto_md_ctx *ctx)
{
    if (ctx->tbh_buf.data)
        gnutls_free(ctx->tbh_buf.data);
    gnutls_free(ctx);
}

int crypto_md_generate_hash(const unsigned char *data, size_t size,
                int hashFunct, unsigned char **outHash,
                size_t *outHashSize)
{
    int rc;
    const gnutls_datum_t data_struct = {.data = (unsigned char *)data, .size = size};
    size_t hash_len;

    hash_len = get_hash_len(hashFunct);
     if (hash_len == 0)
        return HASH_FAIL;

    *outHash = malloc(hash_len);
    if (!*outHash) {
        prlog(PR_ERR, "ERROR: Failed to allocate data\n");
        return ALLOC_FAIL;
    }

    rc = gnutls_fingerprint(hashFunct, &data_struct, *outHash, &hash_len);
    *outHashSize = hash_len;
    if (rc)
        free(*outHash);


    return rc;
}

#endif