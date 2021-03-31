#include <stdio.h>
#include <string.h>
#include <stdlib.h>// for exit
#include "crypto.h"
#include "include/prlog.h"
#include "include/err.h"

#ifdef OPENSSL

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#else

#include <mbedtls/pk_internal.h> // for validating cert pk data
#include "external/extraMbedtls/include/pkcs7.h"
#include "external/extraMbedtls/include/generate-pkcs7.h" //for pem to der

#endif

#ifdef OPENSSL

#include "generic.h"
void *crypto_pkcs7_parse_der(const unsigned char *buf, const int buflen) 
{
    int rc, i, num_signers;
    PKCS7* pkcs7;
    PKCS7_ISSUER_AND_SERIAL * issuer;
    PKCS7_SIGNER_INFO *signer_info;
    pkcs7 = d2i_PKCS7(NULL, &buf, buflen);
    if (!pkcs7) {
        prlog(PR_ERR, "ERROR: parsing PKCS7 with Openssl failed\n");
        rc = PKCS7_FAIL;
        goto out;
    }

    //make sure it contains signed data, openssl supports other types
    //returns 1 if successful
    rc = PKCS7_type_is_signed(pkcs7);
    if (!rc) {
        prlog(PR_ERR, "ERROR: PKCS7 does not contain signed data\n");
        rc = PKCS7_FAIL;
        crypto_pkcs7_free(pkcs7);
        goto out;
    }
    //mbedtls prints signer serial number when parsing, trying to stay as close to mbedtls output as possible
    //only prints anything if verbose is set
    num_signers = sk_PKCS7_SIGNER_INFO_num(PKCS7_get_signer_info(pkcs7));
    for (int s = 0; s < num_signers; s++) {
        signer_info = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(pkcs7), s);
        // issuer = PKCS7_get_issuer_and_serial(pkcs7, 0);
        if (!signer_info) {
            prlog(PR_ERR, "ERROR: Could not get PKCS7 signer information\n");
            rc = PKCS7_FAIL;
            goto out;
        }
        else {
            issuer = signer_info->issuer_and_serial;
            prlog(PR_INFO, "\tpkcs7 message signer serial: ");
            for (i = 0; i < (ssize_t)issuer->serial->length - 1; i++)
                prlog(PR_INFO, "%02x:", issuer->serial->data[i]);
             prlog(PR_INFO, "%02x\n", issuer->serial->data[i]);
        }
    }

    //if parsing made it to here then parsing was successful
    rc = SUCCESS;
out:
    if (rc)
        return NULL;

    return (void *)pkcs7; 
}

int crypto_pkcs7_md_is_sha256(void *pkcs7)
{
    X509_ALGOR *alg;
    //extract signer algorithms from pkcs7
    alg = sk_X509_ALGOR_value(((PKCS7 *)pkcs7)->d.sign->md_algs, 0);
    if (!alg) {
        prlog(PR_ERR, "ERROR: Could not extract message digest identifiers from PKCS7\n");
        return PKCS7_FAIL;
    }
    //extract nid from algorithms and ensure it is the same nid as SHA256
    if (OBJ_obj2nid(alg->algorithm) == NID_sha256 ) 
        return SUCCESS;
    else
        return PKCS7_FAIL;
}

void crypto_pkcs7_free(void *pkcs7) 
{
    PKCS7_free((PKCS7 *)pkcs7);
}

void* crypto_get_signing_cert(void *pkcs7, int cert_num)
{
    X509 *pkcs7_cert = NULL;

    pkcs7_cert = sk_X509_value(((PKCS7 *)pkcs7)->d.sign->cert, cert_num);

    return (void *)pkcs7_cert;

}

int crypto_get_x509_der_len(void *x509) 
{
    return i2d_X509(((X509 *)x509), NULL); 
}

int crypto_get_tbs_x509_der_len(void *x509) 
{
    return i2d_re_X509_tbs(((X509 *)x509), NULL); 
}

int crypto_get_x509_version(void *x509) 
{
    //add one because function return one less than actual certificate version, see https://www.openssl.org/docs/man1.1.0/man3/X509_get_version.html
    return X509_get_version((X509 *) x509) + 1;
}

int crypto_x509_is_RSA(void *x509)
{
    int pk_type;
    pk_type = X509_get_signature_type((X509 *)x509);
    if (pk_type != EVP_PK_RSA)
        return pk_type;
    else 
        return SUCCESS;
}

int crypto_get_x509_sig_len(void *x509)
{
    ASN1_BIT_STRING *sig;
    sig = X509_get0_pubkey_bitstr((X509 *) x509);
    if (!sig) {
        prlog( PR_ERR, "ERROR: Could not extract signature length from x509\n");
        return CERT_FAIL;
    }
    //returns 270 instead of 256 for RSA2048, probably because other struct attributes are included see ASN1_BIT_STRING definition
    return sig->length;
}

int crypto_x509_md_is_sha256(void *x509)
{
    const X509_ALGOR *alg = NULL;
    alg = X509_get0_tbs_sigalg((X509 *)x509);
    if (!alg) {
        prlog(PR_ERR, "ERROR: Could not extract algorithm from X509\n");
        return CERT_FAIL;
    }

    //extract nid from algorithms and ensure it is the same nid as SHA256
    if (OBJ_obj2nid(alg->algorithm) == NID_sha256WithRSAEncryption ) 
        return SUCCESS;
    else {
        prlog(PR_ERR, "ERROR: Certificate NID is not SHA256, expected %d found %d\n",NID_sha256, OBJ_obj2nid(alg->algorithm) );
        return CERT_FAIL;
    }
}

int crypto_x509_oid_is_pkcs1_sha256(void *x509)
{
    const X509_ALGOR *alg = NULL;

    alg = X509_get0_tbs_sigalg((X509 *)x509);
    if (!alg) {
        prlog(PR_ERR, "ERROR: Could not extract algorithm from X509\n");
        return CERT_FAIL;
    }

    if (OBJ_obj2nid(alg->algorithm) != NID_sha256WithRSAEncryption)
        return CERT_FAIL;
    return SUCCESS; 
}


int crypto_x509_get_pk_bit_len(void *x509)
{
    EVP_PKEY * pub = NULL;
    RSA *rsa = NULL;
    int length;
    
    pub = X509_get_pubkey((X509 *)x509);
    if (!pub) {
        prlog( PR_ERR, "ERROR: Failed to extract public key from x509\n");
        return CERT_FAIL;
    }
    rsa = EVP_PKEY_get1_RSA(pub);
    if (!rsa) {
        prlog( PR_ERR, "ERROR: Failed to extract RSA information from public key of x509\n");
        return CERT_FAIL;
    }
    length = RSA_bits(rsa);
    RSA_free(rsa);
    EVP_PKEY_free(pub);
    return length;
}

void crypto_x509_get_short_info(void *x509, char *short_desc, size_t max_len)
{
    const X509_ALGOR *alg = NULL;
    alg = X509_get0_tbs_sigalg((X509 *)x509);
    //unlikely failure
    if (!alg) {
        prlog(PR_ERR, "ERROR: Could not extract algorithm from X509\n");
        return;
    }
    //last arg set as ZERO to get short description in string
    OBJ_obj2txt(short_desc, max_len, alg->algorithm, 0);

}

int crypto_x509_get_long_desc(char *x509_info, size_t max_len, char *delim, void *x509)
{
    int rc;
    long actual_mem_len;
    BIO *bio = BIO_new(BIO_s_mem());
    char *tmp = NULL;
    rc = X509_print_ex(bio,(X509 *)x509, XN_FLAG_MULTILINE, X509_FLAG_COMPAT | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_SIGDUMP);
    if (rc < 0){
        prlog(PR_ERR, "ERROR: could not get BIO data on X509, openssl err#%d\n",rc);
        return rc;
    }
    //returns total data avialable
    actual_mem_len = BIO_get_mem_data(bio, &tmp);
    // check to make sure we do not overflow the allocated mem
    actual_mem_len  = max_len > actual_mem_len ? actual_mem_len : max_len - 1;
    memcpy(x509_info, tmp, actual_mem_len);
    BIO_free(bio);
    return actual_mem_len;
}

void *crypto_x509_parse_der(const unsigned char *data, size_t data_len)
{
    X509* x509;
    x509 = d2i_X509(NULL, &data, data_len);
    
    if (!x509)
        return NULL;

    return (void *)x509; 
}

void crypto_x509_free(void *x509)
{
    X509_free((X509 *)x509);
}

int crypto_convert_pem_to_der(const unsigned char *input, size_t ilen, unsigned char **output, size_t *olen)
{
    int rc;
    BIO *bio;
    bio = BIO_new_mem_buf(input, ilen);
    //these variables are not needed on return, just needed to properly call the function
    char *header = NULL, *name = NULL;
    //returns 0 for fail and 1 on success
    rc = !PEM_read_bio(bio, &name, &header, output, (long int *)olen);
    if (header) free(header);
    if (name) free(name);
    BIO_free(bio);
    return rc;
}

/*=====================END OPENSSL FUNCTIONS=====================*/
#else
/*====================START MBEDTLS FUNCTIONS====================*/



void *crypto_pkcs7_parse_der(const unsigned char *buf, const int buflen) 
{
    int rc;
    struct mbedtls_pkcs7 *pkcs7;
    pkcs7 = malloc(sizeof(struct mbedtls_pkcs7));
    if (!pkcs7) {
     prlog(PR_ERR, "ERROR: failed to allocate memory\n");
     return NULL;
    }
    mbedtls_pkcs7_init(pkcs7);
    rc = mbedtls_pkcs7_parse_der(buf, buflen, pkcs7);
    if (rc != MBEDTLS_PKCS7_SIGNED_DATA)  // if pkcs7 parsing fails, then try new signed data format 
            prlog(PR_ERR, "ERROR: parsing pkcs7 failed mbedtls error #%04x\n", rc); 
    else 
        rc = SUCCESS;

    if (rc) {
        crypto_pkcs7_free(pkcs7);
        return NULL;
    }
    else
        return (void *)pkcs7;
}

int crypto_pkcs7_md_is_sha256(void *pkcs7)
{
    return MBEDTLS_OID_CMP(MBEDTLS_OID_DIGEST_ALG_SHA256, &((struct mbedtls_pkcs7 *)pkcs7)->signed_data.digest_alg_identifiers);
}
void crypto_pkcs7_free(void *pkcs7)
{
        mbedtls_pkcs7_free((struct mbedtls_pkcs7 *)pkcs7);
        free(pkcs7);
}

void* crypto_get_signing_cert(void *pkcs7, int cert_num)
{
    mbedtls_x509_crt *pkcs7_cert = NULL;

    pkcs7_cert = &((struct mbedtls_pkcs7 *)pkcs7)->signed_data.certs;
    for (int i = 0; i < cert_num && pkcs7_cert != NULL; i++)
        pkcs7_cert = pkcs7_cert->next;

    return (void *)pkcs7_cert;

}

int crypto_get_x509_der_len(void *x509) 
{
    return ((mbedtls_x509_crt *)x509)->raw.len; 
}

int crypto_get_tbs_x509_der_len(void *x509) 
{
    return ((mbedtls_x509_crt *)x509)->tbs.len;
}

int crypto_get_x509_version(void *x509) 
{
    return ((mbedtls_x509_crt *)x509)->version;
}

int crypto_x509_is_RSA(void *x509)
{
    int pk_type;
    pk_type = ((mbedtls_x509_crt *)x509)->pk.pk_info->type;
    if (pk_type != MBEDTLS_PK_RSA)
        //zero is also a pk type (MBEDTLS_PK_NONE) so return generic failure if zero so it doesnt look like a success
       return  (pk_type == 0 ? CERT_FAIL : pk_type);
    else 
        return SUCCESS;
}

int crypto_get_x509_sig_len(void *x509)
{
    return ((mbedtls_x509_crt *)x509)->sig.len;
}

int crypto_x509_md_is_sha256(void *x509)
{
    if (((mbedtls_x509_crt *)x509)->sig_md == MBEDTLS_MD_SHA256) 
        return SUCCESS;
    else
        return CERT_FAIL;
}

int crypto_x509_oid_is_pkcs1_sha256(void *x509)
{
    if ( MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS1_SHA256, &((mbedtls_x509_crt *)x509)->sig_oid))
        return CERT_FAIL;
    return SUCCESS;
}

int crypto_x509_get_pk_bit_len(void *x509)
{
    return mbedtls_pk_get_bitlen( &((mbedtls_x509_crt *)x509)->pk);
}

void crypto_x509_get_short_info(void *x509, char *short_desc, size_t max_len)
{

    mbedtls_x509_sig_alg_gets(short_desc, max_len, &((mbedtls_x509_crt *)x509)->sig_oid,
                       ((mbedtls_x509_crt *)x509)->sig_pk, ((mbedtls_x509_crt *)x509)->sig_md, 
                       ((mbedtls_x509_crt *)x509)->sig_opts );
}

int crypto_x509_get_long_desc(char *x509_info, size_t max_len, char *delim, void *x509)
{
    return mbedtls_x509_crt_info(x509_info, max_len, delim, ((mbedtls_x509_crt *)x509)); 
}

void *crypto_x509_parse_der(const unsigned char *data, size_t data_len)
{
    int rc;
    mbedtls_x509_crt *x509 = NULL;
    x509 = malloc(sizeof(*x509));
    if (!x509){
      prlog(PR_ERR, "ERROR: failed to allocate memory\n");
      return NULL;
    }
    mbedtls_x509_crt_init(x509);
    rc = mbedtls_x509_crt_parse(x509, data, data_len); 

    if (rc) {
        crypto_x509_free(x509);
        return NULL;
    }
    else
        return (void *)x509;
}

void crypto_x509_free(void *x509)
{
    mbedtls_x509_crt_free((mbedtls_x509_crt *)x509);
    free(x509);
}

int crypto_convert_pem_to_der(const unsigned char *input, size_t ilen, unsigned char **output, size_t *olen)
{
    return convert_pem_to_der(input, ilen, output, olen);
}
#endif