/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "include/pkcs7.h"
#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif
/*#if defined(MBEDTLS_PKCS7_USE_C)*/

#include <mbedtls/x509.h>
#include <mbedtls/asn1.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/oid.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if defined(MBEDTLS_FS_IO)
#include <sys/types.h>
#include <sys/stat.h>
#endif
#include <unistd.h>

#if defined(MBEDTLS_PLATFORM_C)
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free      free
#define mbedtls_calloc    calloc
#define mbedtls_printf    printf
#define mbedtls_snprintf  snprintf
#endif

#if defined(MBEDTLS_HAVE_TIME)
#include <mbedtls/platform_time.h>
#endif
#if defined(MBEDTLS_HAVE_TIME_DATE)
#include <time.h>
#endif
#include <fcntl.h> //O_WRONLY
/* Prototypes */
//ADDED BY NICK
#include "../../include/prlog.h"
static void pkcs7_free_signer_info( mbedtls_pkcs7_signer_info *si );


int mbedtls_pkcs7_load_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *file;
    struct stat st;
    int rc;

    rc = stat( path, &st );
    if( rc )
        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );

    if( ( file = fopen( path, "rb" ) ) == NULL )
        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );

    *n = (size_t) st.st_size;

    *buf = mbedtls_calloc( 1, *n + 1 );
    if( *buf == NULL )
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

    if( fread( *buf, 1, *n, file ) != *n )
    {
        fclose( file );

        mbedtls_platform_zeroize( *buf, *n + 1 );
        mbedtls_free( *buf );

        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );
    }

    fclose( file );

    (*buf)[*n] = '\0';

    return( 0 );
}


/**
 * Initializes the pkcs7 structure.
 */
void mbedtls_pkcs7_init( mbedtls_pkcs7 *pkcs7 )
{
    memset( pkcs7, 0, sizeof( mbedtls_pkcs7 ) );
}

static int pkcs7_get_next_content_len( unsigned char **p, unsigned char *end,
                                       size_t *len )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_tag( p, end, len, MBEDTLS_ASN1_CONSTRUCTED
                    | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

    return( 0 );
}

/**
 * version Version
 * Version ::= INTEGER
 **/
static int pkcs7_get_version( unsigned char **p, unsigned char *end, int *ver )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_VERSION + ret );

    return( 0 );
}

/**
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content
 *              [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 **/
static int pkcs7_get_content_info_type( unsigned char **p, unsigned char *end,
                                        mbedtls_pkcs7_buf *pkcs7 )
{
    size_t len = 0;
    int ret;

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                            | MBEDTLS_ASN1_SEQUENCE );
    if( ret )
        return( MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO + ret );

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_OID );
    if( ret )
        return( MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO + ret );

    pkcs7->tag = MBEDTLS_ASN1_OID;
    pkcs7->len = len;
    pkcs7->p = *p;

    return( ret );
}

/**
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
static int pkcs7_get_digest_algorithm( unsigned char **p, unsigned char *end,
                                       mbedtls_x509_buf *alg )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_alg_null( p, end, alg ) ) != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    return( 0 );
}

/**
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
static int pkcs7_get_digest_algorithm_set( unsigned char **p,
                                           unsigned char *end,
                                           mbedtls_x509_buf *alg )
{
    size_t len = 0;
    int ret;

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                            | MBEDTLS_ASN1_SET );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    end = *p + len;

    /** For now, it assumes there is only one digest algorithm specified **/
    ret = mbedtls_asn1_get_alg_null( p, end, alg );
    if( ret )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    return( 0 );
}

/**
 * certificates :: SET OF ExtendedCertificateOrCertificate,
 * ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate -- x509,
 *      extendedCertificate[0] IMPLICIT ExtendedCertificate }
 **/
static int pkcs7_get_certificates( unsigned char **buf, size_t buflen,
                                   mbedtls_x509_crt *certs )
{
    int ret, offset = 0;
    mbedtls_x509_crt *next = NULL, *prev = NULL;

    //get first one
    if( ( ret = mbedtls_x509_crt_parse( certs, *buf, buflen ) ) < 0 )
        return( ret );
     offset += certs->raw.len;
    prev = certs;
    //get other ones if the length of the certificates is greater than the currently amount of read bytes
    while (offset < buflen) {
        next = malloc(sizeof(*next));
        mbedtls_x509_crt_init(next);
        //if it fails than unallocate, do not add to chain, return failure
         if( ( ret = mbedtls_x509_crt_parse(next, *buf + offset, buflen - offset ) ) < 0 ) {
            mbedtls_x509_crt_free(next);
            if (next) free(next);
            return( ret );
         } 
         //else add it to the chain and update the amount of read bytes of buflen
        prev->next = next;
        prev = next;
        offset += prev->raw.len;
    }

    return( 0 );
}

/**
 * EncryptedDigest ::= OCTET STRING
 **/
static int pkcs7_get_signature( unsigned char **p, unsigned char *end,
                                mbedtls_pkcs7_buf *signature )
{
    int ret;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE + ret );

    signature->tag = MBEDTLS_ASN1_OCTET_STRING;
    signature->len = len;
    signature->p = *p;

    return( 0 );
}

/**
 * SignerInfo ::= SEQUENCE {
 *      version Version;
 *      issuerAndSerialNumber   IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes
 *              [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes
 *              [1] IMPLICIT Attributes OPTIONAL,
 **/
static int pkcs7_get_signer_info( unsigned char **p, unsigned char *end_set,
                                  mbedtls_pkcs7_signer_info *signer )
{
    int ret;
    size_t len;
    unsigned char *end_info;

    ret = mbedtls_asn1_get_tag( p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
            | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    end_info = *p + len;

    ret = mbedtls_asn1_get_int( p, end_info, &signer->version );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    ret = mbedtls_asn1_get_tag( p, end_info, &len, MBEDTLS_ASN1_CONSTRUCTED
            | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    signer->issuer_raw.p = *p;

    ret = mbedtls_asn1_get_tag( p, end_info, &len, MBEDTLS_ASN1_CONSTRUCTED
            | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    ret  = mbedtls_x509_get_name( p, *p + len, &signer->issuer );
    if( ret != 0 )
        return( ret );

    signer->issuer_raw.len =  *p - signer->issuer_raw.p;

    ret = mbedtls_x509_get_serial( p, end_info, &signer->serial );
    if( ret != 0 )
        return( ret );
    ssize_t i;
    prlog(PR_INFO, "\tpkcs7 message signer serial: ");
    for (i = 0; i < (ssize_t)signer->serial.len - 1; i++)
        prlog(PR_INFO, "%02x:", signer->serial.p[i]);
    prlog(PR_INFO, "%02x\n", signer->serial.p[i]);
    ret = pkcs7_get_digest_algorithm( p, end_info,
            &signer->alg_identifier );
    if( ret != 0 )
        return( ret );

    ret = pkcs7_get_digest_algorithm( p, end_info,
            &signer->sig_alg_identifier );
    if( ret != 0 )
        return( ret );

    ret = pkcs7_get_signature( p, end_info, &signer->sig );
    if( ret != 0 )
        return( ret );

    signer->next = NULL;

    /*
     * place p at the end of the signerInfo, even if we didn't parse all the
     * info
     */
    *p = end_info;

    return( 0 );
}

/**
 * SignerInfos ::= SET OF SignerInfo
 */
static int pkcs7_get_signers_info_set( unsigned char **p, unsigned char *end,
                                       mbedtls_pkcs7_signer_info **signers_set )
{
    unsigned char *end_set;
    int ret;
    size_t len = 0;
    mbedtls_pkcs7_signer_info *signer, *signer_prv;

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
            | MBEDTLS_ASN1_SET );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    end_set = *p + len;

    if( len == 0 )
    {
        /* There are no signerInfos, bail out now. */
        return( 0 );
    }

    /* parse the first one */
    signer = mbedtls_calloc( 1, sizeof( mbedtls_pkcs7_signer_info ) );
    if (signer == NULL)
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

    *signers_set = signer;

    ret = pkcs7_get_signer_info( p, end_set, signer );
    if( ret != 0 )
        goto cleanup;

    /* parse any subsequent ones */
    signer_prv = signer;
    while( *p != end_set )
    {
        signer = mbedtls_calloc( 1, sizeof( mbedtls_pkcs7_signer_info ) );
        if (signer == NULL)
        {
            ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
            goto cleanup;
        }

        ret = pkcs7_get_signer_info( p, end_set, signer );
        if( ret != 0 )
        {
            mbedtls_free( signer );
            goto cleanup;
        }

        signer_prv->next = signer;
        signer_prv = signer;
    }

    return( 0 );

cleanup:
    signer = *signers_set;
    while( signer )
    {
        signer_prv = signer;
        signer = signer->next;
        pkcs7_free_signer_info( signer_prv );
        mbedtls_free( signer_prv );
    }
    return( ret );
}

/**
 * SignedData ::= SEQUENCE {
 *      version Version,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      contentInfo ContentInfo,
 *      certificates
 *              [0] IMPLICIT ExtendedCertificatesAndCertificates
 *                  OPTIONAL,
 *      crls
 *              [0] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos SignerInfos }
 */
static int pkcs7_get_signed_data( unsigned char *buf, size_t buflen,
        mbedtls_pkcs7_signed_data *signed_data )
{
    unsigned char *p = buf;
    unsigned char *end = buf + buflen;
    size_t len = 0;
    int ret;
    mbedtls_md_type_t md_alg;

    ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
            | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

    /* Get version of signed data */
    ret = pkcs7_get_version( &p, end, &signed_data->version );
    if( ret != 0 )
        return( ret );

    /* If version != 1, return invalid version */
    if( signed_data->version != MBEDTLS_PKCS7_SUPPORTED_VERSION ) {
        return( MBEDTLS_ERR_PKCS7_INVALID_VERSION );
    }

    /* Get digest algorithm */
    ret = pkcs7_get_digest_algorithm_set( &p, end,
            &signed_data->digest_alg_identifiers );
    if( ret != 0 ) {
        return( ret );
    }

    ret = mbedtls_oid_get_md_alg( &signed_data->digest_alg_identifiers, &md_alg );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    /* Do not expect any content */
    ret = pkcs7_get_content_info_type( &p, end, &signed_data->content.oid );
    if( ret != 0 )
        return( ret );

    if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_DATA, &signed_data->content.oid ) ) {
        return( MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO ) ;
    }

    p = p + signed_data->content.oid.len;

    /* Look for certificates, there may or may not be any */
    ret = pkcs7_get_next_content_len( &p, end, &len );
    if( ret == 0 ) {
        mbedtls_x509_crt_init( &signed_data->certs );
        ret = pkcs7_get_certificates( &p, len, &signed_data->certs );
        if( ret != 0 )
            return( ret ) ;

      p = p + len;
    }

    /* TODO: optional CRLs go here */

    /* Get signers info */
    ret = pkcs7_get_signers_info_set( &p, end, &signed_data->signers );
    if( ret != 0 )
        return( ret );

    return( ret );
}

int mbedtls_pkcs7_parse_der( const unsigned char *buf, const int buflen,
        mbedtls_pkcs7 *pkcs7 )
{
    unsigned char *start;
    unsigned char *end;
    size_t len = 0;
    int ret;

    /* use internal buffer for parsing */
    start = ( unsigned char * )buf;
    end = start + buflen;

    if(!pkcs7)
        return( MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA );

    ret = pkcs7_get_content_info_type( &start, end, &pkcs7->content_type_oid );
    if( ret != 0 )
        goto try_data;

    if( ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_ENCRYPTED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_ENVELOPED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_DIGESTED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_ENCRYPTED_DATA, &pkcs7->content_type_oid ) )
    {
        ret =  MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
        goto out;
    }

    if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_SIGNED_DATA, &pkcs7->content_type_oid ) )
    {
        ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        goto out;
    }

    start = start + pkcs7->content_type_oid.len;

try_data:


    ret = pkcs7_get_next_content_len( &start, end, &len );
    if( ret != 0 )
        goto out;

    ret = pkcs7_get_signed_data( start, len, &pkcs7->signed_data );
    if (ret != 0)
        goto out;

    pkcs7->content_type_oid.tag = MBEDTLS_ASN1_OID;
    pkcs7->content_type_oid.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS7_SIGNED_DATA);
    pkcs7->content_type_oid.p = (unsigned char *)MBEDTLS_OID_PKCS7_SIGNED_DATA;

    ret = MBEDTLS_PKCS7_SIGNED_DATA;

out:
    return( ret );
}

int mbedtls_pkcs7_signed_data_verify( mbedtls_pkcs7 *pkcs7,
                                      mbedtls_x509_crt *cert,
                                      const unsigned char *data,
                                      size_t datalen )
{

    int ret;
    unsigned char *hash;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_type_t md_alg;

    ret = mbedtls_oid_get_md_alg( &pkcs7->signed_data.digest_alg_identifiers, &md_alg );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    md_info = mbedtls_md_info_from_type( md_alg );

    hash = mbedtls_calloc( mbedtls_md_get_size( md_info ), 1 );
    if( hash == NULL ) {
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );
    }

    mbedtls_md( md_info, data, datalen, hash );

    ret = mbedtls_pkcs7_signed_hash_verify( pkcs7, cert,
                                            hash, sizeof( hash ) );

    mbedtls_free( hash );

    return( ret );
}

int mbedtls_pkcs7_signed_hash_verify( mbedtls_pkcs7 *pkcs7,
                                      mbedtls_x509_crt *cert,
                                      const unsigned char *hash, int hashlen)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_pk_context pk_cxt;
    mbedtls_pkcs7_signer_info *signer;

    ret = mbedtls_oid_get_md_alg( &pkcs7->signed_data.digest_alg_identifiers, &md_alg );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    pk_cxt = cert->pk;

    /*
     * Potential TODO
     * Currently we iterate over all signers and return success if any of them
     * verify.
     *
     * However, we could make this better by checking against the certificate's
     * identification and SignerIdentifier fields first. That would also allow
     * us to distinguish between 'no signature for key' and 'signature for key
     * failed to validate'.
     */

    signer = pkcs7->signed_data.signers;
    while( signer != NULL )
    {
        ret = mbedtls_pk_verify( &pk_cxt, md_alg, hash, hashlen,
                                 signer->sig.p,
                                 signer->sig.len );
        if( ret == 0 )
            return( ret );
        signer = signer->next;
    }
    return ( ret );
}

/*
 * Deallocate the contents of a pkcs7 signer_info
 */
static void pkcs7_free_signer_info( mbedtls_pkcs7_signer_info *si )
{
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;

    name_cur = si->issuer.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_free( name_prv );
    }
}

/*
 * Unallocate all pkcs7 data
 */
void mbedtls_pkcs7_free( mbedtls_pkcs7 *pkcs7 )
{
    mbedtls_pkcs7_signer_info *si_cur;
    mbedtls_pkcs7_signer_info *si_prv;

    if( pkcs7 == NULL )
        return;

    mbedtls_x509_crt_free( &pkcs7->signed_data.certs );
    mbedtls_x509_crl_free( &pkcs7->signed_data.crl );

    si_cur = pkcs7->signed_data.signers;
    while( si_cur != NULL )
    {
        si_prv = si_cur;
        si_cur = si_cur->next;
        pkcs7_free_signer_info( si_prv );
        mbedtls_free( si_prv );
    }
}