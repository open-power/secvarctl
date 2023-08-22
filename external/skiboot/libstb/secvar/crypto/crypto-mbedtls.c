// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2021 IBM Corp.*/
#ifdef SECVAR_CRYPTO_MBEDTLS
// ^extra precaution to not compile with mbedtls unless specified
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // for exit
#include "crypto.h"
// commented out by Nick Child
// #include <skiboot.h> // for prlog

// added by Nick Child
#include "prlog.h"
// commented out by Nick Child
//#include "secvar_crypto_err.h" // for err codes
// added by Nick Child

#include <mbedtls/pk_internal.h> // for validating cert pk data
#include <mbedtls/error.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/oid.h>
// Nick Child edited paths below
// #include "libstb/crypto/pkcs7/pkcs7.h"
// #ifdef SECVAR_CRYPTO_WRITE_FUNC
// #include "libstb/crypto/pkcs7/pkcs7_write.h"
// #endif
#include "external/extraMbedtls/include/pkcs7.h"
#ifdef SECVAR_CRYPTO_WRITE_FUNC
#include "external/extraMbedtls/include/pkcs7_write.h"
#endif
#include <mbedtls/platform.h>

crypto_pkcs7_t *crypto_pkcs7_parse_der(const unsigned char *buf, const int buflen)
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
	if (rc !=
	    MBEDTLS_PKCS7_SIGNED_DATA) // if pkcs7 parsing fails, then try new signed data format
		prlog(PR_ERR,
		      "ERROR: parsing pkcs7 failed mbedtls error #%04x\n", rc);
	else
		rc = MBEDTLS_SUCCESS;

	if (rc) {
		mbedtls_pkcs7_free(pkcs7);
		free(pkcs7);
		return NULL;
	} else
		return pkcs7;
}

int crypto_pkcs7_md_is_sha256(crypto_pkcs7_t *pkcs7)
{
	return MBEDTLS_OID_CMP(MBEDTLS_OID_DIGEST_ALG_SHA256,
			       &((struct mbedtls_pkcs7 *)pkcs7)
					->signed_data.digest_alg_identifiers);
}

void crypto_pkcs7_free(crypto_pkcs7_t *pkcs7)
{
	mbedtls_pkcs7_free((struct mbedtls_pkcs7 *)pkcs7);
	free(pkcs7);
}

crypto_x509_t *crypto_pkcs7_get_signing_cert(crypto_pkcs7_t *pkcs7, int cert_num)
{
	mbedtls_x509_crt *pkcs7_cert = NULL;

	pkcs7_cert = &pkcs7->signed_data.certs;
	for (int i = 0; i < cert_num && pkcs7_cert != NULL; i++)
		pkcs7_cert = pkcs7_cert->next;

	return pkcs7_cert;
}

int crypto_pkcs7_signed_hash_verify(crypto_pkcs7_t *pkcs7, crypto_x509_t *x509,
				    unsigned char *hash, int hash_len)
{
	return mbedtls_pkcs7_signed_hash_verify(pkcs7, x509, hash, hash_len);
}

#ifdef SECVAR_CRYPTO_WRITE_FUNC
int crypto_pkcs7_generate_w_signature(unsigned char **pkcs7, size_t *pkcs7Size,
				      const unsigned char *newData,
				      size_t newDataSize, const char **crtFiles,
				      const char **keyFiles, int keyPairs,
				      int hashFunct)
{
	unsigned char *crtPEM = NULL,**crts = NULL, *keyPEM = NULL, **keys = NULL;
	size_t *keySizes = NULL, crtSizePEM, *crtSizes = NULL;
	int rc;
	// if no keys given
	if (keyPairs == 0) {
		prlog(PR_ERR, "ERROR: missing private key / certificate... use -k <privateKeyFile> -c <certificateFile>\n");
		rc = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
		goto out;
	}
	keys = calloc(1, sizeof(unsigned char*) * keyPairs);
	keySizes = calloc(1, sizeof(size_t) * keyPairs);
	if (!keys || !keySizes) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
		goto out;	
	}
	crts = calloc (1, sizeof(unsigned char*) * keyPairs);
	crtSizes = calloc(1, sizeof(size_t) * keyPairs);
	if (!crts || !crtSizes) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
		goto out;
	}
	for (int i = 0; i < keyPairs; i++) {
		// get data of private keys
		rc = mbedtls_pk_load_file(keyFiles[i], &keys[i], &keySizes[i]);
		if (rc) {
			prlog(PR_ERR, "ERROR: failed to get data from priv key file %s\n", keyFiles[i]);
			goto out;
		}
		if (keyPEM) free(keyPEM);
		keyPEM = NULL;
		// get data from x509
		// this function just gets data from file, its not PKCS7 specific
		rc = mbedtls_pkcs7_load_file(crtFiles[i], &crtPEM, &crtSizePEM);
		if (rc) {
			prlog(PR_ERR, "ERROR: failed to get data from x509 file %s\n", crtFiles[i]);
			goto out;
		}
		// get der format of that crt
		rc = mbedtls_convert_pem_to_der(crtPEM, crtSizePEM, (unsigned char **) &crts[i], &crtSizes[i]);
		if (rc) {
			prlog(PR_ERR, "Conversion for %s from PEM to DER failed\n", crtFiles[i]);
		 	goto out;
		}
		if (crtPEM) free(crtPEM);
		crtPEM = NULL;
	}
	rc = mbedtls_pkcs7_create(pkcs7, pkcs7Size, newData,
					    newDataSize, (const unsigned char **)crts, (const unsigned char **)keys, crtSizes, keySizes,
					    keyPairs, hashFunct, 0);
out:
	if (crtPEM) free(crtPEM);
	if (keyPEM) free(keyPEM);
	for (int i = 0; i < keyPairs; i++) {
		if (keys[i]) free(keys[i]);
		if (crts[i]) free(crts[i]);
	}
	if (keys) free (keys);
	if (crts) free(crts);
	if (keySizes) free(keySizes);
	if (crtSizes) free(crtSizes);
	return rc;
}

int crypto_pkcs7_generate_w_already_signed_data(
	unsigned char **pkcs7, size_t *pkcs7Size, const unsigned char *newData,
	size_t newDataSize, const char **crtFiles, const char **sigFiles,
	int keyPairs, int hashFunct)
{
	unsigned char *crtPEM = NULL,**crts = NULL, **sigs = NULL;
	size_t  *sigSizes = NULL, crtSizePEM,*crtSizes = NULL;
	int rc;
	// if no keys given
	if (keyPairs == 0) {
		prlog(PR_ERR, "ERROR: missing signature / certificate pairs... use -s <signedDataFile> -c <certificateFile>\n");
		rc = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
		goto out;
	}
	sigs = calloc(1, sizeof(unsigned char*) * keyPairs);
	sigSizes = calloc(1, sizeof(size_t) * keyPairs);
	if (!sigs || !sigSizes) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
		goto out;	
	}
	crts = calloc (1, sizeof(unsigned char*) * keyPairs);
	crtSizes = calloc(1, sizeof(size_t) * keyPairs);
	if (!crts || !crtSizes) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		rc = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
		goto out;
	}
	for (int i = 0; i < keyPairs; i++) {
		// get data from signature files
		// this function just gets data from file, its not PKCS7 specifc
		rc = mbedtls_pkcs7_load_file(sigFiles[i], &sigs[i], &sigSizes[i]);
		if (!sigs[i]) {
			prlog(PR_ERR, "ERROR: failed to get data from signature file %s\n", sigFiles[i]);
			goto out;
		}
		// get data from x509
		// this function just gets data from file, its not PKCS7 specific
		rc = mbedtls_pkcs7_load_file(crtFiles[i], &crtPEM, &crtSizePEM);
		if (rc) {
			prlog(PR_ERR, "ERROR: failed to get data from x509 file %s\n", crtFiles[i]);
			goto out;
		}
		// get der format of that crt
		rc = mbedtls_convert_pem_to_der(crtPEM, crtSizePEM, (unsigned char **) &crts[i], &crtSizes[i]);
		if (rc) {
			prlog(PR_ERR, "Conversion for %s from PEM to DER failed\n", crtFiles[i]);
		 	goto out;
		}
		if (crtPEM) free(crtPEM);
		crtPEM = NULL;
	}

	rc =  mbedtls_pkcs7_create(pkcs7, pkcs7Size, newData,
					    newDataSize, (const unsigned char **)crts, (const unsigned char **)sigs, crtSizes, sigSizes,
					    keyPairs, hashFunct, 1);
out:
	if (crtPEM) free(crtPEM);
	for (int i = 0; i < keyPairs; i++) {
		if (sigs[i]) free(sigs[i]);
		if (crts[i]) free(crts[i]);
	}
	if (sigs) free (sigs);
	if (crts) free(crts);
	if (sigSizes) free(sigSizes);
	if (crtSizes) free(crtSizes);
	return rc;
}

int crypto_convert_pem_to_der(const unsigned char *input, size_t ilen,
			      unsigned char **output, size_t *olen)
{
	return mbedtls_convert_pem_to_der(input, ilen, output, olen);
}
#endif
int crypto_x509_get_der_len(crypto_x509_t *x509)
{
	return x509->raw.len;
}

int crypto_x509_get_tbs_der_len(crypto_x509_t *x509)
{
	return x509->tbs.len;
}

int crypto_x509_get_version(crypto_x509_t *x509)
{
	return x509->version;
}

int crypto_x509_is_RSA(crypto_x509_t *x509)
{
	int pk_type;
	pk_type = x509->pk.pk_info->type;
	if (pk_type != MBEDTLS_PK_RSA)
		//zero is also a pk type (MBEDTLS_PK_NONE) so return generic failure if zero so it doesnt look like a success
		return (pk_type == 0 ? MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG : pk_type);
	else
		return MBEDTLS_SUCCESS;
}

int crypto_x509_get_sig_len(crypto_x509_t *x509)
{
	return x509->sig.len;
}

int crypto_x509_md_is_sha256(crypto_x509_t *x509)
{
	if (x509->sig_md == MBEDTLS_MD_SHA256)
		return MBEDTLS_SUCCESS;
	else
		return MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG;
}

int crypto_x509_oid_is_pkcs1_sha256(crypto_x509_t *x509)
{
	if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS1_SHA256, &x509->sig_oid))
		return MBEDTLS_ERR_X509_UNKNOWN_OID;
	return MBEDTLS_SUCCESS;
}

int crypto_x509_get_pk_bit_len(crypto_x509_t *x509)
{
	return mbedtls_pk_get_bitlen(&x509->pk);
}

void crypto_x509_get_short_info(crypto_x509_t *x509, char *short_desc,
				size_t max_len)
{
	mbedtls_x509_sig_alg_gets(short_desc, max_len, &x509->sig_oid,
				  x509->sig_pk, x509->sig_md, x509->sig_opts);
}

int crypto_x509_get_long_desc(char *x509_info, size_t max_len, const char *delim,
			      crypto_x509_t *x509)
{
	return mbedtls_x509_crt_info(x509_info, max_len, delim, x509);
}

crypto_x509_t *crypto_x509_parse_der(const unsigned char *data, size_t data_len)
{
	int rc;
	mbedtls_x509_crt *x509 = NULL;
	x509 = malloc(sizeof(*x509));
	if (!x509) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return NULL;
	}
	mbedtls_x509_crt_init(x509);
	rc = mbedtls_x509_crt_parse(x509, data, data_len);

	if (rc) {
		crypto_x509_free(x509);
		return NULL;
	} else
		return x509;
}

void crypto_x509_free(crypto_x509_t *x509)
{
	mbedtls_x509_crt_free(x509);
	free(x509);
}

void crypto_strerror(int rc, char *out_str, size_t out_max_len)
{
	mbedtls_strerror(rc, out_str, out_max_len);
}

int crypto_md_ctx_init(crypto_md_ctx_t **ctx, int md_id)
{
	int rc;
	const mbedtls_md_info_t *md_info;
	*ctx = malloc(sizeof(mbedtls_md_context_t));
	if (!*ctx) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return MBEDTLS_ERR_MD_ALLOC_FAILED;
	}
	md_info = mbedtls_md_info_from_type(md_id);
	mbedtls_md_init(*ctx);
	rc = mbedtls_md_setup(*ctx, md_info, 0);
	if (rc)
		return rc;
	return mbedtls_md_starts(*ctx);
}

int crypto_md_update(crypto_md_ctx_t *ctx, const unsigned char *data,
		     size_t data_len)
{
	return mbedtls_md_update((mbedtls_md_context_t *)ctx, data, data_len);
}

int crypto_md_finish(crypto_md_ctx_t *ctx, unsigned char *hash)
{
	return mbedtls_md_finish(ctx, hash);
}

void crypto_md_free(crypto_md_ctx_t *ctx)
{
	mbedtls_md_free(ctx);
	if (ctx)
		free(ctx);
}

int crypto_md_generate_hash(const unsigned char *data, size_t size,
			    int hashFunct, unsigned char **outHash,
			    size_t *outHashSize)
{
	const mbedtls_md_info_t *md_info;
    int rc;
    size_t i;

    md_info = mbedtls_md_info_from_type( hashFunct );
    if( md_info == NULL ) {
        prlog(PR_ERR,  "ERROR: Invalid hash function %u, see mbedtls_md_type_t\n",
                        hashFunct );
        rc = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
        goto out;
    }
    *outHash = calloc( 1, md_info->size );
    if( *outHash == NULL ) {
        rc = MBEDTLS_ERR_MD_ALLOC_FAILED;
        goto out;
    }
    rc = mbedtls_md( md_info, data, size, *outHash );
    if( rc ) {
        mbedtls_free( *outHash );
        *outHash = NULL;
        goto out;
    }

    *outHashSize = md_info->size;
    mbedtls_printf( "Hash generation successful, %s: ", md_info->name );
    for (i = 0; i < *outHashSize - 1; i++)
        mbedtls_printf("%02x:", (*outHash)[i]);
    mbedtls_printf("%02x\n", (*outHash)[i]);

out:
    return ( rc );
}

#endif
