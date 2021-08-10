// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifdef MBEDTLS_V3
// ^extra precaution to not compile with mbedtls version 3.x unless specified
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // for exit
#include "crypto.h"
#include "include/prlog.h"
#include "include/err.h"

#include <mbedtls/pk_internal.h> // for validating cert pk data
#include <mbedtls/error.h>
#include "external/extraMbedtls/v3.x/include/pkcs7.h"
#include "external/extraMbedtls/v3.x/include/generate-pkcs7.h"
#include <mbedtls/platform.h>
#include "generic.h"

crypto_pkcs7 *crypto_pkcs7_parse_der(const unsigned char *buf, const int buflen)
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
		rc = SUCCESS;

	if (rc) {
		mbedtls_pkcs7_free(pkcs7);
		free(pkcs7);
		return NULL;
	} else
		return pkcs7;
}

int crypto_pkcs7_md_is_sha256(crypto_pkcs7 *pkcs7)
{
	return MBEDTLS_OID_CMP(MBEDTLS_OID_DIGEST_ALG_SHA256,
			       &((struct mbedtls_pkcs7 *)pkcs7)
					->signed_data.digest_alg_identifiers);
}

void crypto_pkcs7_free(crypto_pkcs7 *pkcs7)
{
	mbedtls_pkcs7_free((struct mbedtls_pkcs7 *)pkcs7);
	free(pkcs7);
}

crypto_x509 *crypto_pkcs7_get_signing_cert(crypto_pkcs7 *pkcs7, int cert_num)
{
	mbedtls_x509_crt *pkcs7_cert = NULL;

	pkcs7_cert = &pkcs7->signed_data.certs;
	for (int i = 0; i < cert_num && pkcs7_cert != NULL; i++)
		pkcs7_cert = pkcs7_cert->next;

	return pkcs7_cert;
}

int crypto_pkcs7_signed_hash_verify(crypto_pkcs7 *pkcs7, crypto_x509 *x509,
				    unsigned char *hash, int hash_len)
{
	return mbedtls_pkcs7_signed_hash_verify(pkcs7, x509, hash, hash_len);
}

/*
 * As of mbedtls v3.0.0 most functions involving a pk need a random
 * number generator function as a parameter. Thus pkcs7 generation
 * will also need a rng. We will just use this makeshift random generator for now
 */
static int rando(void *data, unsigned char *output, size_t len)
{
	for (size_t i =0; i < len; i++)
		output[i] = rand() % 256;
	return 0;
}
int crypto_pkcs7_generate_w_signature(unsigned char **pkcs7, size_t *pkcs7Size,
				      const unsigned char *newData,
				      size_t newDataSize, const char **crtFiles,
				      const char **keyFiles, int keyPairs,
				      int hashFunct)
{
	return to_pkcs7_generate_signature(pkcs7, pkcs7Size, newData,
					   newDataSize, crtFiles, keyFiles,
					   keyPairs, hashFunct, &rando , NULL);
}

int crypto_pkcs7_generate_w_already_signed_data(
	unsigned char **pkcs7, size_t *pkcs7Size, const unsigned char *newData,
	size_t newDataSize, const char **crtFiles, const char **sigFiles,
	int keyPairs, int hashFunct)
{
	return to_pkcs7_already_signed_data(pkcs7, pkcs7Size, newData,
					    newDataSize, crtFiles, sigFiles,
					    keyPairs, hashFunct, &rando , NULL);
}

int crypto_x509_get_der_len(crypto_x509 *x509)
{
	return x509->raw.len;
}

int crypto_x509_get_tbs_der_len(crypto_x509 *x509)
{
	return x509->tbs.len;
}

int crypto_x509_get_version(crypto_x509 *x509)
{
	return x509->version;
}

int crypto_x509_is_RSA(crypto_x509 *x509)
{
	int pk_type;
	pk_type = x509->pk.pk_info->type;
	if (pk_type != MBEDTLS_PK_RSA)
		//zero is also a pk type (MBEDTLS_PK_NONE) so return generic failure if zero so it doesnt look like a success
		return (pk_type == 0 ? CERT_FAIL : pk_type);
	else
		return SUCCESS;
}

int crypto_x509_get_sig_len(crypto_x509 *x509)
{
	return x509->sig.len;
}

int crypto_x509_md_is_sha256(crypto_x509 *x509)
{
	if (x509->sig_md == MBEDTLS_MD_SHA256)
		return SUCCESS;
	else
		return CERT_FAIL;
}

int crypto_x509_oid_is_pkcs1_sha256(crypto_x509 *x509)
{
	if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS1_SHA256, &x509->sig_oid))
		return CERT_FAIL;
	return SUCCESS;
}

int crypto_x509_get_pk_bit_len(crypto_x509 *x509)
{
	return mbedtls_pk_get_bitlen(&x509->pk);
}

void crypto_x509_get_short_info(crypto_x509 *x509, char *short_desc,
				size_t max_len)
{
	mbedtls_x509_sig_alg_gets(short_desc, max_len, &x509->sig_oid,
				  x509->sig_pk, x509->sig_md, x509->sig_opts);
}

int crypto_x509_get_long_desc(char *x509_info, size_t max_len, char *delim,
			      crypto_x509 *x509)
{
	return mbedtls_x509_crt_info(x509_info, max_len, delim, x509);
}

crypto_x509 *crypto_x509_parse_der(const unsigned char *data, size_t data_len)
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

void crypto_x509_free(crypto_x509 *x509)
{
	mbedtls_x509_crt_free(x509);
	free(x509);
}

int crypto_convert_pem_to_der(const unsigned char *input, size_t ilen,
			      unsigned char **output, size_t *olen)
{
	return convert_pem_to_der(input, ilen, output, olen);
}

void crypto_strerror(int rc, char *out_str, size_t out_max_len)
{
	mbedtls_strerror(rc, out_str, out_max_len);
}

int crypto_md_ctx_init(crypto_md_ctx **ctx, int md_id)
{
	int rc;
	const mbedtls_md_info_t *md_info;
	*ctx = malloc(sizeof(mbedtls_md_context_t));
	if (!*ctx) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	md_info = mbedtls_md_info_from_type(md_id);
	mbedtls_md_init(*ctx);
	rc = mbedtls_md_setup(*ctx, md_info, 0);
	if (rc)
		return HASH_FAIL;
	return mbedtls_md_starts(*ctx);
}

int crypto_md_update(crypto_md_ctx *ctx, const unsigned char *data,
		     size_t data_len)
{
	return mbedtls_md_update((mbedtls_md_context_t *)ctx, data, data_len);
}

int crypto_md_finish(crypto_md_ctx *ctx, unsigned char *hash)
{
	return mbedtls_md_finish(ctx, hash);
}

void crypto_md_free(crypto_md_ctx *ctx)
{
	mbedtls_md_free(ctx);
	if (ctx)
		free(ctx);
}

int crypto_md_generate_hash(const unsigned char *data, size_t size,
			    int hashFunct, unsigned char **outHash,
			    size_t *outHashSize)
{
	//calls function in generate-pkcs7 (mbedtls specific)
	return toHash(data, size, hashFunct, outHash, outHashSize);
}

#endif