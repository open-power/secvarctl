// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef EDK2_SVC_SKIBOOT_H
#define EDK2_SVC_SKIBOOT_H

#include <stdint.h> // for uint_16 stuff like that
#include "external/skiboot/libstb/secvar/secvar.h" // for secvar struct
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "libstb/secvar/crypto/crypto.h"
#include "external/skiboot/libstb/secvar/backend/edk2.h" // include last or else problems from pragma pack(1)

// all argp options must have a single character option
// so we set --usage to have a single character option that is out of range
#define ARGP_OPT_USAGE_KEY 0x100
#define CERT_BUFFER_SIZE 2048

#ifndef SECVARPATH
#define SECVARPATH "/sys/firmware/secvar/vars/"
#endif

#define variables                                                                                  \
	(char *[])                                                                                 \
	{                                                                                          \
		"PK", "KEK", "db", "dbx", "TS"                                                     \
	}
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define uuid_equals(a, b) (!memcmp(a, b, UUID_SIZE))

// array holding different hash function information
static const struct hash_funct {
	char name[8];
	size_t size;
	int crypto_md_funct;
	uuid_t const *guid;
} hash_functions[] = {
	{ .name = "SHA1",
	  .size = 20,
	  .crypto_md_funct = CRYPTO_MD_SHA1,
	  .guid = &EFI_CERT_SHA1_GUID },
	{ .name = "SHA224",
	  .size = 28,
	  .crypto_md_funct = CRYPTO_MD_SHA224,
	  .guid = &EFI_CERT_SHA224_GUID },
	{ .name = "SHA256",
	  .size = 32,
	  .crypto_md_funct = CRYPTO_MD_SHA256,
	  .guid = &EFI_CERT_SHA256_GUID },
	{ .name = "SHA384",
	  .size = 48,
	  .crypto_md_funct = CRYPTO_MD_SHA384,
	  .guid = &EFI_CERT_SHA384_GUID },
	{ .name = "SHA512",
	  .size = 64,
	  .crypto_md_funct = CRYPTO_MD_SHA512,
	  .guid = &EFI_CERT_SHA512_GUID },
};

int performReadCommand(int argc, char *argv[]);
int performVerificationCommand(int argc, char *argv[]);
int performWriteCommand(int argc, char *argv[]);
int performValidation(int argc, char *argv[]);
int performGenerateCommand(int argc, char *argv[]);

int printCertInfo(crypto_x509 *x509);
void printESLInfo(EFI_SIGNATURE_LIST *sigList);
void printTimestamp(struct efi_time t);
void printGuidSig(const void *sig);

EFI_SIGNATURE_LIST *get_esl_signature_list(const char *buf, size_t buflen);
ssize_t get_esl_cert(const char *c, EFI_SIGNATURE_LIST *list, char **cert);
size_t get_pkcs7_len(const struct efi_variable_authentication_2 *auth);
int parseX509(crypto_x509 **x509, const unsigned char *certBuf, size_t buflen);
const char *getSigType(const uuid_t);

int getSecVar(struct secvar **var, const char *name, const char *fullPath);
int updateVar(const char *path, const char *var, const unsigned char *buff, size_t size);
int isVariable(const char *var);

int validateAuth(const unsigned char *authBuf, size_t buflen, const char *key);
int validateESL(const unsigned char *eslBuf, size_t buflen, const char *key);
int validateCert(const unsigned char *authBuf, size_t buflen, const char *varName);
int validatePKCS7(const unsigned char *cert_data, size_t len);
int validateTS(const unsigned char *data, size_t size);
int validateTime(struct efi_time *time);

extern struct command edk2_compat_command_table[5];
#endif
