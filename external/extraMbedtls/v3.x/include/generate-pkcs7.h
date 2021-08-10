#ifndef GENERATE_PKCS7_H
#define GENERATE_PKCS7_H
#include "pkcs7.h"
int to_pkcs7_already_signed_data(unsigned char **pkcs7, size_t *pkcs7Size, const unsigned char *newData, size_t newDataSize, 
    const char** crtFiles, const char** sigFiles,  int keyPairs, int hashFunct, int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng);
int to_pkcs7_generate_signature(unsigned char **pkcs7, size_t *pkcs7Size, const unsigned char *newData, size_t newDataSize, 
    const char** crtFiles, const char** keyFiles,  int keyPairs, int hashFunct, int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng);
int convert_pem_to_der( const unsigned char *input, size_t ilen, unsigned char **output, size_t *olen);
int toHash(const unsigned char* data, size_t size, int hashFunct, unsigned char** outHash, size_t* outHashSize);
#endif
