#ifndef GENERATE_PKCS7_H
#define GENERATE_PKCS7_H
#include "pkcs7.h"
int toPKCS7(unsigned char **pkcs7, size_t *pkcs7Size, const char *newData, size_t newDataSize, const char** crtFiles, const char** keyFiles, int keyPairs, int hashFunct );
int convert_pem_to_der( const unsigned char *input, size_t ilen, unsigned char **output, size_t *olen );
int toHash(const char* data, size_t size, int hashFunct, char** outHash, size_t* outHashSize);
#endif
