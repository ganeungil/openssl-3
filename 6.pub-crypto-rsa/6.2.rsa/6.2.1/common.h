#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

int genKey(EVP_PKEY **pkey);
EVP_PKEY *getPubKey(EVP_PKEY *pkey);
int rsaEncrypt (EVP_PKEY *pkey, unsigned char *in, size_t inLen, unsigned char **out, size_t *outLen);
int rsaDecrypt (EVP_PKEY *pkey, unsigned char *ct, size_t ctLen, unsigned char **pt, size_t *ptLen);
