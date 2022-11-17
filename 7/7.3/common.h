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

void print_errors(void);
void printKeys (EVP_PKEY *pkey);

int getCharKeys (EVP_PKEY *pkey, unsigned char **pubkey, int *publen, unsigned char **privkey, int *privlen);
int setCharKeys (EVP_PKEY **pkey, unsigned char *pubkey, int publen, unsigned char *privkey, int privlen);

int ecdsaSign (unsigned char *privkey, int privlen, char *VerifyFile,
        const EVP_MD *mdName, unsigned char **out, size_t *outLen);
int ecdsaVerify (unsigned char *pubkey, int publen, char *VerifyFile,
        const EVP_MD *mdName, unsigned char *sig, size_t sigLen);
