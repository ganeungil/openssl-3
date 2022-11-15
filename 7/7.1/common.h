// common.h
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

void print_errors(void);
int genKey(EVP_PKEY **ppkey);
int expubkey (EVP_PKEY *pkey, unsigned char **out, uint *outlen);
