#include <assert.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

int genKey(EVP_PKEY **pkey);
int pubKeyTest (EVP_PKEY *key);
int privKeyTest (EVP_PKEY *key);
