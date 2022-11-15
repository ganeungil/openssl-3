#include <assert.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
void print_errors(void);
int genKey(EVP_PKEY ** ppkey);
int computeDH(EVP_PKEY * myPrivKey, EVP_PKEY * peerPubKey, unsigned char **out, size_t * outlen);
EVP_PKEY *getPubKey(EVP_PKEY * pkey);
