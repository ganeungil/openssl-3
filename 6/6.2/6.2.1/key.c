#include "common.h"

// generate EC key, save to pkey
int genKey(EVP_PKEY **pkey)
{
	EVP_PKEY_CTX *ctx;

	// create ctx
	assert((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)));
	assert(EVP_PKEY_keygen_init(ctx));

	// set RSA key length
	assert (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) != 0);

	// generate key pair
	assert(EVP_PKEY_keygen(ctx, pkey));

	EVP_PKEY_CTX_free(ctx);
}

// get public key from pkey
// return EVP_PKEY (contains only public key)
EVP_PKEY *getPubKey(EVP_PKEY *pkey)
{
	int len;

	BIO *bp = BIO_new(BIO_s_mem());
	EVP_PKEY *pubkey = 0;

	assert(i2d_PUBKEY_bio(bp, pkey));
	assert(d2i_PUBKEY_bio(bp, &pubkey));
	BIO_free(bp);

	return (pubkey);
}
