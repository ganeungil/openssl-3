#include "common.h"

// extract public, private key from EVP_PKEY
// save these to paramters
int getCharKeys (EVP_PKEY *pkey, unsigned char **pubkey, int *publen,
	                    unsigned char **privkey, int *privlen)
{
	unsigned char *ucptr;

	assert ((*privlen=i2d_PrivateKey(pkey, 0)) > 0);
    ucptr = *privkey = malloc (*privlen);
    assert (i2d_PrivateKey(pkey, &ucptr) > 0);

	assert ((*publen=i2d_PublicKey(pkey, 0)) > 0);
	ucptr = *pubkey = malloc (*publen);
	assert (i2d_PublicKey(pkey, &ucptr) > 0);
}

// set pkey's private/public key.
// 		set only private key, if pubkey null
// 		set only public key, if privkey null
int setCharKeys (EVP_PKEY **pkey, unsigned char *pubkey, int publen,
	                    unsigned char *privkey, int privlen)
{
	const unsigned char *ucptr;
	const char p256params[]={0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};

	if (privkey != 0) {
		ucptr = privkey;
		assert (d2i_PrivateKey(EVP_PKEY_RSA, pkey, &ucptr, privlen) != 0);
	}

	if (pubkey != 0) {
		// set oid for pkey
		ucptr = p256params;
		d2i_KeyParams(EVP_PKEY_RSA, pkey, &ucptr, sizeof(p256params));

		ucptr = pubkey;
		assert (d2i_PublicKey(EVP_PKEY_RSA, pkey, &ucptr, publen));
	}
}

// generate RSA key, save to pkey
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
