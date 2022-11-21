#include "common.h"

// extract public, private key from 'pkey'
// save these to paramters
int getCharKeys (EVP_PKEY *pkey, unsigned char **pubKey, int *pubLen,
	                    unsigned char **privKey, int *privLen)
{
	unsigned char *ucptr;

	assert ((*privLen=i2d_PrivateKey(pkey, 0)) > 0);
    ucptr = *privKey = OPENSSL_malloc (*privLen);
    assert (i2d_PrivateKey(pkey, &ucptr) > 0);

	assert ((*pubLen=i2d_PublicKey(pkey, 0)) > 0);
	ucptr = *pubKey = OPENSSL_malloc (*pubLen);
	assert (i2d_PublicKey(pkey, &ucptr) > 0);
}

// set private/public key of 'pkey'
// 		set only private key, if pubKey null
// 		set only public key, if privKey null
int setCharKeys (EVP_PKEY **pkey, unsigned char *pubKey, int pubLen,
	                    unsigned char *privKey, int privLen)
{
	const unsigned char *ucptr;
	const char p256params[]={0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};

	if (privKey != 0) {
		ucptr = privKey;
		assert (d2i_PrivateKey(EVP_PKEY_EC, pkey, &ucptr, privLen) != 0);
	}

	if (pubKey != 0) {
		// set oid for pkey
		ucptr = p256params;
		d2i_KeyParams(EVP_PKEY_EC, pkey, &ucptr, sizeof(p256params));

		ucptr = pubKey;
		assert (d2i_PublicKey(EVP_PKEY_EC, pkey, &ucptr, pubLen));
	}
}
