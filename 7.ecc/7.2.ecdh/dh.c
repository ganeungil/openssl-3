#include "common.h"
int computeDH(EVP_PKEY *myPrivKey, EVP_PKEY *peerPubKey, unsigned char **out, size_t *outlen)
{
	EVP_PKEY_CTX *pkeyctx;

	assert((pkeyctx = EVP_PKEY_CTX_new(myPrivKey, NULL)));
	assert((EVP_PKEY_derive_init(pkeyctx) == 1));

	// set peer pub key to pkeyctx
	assert(EVP_PKEY_derive_set_peer(pkeyctx, peerPubKey) == 1);

	// set outlen, allocate mem
	assert((EVP_PKEY_derive(pkeyctx, NULL, outlen)) == 1);
	*out = malloc(*outlen);
	assert((EVP_PKEY_derive(pkeyctx, *out, outlen)) == 1);

	EVP_PKEY_CTX_free (pkeyctx);
}
