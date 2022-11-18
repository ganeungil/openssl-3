#include "common.h"
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX * ctx, int nid);
int genKey(EVP_PKEY ** pkey)
{
	EVP_PKEY_CTX *ctx;

	// create ctx
	assert((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)));
	assert(EVP_PKEY_keygen_init(ctx));

	// set EC curve fot the ctx
	assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid
		   (ctx, NID_X9_62_prime256v1) > 0);

	// generate key pair
	assert(EVP_PKEY_keygen(ctx, pkey));

	EVP_PKEY_CTX_free(ctx);
}
