#include "common.h"

// get public key from pkey
// return EVP_PKEY (contains only public key)
EVP_PKEY *getPubKey(EVP_PKEY * pkey)
{
	int len;

	BIO *bp = BIO_new(BIO_s_mem());
	EVP_PKEY *pubkey = 0;

	assert(i2d_PUBKEY_bio(bp, pkey));
	assert(d2i_PUBKEY_bio(bp, &pubkey));
	BIO_free(bp);
	return (pubkey);
}

void print_errors(void)
{
	unsigned long err = 0;

	err = ERR_get_error();
	printf("----->[%s]\n", ERR_error_string(err, NULL));
}
