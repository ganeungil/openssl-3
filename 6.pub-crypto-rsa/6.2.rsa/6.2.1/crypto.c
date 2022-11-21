#include "common.h"

// encrypt with public key. 
//		'pkey' contains only pub key.
int rsaEncrypt (EVP_PKEY *pkey, unsigned char *pt, size_t ptLen,
								unsigned char **ct, size_t *ctLen) 
{
	EVP_PKEY_CTX *ctx;

	assert ((ctx = EVP_PKEY_CTX_new(pkey, 0)) != 0);
	assert (EVP_PKEY_encrypt_init(ctx) > 0);
	assert (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0);

	/* Determine buffer length */ 
	assert (EVP_PKEY_encrypt(ctx, NULL, ctLen, pt, ptLen) > 0);

	assert ((*ct = OPENSSL_malloc(*ctLen)) != 0);
	assert (EVP_PKEY_encrypt(ctx, *ct, ctLen, pt, ptLen) > 0);

	EVP_PKEY_CTX_free (ctx);
}

// decrypt with public key. 
//      'pkey' contains private key.
int rsaDecrypt (EVP_PKEY *pkey, unsigned char *ct, size_t ctLen,
								unsigned char **pt, size_t *ptLen) 
{
	EVP_PKEY_CTX *ctx;

    assert ((ctx = EVP_PKEY_CTX_new(pkey, 0)) != 0);
    assert (EVP_PKEY_decrypt_init(ctx) > 0);
    assert (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0);

    /* Determine buffer length */
    assert (EVP_PKEY_decrypt(ctx, NULL, ptLen, ct, ctLen) > 0);

    assert ((*pt = OPENSSL_malloc(*ptLen)) != 0);
    assert (EVP_PKEY_decrypt(ctx, *pt, ptLen, ct, ctLen) > 0);
    
    EVP_PKEY_CTX_free (ctx);
}
