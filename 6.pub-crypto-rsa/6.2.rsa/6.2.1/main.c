#include "common.h"

#define MSG "OpenSSL is a cryptography toolkit implementing the SSL and TLS"

int main()
{
	unsigned char *ct, *pt;
	size_t ctLen, ptLen;
	EVP_PKEY *pubPkey;
	EVP_PKEY *pkey = EVP_PKEY_new();

	genKey(&pkey);
	pubPkey = getPubKey(pkey);

	rsaEncrypt (pubPkey, MSG, strlen(MSG), &ct, &ctLen);

	rsaDecrypt (pkey, ct, ctLen, &pt, &ptLen);
	*(pt+ptLen) =0; // set null

	printf ("original  message:[%s]\n", MSG);
	printf ("decrypted message:[%s]\n", pt);

	OPENSSL_free (ct);
	OPENSSL_free (pt);
	EVP_PKEY_free (pkey);
	EVP_PKEY_free (pubPkey);
}
