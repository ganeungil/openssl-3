#include "common.h"

#define VerifyFile 	"ls.man"
#define MdName	EVP_sha256()

int main() {
	unsigned char *pubKey, *privKey;
	int pubLen, privLen, ret;
	EVP_PKEY *pkey;
	unsigned char *signOut;
	size_t signOutLen;

	pkey = EVP_EC_gen("P-256");	// for 256-bits ecdsa, ecdh

	getCharKeys (pkey, &pubKey, &pubLen, &privKey, &privLen);
	
	ecdsaSign (privKey, privLen, VerifyFile, MdName, &signOut, &signOutLen);
	
	ret = ecdsaVerify (pubKey, pubLen, VerifyFile, MdName, signOut, signOutLen);

	if (ret == 1)
		printf ("verify success\n");
	else
		printf ("verify fail\n");
		
	OPENSSL_free (pubKey);
	OPENSSL_free (privKey);
	OPENSSL_free (signOut);
	EVP_PKEY_free (pkey);
}
