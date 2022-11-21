#include "common.h"

#define MdName	EVP_sha256()

int main(int argc, char *argv[]) {
	char *VerifyFile = argv[1];
	unsigned char *pubKey, *privKey;
	int pubLen, privLen, ret;
	EVP_PKEY *pkey=EVP_PKEY_new(), *newpkey;
	unsigned char *signOut;
	size_t signOutLen;

	genKey (&pkey);

	getCharKeys (pkey, &pubKey, &pubLen, &privKey, &privLen);
	setCharKeys (&newpkey, pubKey, pubLen, privKey, privLen);

	rsaSign (privKey, privLen, VerifyFile, MdName, &signOut, &signOutLen);
	ret = rsaVerify (pubKey, pubLen, VerifyFile, MdName, signOut, signOutLen);

	if (ret == 1)
		printf ("verify success\n");
	else
		printf ("verify fail\n");


	// for the verification with openssl(1)
	int fd;
	assert ((fd = open ("signPgm.out", O_WRONLY | O_CREAT | O_TRUNC)) >= 0);
	assert (write (fd, signOut, signOutLen) == signOutLen);
	close (fd);
	printf ("digest=sha256\n"); 
	printf ("sign for [%s] file is saved in signPgm.out\n", argv[1]);

	printf ("save private/public key to file (priv.pem/pub.pem)\n");
	saveKey (1, pkey, "priv.pem", "password", strlen("password"));
	saveKey (2, pkey, "pub.pem", 0, 0);

	OPENSSL_free (pubKey);
	OPENSSL_free (privKey);
	OPENSSL_free (signOut);
	EVP_PKEY_free (pkey);
}
