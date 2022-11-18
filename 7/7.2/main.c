#include "common.h"
int main()
{
	EVP_PKEY *pubkeyAlice, *pubkeyBob;
	EVP_PKEY *pkeyAlice = EVP_PKEY_new();
	EVP_PKEY *pkeyBob = EVP_PKEY_new();
	unsigned char *commonKeyAlice, *commonKeyBob;
	size_t comKeyLenAlice, comKeyLenBob;

	genKey(&pkeyAlice);
	genKey(&pkeyBob);

	pubkeyAlice = getPubKey(pkeyAlice);
	pubkeyBob = getPubKey(pkeyBob);

	computeDH(pkeyAlice, pubkeyBob, &commonKeyAlice, &comKeyLenAlice);
	computeDH(pkeyBob, pubkeyAlice, &commonKeyBob, &comKeyLenBob);

	//if (memcmp(commonKeyAlice, commonKeyBob, comKeyLenAlice) == 0)
	if (CRYPTO_memcmp(commonKeyAlice, commonKeyBob, comKeyLenAlice) == 0)
		printf("two keys are equal\n");

	EVP_PKEY_free (pkeyAlice);
	EVP_PKEY_free (pkeyBob);
	free(commonKeyAlice);
	free(commonKeyBob);
}
