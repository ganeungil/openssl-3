#include "common.h"

int main()
{
	EVP_PKEY *key = EVP_PKEY_new();

	genKey (&key);

	pubKeyTest (key);
	privKeyTest (key);
}
