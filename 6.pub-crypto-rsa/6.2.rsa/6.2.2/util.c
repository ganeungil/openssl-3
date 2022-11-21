#include "common.h"

// save private key to file
// if (keyType=1) save private key
// if (keyType=2) save public key
int saveKey (int keyType, EVP_PKEY *pkey, char *fileName, char *password, int passLen)
{
	FILE *fp;

	assert ((fp=fopen(fileName, "w")) != 0);
	if (keyType == 1)
		assert (PEM_write_PrivateKey (fp, pkey, EVP_aes_192_cbc(), password, passLen, 0, 0) != 0);
	else if (keyType == 2)
		assert (PEM_write_PUBKEY(fp, pkey) != 0);
	else
		printf ("saveKey: invalid keyType.\n");

	fclose (fp);
}

void printKeys (EVP_PKEY *pkey)
{
	printf ("-----------\n");
	EVP_PKEY_print_public_fp(stdout, pkey, 4, 0);
	printf ("-----------\n");
	EVP_PKEY_print_private_fp(stdout, pkey, 4, 0);
}

void print_errors(void)
{
	unsigned long err = 0;

	err = ERR_get_error();
	printf("----->[%s]\n", ERR_error_string(err, NULL)); 
}
