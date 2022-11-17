#include <unistd.h>
#include "common.h"

#define PASSWORD "password"

int pubKeyTest (EVP_PKEY *key)
{
	FILE *fp;
    char file[128];
	EVP_PKEY *readKey = EVP_PKEY_new();

	memset (file, 0, sizeof(file)); // clear
    sprintf (file, "pub%d", getpid());

    assert ((fp = fopen(file, "w")) != 0);
    assert (PEM_write_PUBKEY(fp, key) != 0);    // save
    fclose (fp);

    assert ((fp = fopen(file, "r")) != 0);
    assert (PEM_read_PUBKEY(fp, &readKey, 0, 0) != 0);  // read
    fclose (fp);

    if (EVP_PKEY_eq (key, readKey) == 1)
        printf ("public key test success\n");
    else
        printf ("public key test failed.\n");

    unlink (file);
}

int privKeyTest (EVP_PKEY *key)
{
	FILE *fp;
    char file[128];
	EVP_PKEY *readKey = EVP_PKEY_new();

    memset (file, 0, sizeof(file)); // clear
    sprintf (file, "priv%d", getpid());

    assert ((fp = fopen(file, "w")) != 0);
    assert (PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(), PASSWORD, strlen(PASSWORD), 0, 0) != 0);    // save
    fclose (fp);

    assert ((fp = fopen(file, "r")) != 0);
    assert (PEM_read_PrivateKey(fp, &readKey, 0, PASSWORD) != 0);  // read
    fclose (fp);

    if (EVP_PKEY_eq (key, readKey) == 1)
        printf ("private key test success\n");
    else
        printf ("private key test failed.\n");

    unlink (file);
}
