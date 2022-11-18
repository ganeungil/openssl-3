// main.c
#include "common.h"

int main() {
    EVP_PKEY *pkey=EVP_PKEY_new();

    genKey (&pkey);

    EVP_PKEY_print_public_fp(stdout, pkey, 4, 0);
    printf ("----------------\n");
    EVP_PKEY_print_private_fp(stdout, pkey, 4, 0);

	EVP_PKEY_free (pkey);
}
