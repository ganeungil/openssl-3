#include "common.h"

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
