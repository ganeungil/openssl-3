#include <stdio.h>
#include <assert.h>
#include <openssl/pem.h>

int main(int argc, char *argv[]) {
    EVP_PKEY *pkey;
    FILE *fp;
    char pass[] = "password";   // 패스워드

    pkey = EVP_PKEY_new();

    assert (argc == 2);
    assert ((fp = fopen (argv[1], "r")) != 0);  // 비밀키 파일
    assert (PEM_read_PrivateKey(fp, &pkey, NULL, pass) != 0);
    fclose(fp);

    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, 0, NULL);
}
