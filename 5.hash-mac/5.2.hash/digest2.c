#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[]) {
    EVP_MD_CTX *mdctx;
    char mess1[] = "Test message\n";
    char mess2[] = "Hello world\n";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len, i;

    if (!argv[1]) {
            printf("Usage: a.out digestname\n");    exit(1);
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);		// 

    EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
    EVP_DigestUpdate(mdctx, mess2, strlen(mess2));

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    printf("Digest is: ");
    for(i = 0; i < md_len; i++)     printf("%02x", md_value[i]);
    printf("\n");
}
