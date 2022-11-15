#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define STRING "Hello world. This is test string."
#define ExKey "example key"

int main () {
    unsigned int  i, len;
    unsigned char out[SHA512_DIGEST_LENGTH];

    HMAC (EVP_sha3_512(), ExKey, strlen(ExKey), STRING, strlen(STRING), out, &len);
    for (i = 0;  i < len;  i++) printf("%02x", out[i]);

    printf("\n");
}
