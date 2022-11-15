#include <stdio.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#define BUFSIZE 10

void verification(int fd, char *o_hash, char *key) 
{
	int i;
	size_t len;
	OSSL_PARAM params[2];
	unsigned char out[1024], nn[1024], buf[BUFSIZE];

	EVP_MAC *mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);

	params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
	params[1] = OSSL_PARAM_construct_end();

	EVP_MAC_init(ctx, key, strlen(key), params);
	while ((i = read(fd, buf, BUFSIZE)) > 0) {
		EVP_MAC_update(ctx, buf, i);
	}
	EVP_MAC_final(ctx, out, &len, sizeof(out));

	printf("sha256 mac      = ");
	for (i = 0; i < len; i++) {
		printf("%02x", out[i]);
		sprintf(nn + (i * 2), "%02x", out[i]);
	}
	printf("\n");
	if (strncmp(nn, o_hash, len * 2) == 0)
		printf("verify OK\n");
	else
		printf("verification fail\n");
}

int main(int argc, char *argv[])
{
	int fd;

	if (argc < 3) {
		printf("usage : veri [input file] [mac value] [key]\n");
		exit(1);
	}
	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		printf("file open error\n");
		exit(1);
	}
	verification(fd, argv[2], argv[3]);
}

