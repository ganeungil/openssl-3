#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "common.h"

#define BlockLength	16
#define CIPHER		EVP_aes_128_cbc()
#define KeyLength	(128/8)		// key length is 128.  128/8=16
#define IVLength	(128/8)	// in aes-CBC, IV length should be block size

void asc2hex (char *name, const char *cp)
{
    printf ("%s is 0x[", name);
    for (; *cp!=0; cp++)
        printf ("%2X", *cp);
    printf ("]\n");
}


int main(int argc, char *argv[])
{
	int fileLength;
	int inFd, outFd, encLen, readLen;
	unsigned char key[KeyLength + 1], iv[IVLength + 1];
	unsigned char readData[BlockLength + 1];
	unsigned char *pt, *ct;

	EVP_CIPHER_CTX *ctx;

	if (argc != 3) {
		printf("Usage: a.out plaintextInFile encryptedOutFile \n");
		exit(1);
	}
	if ((inFd = open(argv[1], O_RDONLY)) < 0) {
		printf("can't open input file \n");
		exit(2);
	}
	if ((outFd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
		printf("can't open output file \n");
		exit(3);
	}

	memset(key, 0, KeyLength + 1);
	memset(iv, 0, IVLength + 1);
	memcpy(key, "0001020304050607", KeyLength);	// aes128,key=128bits
	memcpy(iv, "0001020304050607", IVLength);

	if (!(ctx = EVP_CIPHER_CTX_new()))
		exit (-1);

	EVP_EncryptInit(ctx, CIPHER, key, iv);
	ct = malloc(EVP_CIPHER_CTX_block_size(ctx));

	fileLength = lseek(inFd, 0, SEEK_END);
	lseek(inFd, 0L, SEEK_SET);

	do {
		if ((readLen = read(inFd, readData, BlockLength)) < 0) {
			printf("read from [%s] file error.\n", argv[1]);
			exit(6);
		}
		if (EVP_EncryptUpdate(ctx, ct, &encLen, readData, readLen) <= 0) {
			printf("EVP_EncryptUpdate() error.\n");
			exit(7);
		}
		write(outFd, ct, encLen);
		fileLength -= readLen;
	} while (fileLength > 0);

	if (EVP_EncryptFinal(ctx, ct, &encLen) <= 0) {
		printf("EVP_EncryptFinal_ex() error.\n");
		exit(7);
	}

	asc2hex ("key", key);
	asc2hex ("iv", iv);

	write(outFd, ct, encLen);
	close(inFd);
	close(outFd);
	EVP_CIPHER_CTX_free(ctx);
}
