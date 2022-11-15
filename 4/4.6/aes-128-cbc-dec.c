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
#define KeyLength	(8*2)		// key length is 128.  128/8=16
#define IVLength		(8*2)	// in CBC, IV length should be block size (128, if AES)

int main(int argc, char **argv)
{
	int fileLength;
	int inFd, outFd, decLen, readLen;
	unsigned char key[KeyLength + 1], iv[IVLength + 1];
	unsigned char readData[BlockLength + 1];
	unsigned char *pt, *ct;

	EVP_CIPHER_CTX *ctx;

	if (argc != 3) {
		printf("Usage: a.out cipherTextInFile DecryptedOutFile \n");
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
	memcpy(key, "0001020304050607", KeyLength);
	memcpy(iv, "0001020304050607", IVLength);

	if (!(ctx = EVP_CIPHER_CTX_new()))
		exit (-1);

	EVP_DecryptInit(ctx, CIPHER, key, iv);
	pt = malloc(EVP_CIPHER_CTX_block_size(ctx) + 1);

	fileLength = lseek(inFd, 0, SEEK_END);
	lseek(inFd, 0L, SEEK_SET);

	do {
		if ((readLen = read(inFd, readData, BlockLength)) < 0) {
			printf("Decryption: read error.\n", argv[2]);
			exit(6);
		}
		if (EVP_DecryptUpdate(ctx, pt, &decLen, readData, readLen) <= 0) {
			printf("EVP_DecryptUpdate() error\n");
			exit(10);
		}

		write(outFd, pt, decLen);
		fileLength -= readLen;
	} while (fileLength > 0);

	if (!EVP_DecryptFinal(ctx, pt, &decLen)) {
		printf("EVP_DecryptFinal_ex() error\n");
		exit(10);
	}
	write(outFd, pt, decLen);

	EVP_CIPHER_CTX_free(ctx);

}
