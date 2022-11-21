// dec.c
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

void printErr(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	ERR_print_errors_fp(stderr);
	exit(1);
}

int readData(const char *filename, unsigned char *key)
{
	BIO *file, *buffer, *b64, *cipher;
	int readcnt;
	int total;
	char outBuf[1024];
	int status;

	if (!(file = BIO_new_file(filename, "r")))
		printErr("BIO_new_file() error");

	buffer = BIO_new(BIO_f_buffer());
	b64 = BIO_new(BIO_f_base64());
	cipher = BIO_new(BIO_f_cipher());

	// 암호 방식과 키 설정. 마지막 파라메타는 인코딩(1), 또는 디코딩(0)을 지정
	BIO_set_cipher(cipher, EVP_aes_128_cfb(), key, NULL, 0);

	/* bio 체인 설정: cipher-b64-buffer-file */
	BIO_push(cipher, b64);
	BIO_push(b64, buffer);
	BIO_push(buffer, file);

	for (total = 0;; total += readcnt) {
		if ((readcnt = BIO_read(cipher, outBuf, sizeof(outBuf))) <= 0) {
			if (BIO_should_retry(cipher)) {
				readcnt = 0;
				continue;
			}
			break;
		}
		printf("read %d bytes\n", readcnt);
		outBuf[readcnt] = '\0';
		printf("%s", outBuf);
	}

	putchar('\n');				/* newline */
	if (!(status = BIO_get_cipher_status(cipher))) {
		printf("Decryption failure!\n");
		printErr("BIO_get_cipher_status");
	}
	BIO_free_all(cipher);
}

int main()
{
	char *filename = "aes128.out";
	char *key = "0123456789012345";

	readData(filename, key);
}
