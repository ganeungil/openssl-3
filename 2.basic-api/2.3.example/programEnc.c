#include <stdio.h>
#include <openssl/bio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define OUT_FILE "aes128.out"

void printErr(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	ERR_print_errors_fp(stderr);
	exit(1);
}

int writeData(const char *filename, char *outData, int len,
				 unsigned char *key, unsigned char *iv)
{
	int total, written;
	BIO *cipher, *buffer, *file;

	if (!(file = BIO_new_file(filename, "w")))
		printErr("BIO_new_file()");
	buffer = BIO_new(BIO_f_buffer());
	cipher = BIO_new(BIO_f_cipher());

	// 암호 방식과 키 설정. 마지막 파라메타는 인코딩(1), 또는 디코딩(0)을 지정
	BIO_set_cipher(cipher, EVP_aes_128_cfb(), key, iv, 1);

	/* set bio chain to  cipher-buffer-file */
	BIO_push(cipher, buffer);
	BIO_push(buffer, file);

	for (total = 0; total < len; total += written) {
		if ((written=BIO_write(cipher, outData + total, len - total)) <= 0) {
			if (BIO_should_retry(cipher)) {
				written = 0;
				continue;
			}
			break;
		}
	}

	/* push remaining data if any */
	if (!BIO_flush(cipher)) {
		printf("Bad encrypt!\n");
	}

	/* We now need to free the BIO chain. */
	BIO_free_all(cipher);
}

// ascii 코드를 hex로 출력
void asc2hex(char *name, const char *cp)
{
	printf("%s is 0x[", name);
	for (; *cp != 0; cp++)
		printf("%2X", *cp);
	printf("]\n");
}

int main()
{
	char *outData = "Hello world. This is test input";
	char *key = "0123456789012345";
	char *iv = "0123456789012345";

	writeData(OUT_FILE, outData, strlen(outData), key, iv);
	asc2hex("key", key);
	asc2hex("iv", key);
}
