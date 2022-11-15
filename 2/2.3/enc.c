// enc.c
#include <stdio.h>
#include <openssl/bio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

void printErr(const char *msg)
{
    fprintf (stderr, "%s\n", msg);
    ERR_print_errors_fp (stderr);
    exit (1);
}

int writeData(const char *filename, char *outData, int len, unsigned char *key)
{
    int total, written;
    BIO *cipher, *b64, *buffer, *file;

    // 파일에 쓰기 위한 bio 생성
    if (!(file=BIO_new_file (filename, "w")))
        printErr ("BIO_new_file()");

	// 필터 bio 생성 (버퍼용)
    buffer = BIO_new (BIO_f_buffer());

	// base64 인코딩을 위한 필터 bio 생성
    b64 = BIO_new (BIO_f_base64());

	// encryption을 위한 필터 bio 생성
    cipher = BIO_new (BIO_f_cipher());

	// 암호 방식과 키 설정. 마지막 파라메타는 인코딩(1), 또는 디코딩(0)을 지정
    BIO_set_cipher (cipher, EVP_aes_128_cfb(), key, NULL, 1);

	// bio 체인 생성: cipher-b64-buffer-file
    BIO_push (cipher, b64);
    BIO_push (b64, buffer);
    BIO_push (buffer, file);

    for (total=0; total<len; total += written) {
    		if ((written=BIO_write(cipher, outData+total, len-total)) <= 0) {
				if (BIO_should_retry (cipher)) {
					written = 0;
					continue;
				}
				printErr("BIO_write error()");
				break;
			}
    }

	// cipher에 출력되지 않는 데이터가 있는 경우, 전부 출력
    if (!BIO_flush (cipher)) {
        printf("Bad encrypt!\n");
    }

    BIO_free_all (cipher); // 제거
}


void asc2hex (char *name, const char *cp)
{
    printf ("%s is 0x[", name);
    for (; *cp!=0; cp++)
        printf ("%2X", *cp);
    printf ("]\n");
}

int main()
{
    char *outData = "Hello world. This is test input";
    char *key = "0123456789012345";		// 16 octet

    printf ("encryption data length=[%ld]\n", strlen(outData));
    writeData ("aes128.out", outData, strlen(outData), key);

    asc2hex ("key", key);
}
