#include <err.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY "0001020304050607"
#define IV "0001020304050607"
#define KeyLength   (128/8)
#define IVLength    (128/8)

int decryptExample(EVP_CIPHER_CTX * ctx, unsigned char *ctbuf, int ctlen, unsigned char *ptbuf, int *ptlen)
{
	int len;
	if (1 != EVP_DecryptUpdate(ctx, ptbuf, ptlen, ctbuf, ctlen))
		err(-1, "EVP_DecryptUpdate()");
	if (1 != EVP_DecryptFinal_ex(ctx, ptbuf + *ptlen, &len))
		err(-1, "EVP_DecryptFinal_ex()");
	*ptlen = *ptlen + len;
	return *ptlen;
}

int encryptExample(EVP_CIPHER_CTX * ctx, unsigned char *ptbuf, int ptlen, unsigned char *ctbuf, int *ctlen)
{
	int tmp;
	if (1 != EVP_EncryptUpdate(ctx, ctbuf, ctlen, ptbuf, ptlen))
		err(-1, "EVP_EncryptUpdate()");
	if (1 != EVP_EncryptFinal_ex(ctx, ctbuf + *ctlen, &tmp))
		err(-1, "EVP_EncryptFinal_ex()");
	*ctlen = *ctlen + tmp;
	return *ctlen;
}

#define MESSAGE "In cryptography, a public key certificate, also known as a digital certificate or identity certificate, is an electronic document used to prove the validity of a public key."

int main()
{
	int ctlen, ptlen;
	char *ctbuf, *ptbuf;
	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		err(1, "EVP_CIPHER_CTX_new() error");

	// for encryption
	if (1 != EVP_EncryptInit(ctx, EVP_aes_128_cbc(), KEY, IV))
		err(1, "EVP_EncryptInit() error");
	ctbuf = OPENSSL_malloc(strlen(MESSAGE));
	encryptExample(ctx, MESSAGE, strlen(MESSAGE), ctbuf, &ctlen);

	// for decryption
	if (1 != EVP_DecryptInit(ctx, EVP_aes_128_cbc(), KEY, IV))
		err(1, "EVP_EncryptInit() error");
	ptbuf = OPENSSL_malloc(strlen(MESSAGE));
	decryptExample(ctx, ctbuf, ctlen, ptbuf, &ptlen);
	printf("original  message: [%s]\n\n", MESSAGE);
	printf("decrypted message: [%s]\n", ptbuf);
	OPENSSL_free(ctbuf);
	OPENSSL_free(ptbuf);
	EVP_CIPHER_CTX_free(ctx);
}

