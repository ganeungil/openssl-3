#include "common.h"

// privFileName: private key file
// verifyFile: file containing a message
// mdName: message digest name
// out: contains a calculated signature
int ecdsaSign (unsigned char *privKey, int privLen, char *verifyFile,
        const EVP_MD *mdName, unsigned char **out, size_t *outLen)
{
	int fd, len;
	unsigned char buf[512];
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_PKEY *pkey = EVP_PKEY_new();

	setCharKeys (&pkey, 0, 0, privKey, privLen);

	if (EVP_DigestSignInit(mdCtx, NULL, mdName, NULL, pkey) != 1)
		print_errors();
	assert ((fd=open(verifyFile, O_RDONLY)));
	while ((len=read(fd, buf, 128)) > 0)
		EVP_DigestSignUpdate(mdCtx, buf, len);
	close (fd);

	assert ((*outLen = (size_t)EVP_PKEY_size(pkey)));
	*out = OPENSSL_malloc (*outLen);
	assert (EVP_DigestSignFinal(mdCtx, *out, outLen));

	EVP_MD_CTX_free(mdCtx);
	EVP_PKEY_free(pkey);
}

// verify input 'sig' for the 'verifyFile'
int ecdsaVerify (unsigned char *pubKey, int pubLen, char *verifyFile,
        const EVP_MD *mdName, unsigned char *sig, size_t sigLen)
{
	int fd, len;
	unsigned char buf[128];
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_PKEY *pkey = EVP_PKEY_new();

	setCharKeys(&pkey, pubKey, pubLen, 0, 0);

	if (EVP_DigestVerifyInit(mdCtx, NULL, mdName, NULL, pkey) != 1)
		print_errors();
	assert((fd = open(verifyFile, O_RDONLY)));
	while ((len = read(fd, buf, 128)) > 0)
		EVP_DigestVerifyUpdate(mdCtx, buf, len);
	close(fd);

	return (EVP_DigestVerifyFinal(mdCtx, sig, sigLen));

	EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);
}
