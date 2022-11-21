#include "common.h"
#define OID	NID_X9_62_prime256v1

// read private key from 'privFileName'
// file containing a message = 'VerifyFile'
// message digest name = mdName
int rsaSign (unsigned char *privkey, int privlen, char *VerifyFile,
        const EVP_MD *mdName, unsigned char **out, size_t *outLen)
{
	int fd, len;
	unsigned char buf[512];
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	EVP_PKEY *pkey = EVP_PKEY_new();

	setCharKeys (&pkey, 0, 0, privkey, privlen);

	if (EVP_DigestSignInit(mdctx, NULL, mdName, NULL, pkey) != 1)
		print_errors();
	assert ((fd=open(VerifyFile, O_RDONLY)) >= 0);
	while ((len=read(fd, buf, 128)) > 0)
		EVP_DigestSignUpdate(mdctx, buf, len);
	close (fd);

	assert ((*outLen = (size_t)EVP_PKEY_size(pkey)));
	*out = OPENSSL_malloc (*outLen);
	assert (EVP_DigestSignFinal(mdctx, *out, outLen));

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
}

int rsaVerify (unsigned char *pubkey, int publen, char *VerifyFile,
        const EVP_MD *mdName, unsigned char *sig, size_t sigLen)
{
	int fd, len;
	//size_t keylen;
	unsigned char buf[128];
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	EVP_PKEY *pkey = EVP_PKEY_new();

	setCharKeys(&pkey, pubkey, publen, 0, 0);

	if (EVP_DigestVerifyInit(mdctx, NULL, mdName, NULL, pkey) != 1)
		print_errors();
	assert((fd = open(VerifyFile, O_RDONLY)) >= 0);
	while ((len = read(fd, buf, 128)) > 0)
		EVP_DigestVerifyUpdate(mdctx, buf, len);
	close(fd);

	return (EVP_DigestVerifyFinal(mdctx, sig, sigLen));

	EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
}
