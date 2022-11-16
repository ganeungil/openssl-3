#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERT_FILE "./client.crt.pem"
int main()
{
	BIO *certBio = NULL;
	BIO *outBio = NULL;
	X509 *cert = NULL;
	const EVP_MD *fprintType = NULL;
	int j, fprintLen;
	unsigned char fprint[EVP_MAX_MD_SIZE];

	certBio = BIO_new(BIO_s_file());
	outBio = BIO_new_fp(stdout, BIO_NOCLOSE);

	// 인증서 읽기
	BIO_read_filename(certBio, CERT_FILE);
	if (!(cert = PEM_read_bio_X509(certBio, NULL, 0, NULL))) {
		BIO_printf(outBio, "Error reading cert\n");
		exit(-1);
	}

	// 다이제스트 계산
	fprintType = EVP_sha1();
	if (!X509_digest(cert, fprintType, fprint, &fprintLen))
		BIO_printf(outBio, "Error calculating cert digest.\n");

	BIO_printf(outBio, "Digest method: %s\n", OBJ_nid2sn(EVP_MD_type(fprintType)));
	BIO_printf(outBio, "Digest length: %d\n", fprintLen);

	BIO_printf(outBio, "Digest: ");
	for (j = 0; j < fprintLen; ++j)
		BIO_printf(outBio, "%02x ", fprint[j]);
	BIO_printf(outBio, "\n");

	BIO_free_all(certBio);
	BIO_free_all(outBio);
	exit(0);
}
