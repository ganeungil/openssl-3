#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERT_FILE "./client.crt.pem"

int main()
{
	const ASN1_BIT_STRING *asnSig;
	const X509_ALGOR *sigAlg = NULL;
	BIO *certBio = NULL, *outBio = NULL;
	X509 *cert = NULL;

	certBio = BIO_new(BIO_s_file());
	outBio = BIO_new_fp(stdout, BIO_NOCLOSE);

	// 인증서 파일 읽기
	BIO_read_filename(certBio, CERT_FILE);
	if (!(cert = PEM_read_bio_X509(certBio, NULL, 0, NULL))) {
		BIO_printf(outBio, "Error reading cert file\n");
		exit(-1);
	}

	// 서명 추출
	X509_get0_signature(&asnSig, &sigAlg, cert);

	// 출력
    assert (X509_signature_print(outBio, sigAlg, asnSig) > 0);

	BIO_free_all(certBio);
	BIO_free_all(outBio);
	exit(0);
}
