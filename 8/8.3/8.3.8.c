#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERTFILE "./client.crt.pem"

int main()
{
	ASN1_INTEGER *asn1Serial = NULL;
	BIO *certBio = NULL;
	BIO *outBio = NULL;
	X509 *cert = NULL;

	certBio = BIO_new(BIO_s_file());
	outBio = BIO_new_fp(stdout, BIO_NOCLOSE);

	// 인증서 읽기
	BIO_read_filename(certBio, CERTFILE);
	if (!(cert = PEM_read_bio_X509(certBio, NULL, 0, NULL))) {
		BIO_printf(outBio, "Error loading cert into memory\n");
		exit(-1);
	}

	// serial number 추출
	asn1Serial = X509_get_serialNumber(cert);
	if (asn1Serial == NULL)
		BIO_printf(outBio, "Error getting serial number from certificate");

	// serial number 출력
	i2a_ASN1_INTEGER(outBio, asn1Serial);
	BIO_puts(outBio, "\n");

	BIO_free_all(certBio);
	BIO_free_all(outBio);
	exit(0);
}
