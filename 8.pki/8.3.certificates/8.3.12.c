#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define CERT_FILE "./ca-cert.pem"

int main()
{
	BIO *certBio = NULL;
	BIO *outBio = NULL;
	X509 *cert = NULL;
	X509_CINF *certInf = NULL;
	const STACK_OF(X509_EXTENSION) *extList;
	int ret, i;

	
	certBio = BIO_new(BIO_s_file());
	outBio = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	// read cert file
	ret = BIO_read_filename(certBio, CERT_FILE);
	if (!(cert = PEM_read_bio_X509(certBio, NULL, 0, NULL))) {
		BIO_printf(outBio, "Error loading cert into memory\n");
		exit(-1);
	}
	
	// extract extension field
	extList = X509_get0_extensions(cert);

	if (sk_X509_EXTENSION_num(extList) <= 0)
		return 1;
	
	// print each extension field
	for (i = 0; i < sk_X509_EXTENSION_num(extList); i++) {
		ASN1_OBJECT * obj;
		X509_EXTENSION * ext;

		ext = sk_X509_EXTENSION_value(extList, i);
		obj = X509_EXTENSION_get_object(ext);

		BIO_printf(outBio, "\n");
		BIO_printf(outBio, "Object %.2d: ", i);

		i2a_ASN1_OBJECT(outBio, obj);
		BIO_printf(outBio, "\n");
		X509V3_EXT_print(outBio, ext, 0, 0);
		BIO_printf(outBio, "\n");
	}

	BIO_free_all(certBio);
	BIO_free_all(outBio);
	exit(0);
}
