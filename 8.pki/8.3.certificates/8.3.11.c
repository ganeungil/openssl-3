#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

// concatenated certificate bundle file
#define CONCATED_CERTS "./tls-ca-bundle.pem"

int main()
{
	STACK_OF(X509_INFO) *certStack;
	X509_INFO *stackItem = NULL;
	X509_NAME *certSubject = NULL;
	BIO *stackBio = NULL;
	BIO *outBio = NULL;
	X509 *cert = NULL;
	int i;
	
	stackBio = BIO_new(BIO_s_file());
	outBio = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	// read concatenated cert file
	if (BIO_read_filename(stackBio, CONCATED_CERTS) <= 0) {
		BIO_printf(outBio, "Error loading cert bundle into memory\n");
		exit(-1);
	}
	certStack = sk_X509_INFO_new_null();
	certStack = PEM_X509_INFO_read_bio(stackBio, NULL, NULL, NULL);
	
	// print the num of certs
	BIO_printf(outBio, "# of stack certs: %d\n", sk_X509_INFO_num(certStack));
	
	// print info for each cert
	for (i = 0; i < sk_X509_INFO_num(certStack); i++) {
		char subject_cn[256] = "** n/a **";
		long cert_version;

		stackItem = sk_X509_INFO_value(certStack, i);
		certSubject = X509_get_subject_name(stackItem->x509);
		X509_NAME_get_text_by_NID(certSubject, NID_commonName,
								   subject_cn, 256);
		cert_version = X509_get_version(stackItem->x509) + 1;

		BIO_printf(outBio, "Cert #%.2d v%ld CN: %.70s\n", i,
					 cert_version, subject_cn);
	} 

	// free all
	sk_X509_INFO_pop_free(certStack, X509_INFO_free);
	BIO_free_all(stackBio);
	BIO_free_all(outBio);
	exit(0);
}
