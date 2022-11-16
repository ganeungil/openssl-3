#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERT_FILE "client.crt.pem"
#define PKEY_FILE "client.key.pem"

int main()
{
	BIO *certbio = NULL, *pkeybio = NULL, *outbio = NULL;
	X509 *cert = NULL;
	X509_REQ *certreq = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD const *digest = EVP_sha1();
	int ret;

	certbio = BIO_new(BIO_s_file());
	pkeybio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	// load old certificate
	ret = BIO_read_filename(certbio, CERT_FILE);
	if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
		BIO_printf(outbio, "Error loading cert into memory\n");
		exit(-1);
	}

	// load private key
	ret = BIO_read_filename(pkeybio, PKEY_FILE);
	if (!(pkey = PEM_read_bio_PrivateKey(pkeybio, NULL, 0, NULL))) {
		BIO_printf(outbio, "Error loading private key into memory\n");
		exit(-1);
	}

	// create new cert request from old certificate
	if ((certreq = X509_to_X509_REQ(cert, pkey, digest)) == NULL) {
		BIO_printf(outbio, "Error converting certificate into request.\n");
		exit(-1);
	}

	// print new certificate request
	PEM_write_bio_X509_REQ(outbio, certreq);

	X509_free(cert);
	X509_REQ_free(certreq);
	EVP_PKEY_free(pkey);
	BIO_free_all(certbio);
	BIO_free_all(pkeybio);
	BIO_free_all(outbio);

	exit(0);
}
