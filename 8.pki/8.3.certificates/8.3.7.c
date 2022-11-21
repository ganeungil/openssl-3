#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERTFILE "./client.crt.pem"

int main()
{
	X509 *cert = NULL;
	BIO *outBio = NULL, *certBio = NULL;
	EVP_PKEY *pkey = NULL;
	
	certBio = BIO_new(BIO_s_file());
	outBio = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	// 인증서 파일 읽기
	BIO_read_filename(certBio, CERTFILE);
	if (!(cert = PEM_read_bio_X509(certBio, NULL, 0, NULL))) {
		BIO_printf(outBio, "Error loading cert into memory\n");
		exit(-1);
	}
	
	// 공개키 추출
	if ((pkey = X509_get_pubkey(cert)) == NULL)
		BIO_printf(outBio, "Error getting public key from certificate");
	
	// 출력
	if (pkey) {
		int id = EVP_PKEY_id(pkey);		// returns the actual OID for pkey.
		printf ("%s information:\t", CERTFILE);

		switch (id) {
			case EVP_PKEY_RSA:
				BIO_printf(outBio, "%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_DSA:
				BIO_printf(outBio, "%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_EC:
				BIO_printf(outBio, "%d bit ECDSA Key\n\n", EVP_PKEY_bits(pkey));
				break;
			default:
				BIO_printf(outBio, "%d bit non-RSA/(EC)DSA Key\n\n",
						EVP_PKEY_bits(pkey));
			break;
		}
	}

	if (!PEM_write_bio_PUBKEY(outBio, pkey))
		BIO_printf(outBio, "Error writing public key data in PEM format");

	EVP_PKEY_free(pkey);
	BIO_free_all(certBio);
	BIO_free_all(outBio);

	exit(0);
}
