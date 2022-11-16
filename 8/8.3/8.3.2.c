#include <stdio.h>
#include <assert.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

#define ClientPriv "client.key.pem"
#define ClientCert "client.crt.pem"
#define CaCert "ca-cert.pem"

int main()
{
	X509 *cert, *caCert;
	STACK_OF(X509) *caCertStack;
	PKCS12 *pkcs12Bundle;
	EVP_PKEY *certPrivkey;
	FILE *caCertFile, *certFile, *keyFile, *pkcs12File;
	int bytes = 0;
	
	// 클라이언트 비밀키 읽기 (client.key.pem)
	assert((certPrivkey = EVP_PKEY_new()) != NULL);
	assert((keyFile = fopen(ClientPriv, "r")) != 0);
	assert((certPrivkey=PEM_read_PrivateKey(keyFile, NULL, NULL, NULL)) !=0);
	fclose(keyFile);
	
	// 클라이언트 인증서 읽기
	assert ((certFile = fopen(ClientCert, "r")) != 0);
	assert ((cert = PEM_read_X509(certFile, NULL, NULL, NULL)) != 0);
	fclose(certFile);
	
	// CA 인증서 읽기
	assert ((caCertFile = fopen(CaCert, "r")) != 0);
	assert ((caCert = PEM_read_X509(caCertFile, NULL, NULL, NULL)) != 0);
	fclose(caCertFile);
	
	// CA 인증서를 스택에 push
	assert ((caCertStack = sk_X509_new_null()) != 0);
	sk_X509_push(caCertStack, caCert);
	
	// PKCS#12 번들 생성
	assert ((pkcs12Bundle = PKCS12_new()) != 0);
	
	// values of zero use the openssl default values
	pkcs12Bundle = PKCS12_create("test",	// 생성되는 번들의 암호
						 "pkcs12test",	// 생성되는 번들의 friendly 이름
						 certPrivkey,	// 포함할 비밀키
						 cert,			// 포함할 인증서
						 caCertStack,	// CA 인증서의 스택
						 0,	// int nid_key (default)
						 0,	// int nid_cert (efault)
						 0,	// int iter (default)
						 0,	// int mac_iter (default)
						 0	// int keytype (default)
	);
	if (pkcs12Bundle == NULL)
		printf("PKCS12_create() error.\n");
	
	// write the PKCS12 structure out to file 
	assert ((pkcs12File = fopen("./testcert.p12", "w")) != 0);

	bytes = i2d_PKCS12_fp(pkcs12File, pkcs12Bundle);
	if (bytes <= 0)
		printf("i2d_PKCS12_fp() error\n");
	
	// clean up
	sk_X509_free(caCertStack);
	PKCS12_free(pkcs12Bundle);
	return (0);
}
