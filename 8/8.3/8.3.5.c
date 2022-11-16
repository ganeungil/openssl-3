#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#define CACERT	"./ca-cert.pem"
#define CAKEY	"./ca-key.pem"
#define PASS	"password"
#define CSR	"x509Req.pem"

BIO *outBio = NULL;
X509 *cert = NULL;
X509_REQ *certReq = NULL;

int main()
{
	FILE * fp;
	X509V3_CTX ctx;
	X509_NAME *name;
	X509 *newCert, *caCert;
	ASN1_INTEGER *serial = NULL;
	EVP_PKEY *caPrivkey, *reqPubkey;
	EVP_MD const *digest = NULL;
	long validSecs = 31536000;
	
	// bio 생성
	outBio = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	// csr 파일 읽기
	assert ((fp = fopen(CSR, "r")) != 0);
	assert ((certReq = PEM_read_X509_REQ(fp, NULL, NULL, NULL)) != 0);
	fclose(fp);

	// CA 인증서 읽기
	assert ((fp = fopen(CACERT, "r")) != 0);
	assert ((caCert = PEM_read_X509(fp, NULL, NULL, NULL)) != 0);
	fclose(fp);
	
	// CA 비밀키 읽기
	caPrivkey = EVP_PKEY_new();
	assert ((fp = fopen(CAKEY, "r")) != 0);
	assert ((caPrivkey = PEM_read_PrivateKey(fp, NULL, NULL, PASS)) != 0);
	fclose(fp);
	
	// 인증서 생성
	assert ((newCert = X509_new()) != 0);
	assert (X509_set_version(newCert, 2) == 1);		// 버전 세팅
	
	// serial number 세팅
	serial = ASN1_INTEGER_new();
	ASN1_INTEGER_set(serial, 0);
	assert (X509_set_serialNumber(newCert, serial) != 0);
	
	// csr로부터 subject name 읽고 인증서 세팅
	assert ((name = X509_REQ_get_subject_name(certReq)) != 0);
	// 인증서에 subject name 설정
	assert (X509_set_subject_name(newCert, name) == 1);
	
	// CA 인증서로부터 subject 읽어서
	assert ((name = X509_get_subject_name(caCert)) != 0);
	// 인증서의 생성자 이름 (issuer name)을 세팅
	assert (X509_set_issuer_name(newCert, name) == 1);
	
	// csr로부터 공개키 값을 얻어서
	assert ((reqPubkey = X509_REQ_get_pubkey(certReq)) != 0);
	// csr의 서명을 검증
	if (X509_REQ_verify(certReq, reqPubkey) != 1) {
		BIO_printf(outBio, "Error verifying signature request\n");
		exit - 1;
	}
	
	// 인증서의 공개키 값을 세팅
	assert (X509_set_pubkey(newCert, reqPubkey) == 1);
	
	// 인증서의 시작 시간 (현재 시간)과 종료 시간(1년 후)을 세트
	assert ((X509_gmtime_adj(X509_get_notBefore(newCert), 0)) != 0);
	assert ((X509_gmtime_adj(X509_get_notAfter(newCert), validSecs)) != 0);
	
	// X509V3 확장부 설정 추가
	// void X509V3_set_ctx(ctx, issuer, subject, req, crl, flags);
	X509V3_set_ctx(&ctx, caCert, newCert, NULL, NULL, 0);
	
	// 새로운 인증서에 서명 (해시는 sha512)
	digest = EVP_sha512();
	assert (X509_sign(newCert, caPrivkey, digest) != 0);
	
	// 출력
	assert (PEM_write_bio_X509(outBio, newCert) != 0);
	
	EVP_PKEY_free(reqPubkey);
	EVP_PKEY_free(caPrivkey);

	X509_REQ_free(certReq);
	X509_free(newCert);

	BIO_free_all(outBio);

	exit(0);
}
