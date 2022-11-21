#include <stdio.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define CLIENT_PRIV "client.key.pem"
#define X509FILE "x509Req.pem"
#define PASS "password"		// password for client priv file

int genX509Req() 
{
	FILE * fp;
	int ret = 0, nVersion = 0, bits = 2048;
	BIGNUM * bne = NULL;
	X509_REQ *x509Req = NULL;
	X509_NAME *x509Name = NULL;
	EVP_PKEY *pKey = NULL;
	BIO * out = NULL, *bio_err = NULL;
	const char *szCountry = "CA";
	const char *szProvince = "BC";
	const char *szCity = "Daejeon";
	const char *szOrganization = "Hanbat univ";
	const char *szCommon =
		"Deptartmemt of information and communication engineering";
	const char *szPath = X509FILE;
	
	// pKey에 클라이언트 비밀키 읽기
	assert((fp = fopen(CLIENT_PRIV, "r")) != 0);
	assert(PEM_read_PrivateKey(fp, &pKey, NULL, PASS) != 0);
	fclose(fp);
	
	// empty csr 생성 및 버전 설정
	x509Req = X509_REQ_new();
	assert((ret = X509_REQ_set_version(x509Req, nVersion)) == 1);
	
	// 인증서에 subject 설정 (x509 req)
    // x509Name = x509Req 내부의 subject name 주소
	x509Name = X509_REQ_get_subject_name(x509Req);
	assert (X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC, 
				  (const unsigned char *) szCountry, -1, -1, 0) == 1);
	assert (X509_NAME_add_entry_by_txt(x509Name, "ST", MBSTRING_ASC, 
				  (const unsigned char *) szProvince, -1, -1, 0) == 1);
	assert (X509_NAME_add_entry_by_txt(x509Name, "L", MBSTRING_ASC, 
				  (const unsigned char *) szCity, -1, -1, 0) == 1);
	assert (X509_NAME_add_entry_by_txt(x509Name, "O", MBSTRING_ASC, 
				(const unsigned char *) szOrganization, -1, -1, 0) == 1);
	assert (X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC, 
				(const unsigned char *) szCommon, -1, -1, 0) == 1);
	
    // csr (x509Req)에 공개키 설정
	assert((ret = X509_REQ_set_pubkey(x509Req, pKey)) == 1);
	
	// pKey의 비밀키로 x509Req에 서명 (EVP_sha512 알고리즘)
	assert((ret = X509_REQ_sign(x509Req, pKey, EVP_sha512())) > 0);

	// csr (x509Req) 출력
	out = BIO_new_file(szPath, "w");
	ret = PEM_write_bio_X509_REQ(out, x509Req);
	
	// free
	X509_REQ_free(x509Req);
	BIO_free_all(out);
	EVP_PKEY_free(pKey);
	BN_free(bne);

	return (ret == 1);
}

int main(int argc, char *argv[]) 
{
	genX509Req();
	return 0;
}
