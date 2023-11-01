#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

// (chained) cert. for CA
#define CERT_CA "./ca-cert.pem"
	
// cert. for verification
#define CERT4VRFY "./client.crt.pem"

int main()
{
    BIO *certBio = NULL;
    BIO *outBio = NULL;
    X509 *errorCert = NULL;
    X509 *cert = NULL;
    X509_NAME *certSubject = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verifyCertCtx = NULL;
    int ret;

    // 검증할 인증서 읽기
    certBio = BIO_new(BIO_s_file());
    BIO_read_filename(certBio, CERT4VRFY);
    if (!(cert = PEM_read_bio_X509(certBio, NULL, 0, NULL))) {
        BIO_printf(outBio, "Error loading cert into memory\n");
        exit(-1);
    }

    outBio = BIO_new_fp(stdout, BIO_NOCLOSE);

    // X509_STORE에는 상대방 인증서 검증을 위한 CA의 공개키(인증서)를 저장
    assert ((store = X509_STORE_new()) != 0);
    // CA 인증서를 읽어서 store에 저장
    ret = X509_STORE_load_locations(store, CERT_CA, NULL);
    if (ret != 1)
        BIO_printf(outBio, "Error loading CA cert or chain file\n");

    // 인증서 “cert” 검증을 위하여 “verifyCertCtx”를 초기화.
    //      CA 인증서는 store에 저장되어 있음.
    // 각 인증서 검증시마다 호출하여야 함.
    verifyCertCtx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(verifyCertCtx, store, cert, NULL);

    // 성공시 1, 실패시 0을 리턴
    ret = X509_verify_cert(verifyCertCtx);
    BIO_printf(outBio, "Verification return code: %d\n", ret);
    if (ret == 0 || ret == 1)
        BIO_printf(outBio, "Verification result text: %s\n",
            X509_verify_cert_error_string(X509_STORE_CTX_get_error (verifyCertCtx)));

    // 실패시
    if (ret == 0) {
        // 실패한 인증서를 가져와서 출력
        errorCert = X509_STORE_CTX_get_current_cert(verifyCertCtx);
        certSubject = X509_get_subject_name(errorCert);

        BIO_printf(outBio, "Verification failed cert:\n");
        X509_NAME_print_ex(outBio, certSubject, 0, XN_FLAG_MULTILINE);
        BIO_printf(outBio, "\n");
    }
	
    // free all
    X509_STORE_CTX_free(verifyCertCtx);
    X509_STORE_free(store);
    BIO_free_all(certBio);
    BIO_free_all(outBio);

    exit(0);
}
