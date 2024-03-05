#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

typedef unsigned char uchar;

#define OK 1
#define NOTOK 0


#define CURVE NID_X9_62_prime256v1
#define S1 "This is S1"
#define S2 "This is S2"

#define CERT_RECEIVER	"/home/share/egkim/ecies/certs/newcerts/client.crt.pem"
#define CERT_CA			"/home/share/egkim/ecies/certs/newcerts/ca-cert.pem"

// for Bob's private key (kb)
#define PRIV_KEY		"/home/share/egkim/ecies/certs/private/client.key.pem"

void readCertFile (char *certFileName, char *certCaFileName, X509 **certPeer);
void verifyCert (X509 *cert, char *certCaFileName);
void getPubkeyFromCert (EC_POINT **peerPubKey, X509 *certPeer, EC_GROUP *ecg);
void getPrivFromEvpPkey (BIGNUM **bn, EVP_PKEY *pkey);
void x963kdf (uchar *s, short sLen, uchar *s1, short s1Len, uchar *derivedKey,
				int neededKeyLen);
void encrypt (uchar *msg, size_t msgLen, X509 *certPeer, uchar *R, size_t *RLen,
				uchar *c, uchar *d);
int decrypt (uchar *R, size_t *RLen, uchar *c, size_t cLen, uchar *d, size_t dLen,
				uchar *decMsg, size_t decMsgLen);

EVP_PKEY * readPrivKey (char *filename, EVP_PKEY **privKey);
void calSkdf (EC_POINT *ecp, EC_POINT *P, BIGNUM *bn, BN_CTX *ctx, EC_GROUP *ecg,
				unsigned char *derivedKey, size_t msgLen);



