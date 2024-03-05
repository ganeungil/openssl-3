#include "common.h"
#define MSG "hello world. This is test"


int main(void) {
	X509 *certPeer;
	EC_POINT *G;
	uchar R[256], *c, d[256/8+1], *decMsg;
	size_t RLen = 256;

	readCertFile (CERT_RECEIVER, CERT_CA, &certPeer);

	c = OPENSSL_malloc(strlen(MSG));
	encrypt (MSG, strlen(MSG), certPeer, R, &RLen, c, d);
	printf("encrypted.\n");

	decMsg = OPENSSL_malloc(strlen(MSG));
	if (OK == decrypt(R, &RLen, c, strlen(MSG), d, 256/8+1, decMsg, strlen(MSG)))
		printf("decryption success\n");
	else
		printf("decryption failed\n");

	OPENSSL_free (c);
	OPENSSL_free (decMsg);
}
