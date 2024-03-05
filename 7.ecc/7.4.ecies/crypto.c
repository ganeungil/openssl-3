#include "common.h"

/* using ECIES in wiki
 *		https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
 */

/* ecryption: XOR with message
 * MAC: HMAC with sha256
 * return: R , c, d
 *			R is octet string format. !='hex string')
 */
void encrypt (uchar *msg, size_t msgLen, X509 *certPeer, uchar *R, size_t *RLen, uchar *c, uchar *d)
{
	EVP_PKEY *pkeyR = EVP_PKEY_new();
	EC_POINT *peerPubKey, *P;
	EC_GROUP *ecg;
	BIGNUM *bn=BN_new(), *bnS = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	unsigned char *key, *derivedKey;
	
	pkeyR = EVP_EC_gen("prime256v1");
	// public part of pkeyR is R, private part of pkeyR is r (wiki)
	
	assert (0 != (ecg = EC_GROUP_new_by_curve_name(CURVE)));
	peerPubKey = EC_POINT_new(ecg);
	P = EC_POINT_new(ecg);

	getPubkeyFromCert(&peerPubKey, certPeer, ecg);	// Kb = read peerPubKey from peer cert
	getPrivFromEvpPkey (&bn, pkeyR);	// bn --> r in wiki

	assert (0 != (derivedKey = OPENSSL_malloc (msgLen + 256/8)));

	calSkdf (peerPubKey, P, bn, ctx, ecg, derivedKey, msgLen);

	for (int i=0; i<msgLen; i++)	// encrypt
		*(c+i) = *(msg+i) ^ *(derivedKey+i);
	assert (0 != HMAC(EVP_sha256(), derivedKey+msgLen, 256/8, c, msgLen, d, 0));	// MAC

	// finally get return values
	//assert (1 == EVP_PKEY_get_octet_string_param(pkeyR, OSSL_PKEY_PARAM_PUB_KEY, R, 256, RLen));
	assert (1 == EVP_PKEY_get_octet_string_param(pkeyR, "pub", R, 256, RLen));
	

	EVP_PKEY_free (pkeyR);
	EC_POINT_free (peerPubKey);
	EC_POINT_free (P);
	EC_GROUP_free(ecg);
	BN_free (bn);
	BN_free (bnS);
	BN_CTX_free(ctx);
	OPENSSL_free(key);
	OPENSSL_free(derivedKey);
}

// input: R, c, d
//			R is octet string format
// return	OK if verify success
// 			NOTOK if verify fail
int decrypt (uchar *R, size_t *RLen, uchar *c, size_t cLen, uchar *d, size_t dLen,
					uchar *decMsg, size_t decMsgLen)
{
	EC_GROUP *ecg;
	EC_POINT *Rpoint, *P;
	EVP_PKEY *privKey;
	BIGNUM *bnKb=BN_new(), *bnS=BN_new();
	BN_CTX *ctx = BN_CTX_new();
	unsigned char *derivedKey, mac[256/8+1];

	assert (0 != (ecg = EC_GROUP_new_by_curve_name(CURVE)));
	Rpoint = EC_POINT_new(ecg);
	P = EC_POINT_new(ecg);

	assert (1 == EC_POINT_oct2point(ecg, Rpoint, R, *RLen, ctx));
	privKey = EVP_PKEY_new();
	readPrivKey (PRIV_KEY, &privKey);
	getPrivFromEvpPkey(&bnKb, privKey);
	
	assert (0 != (derivedKey = OPENSSL_malloc (cLen + 256/8)));
	calSkdf (Rpoint, P, bnKb, ctx, ecg, derivedKey, cLen);
	
	for (int i=0; i<cLen; i++)	// decrypt
		*(decMsg+i) = *(c+i) ^ *(derivedKey+i);
	assert (0 != HMAC(EVP_sha256(), derivedKey+cLen, 256/8, c, cLen, mac, 0));	// MAC

	EC_GROUP_free(ecg);
	EC_POINT_free(Rpoint);
	EC_POINT_free(P);
	EVP_PKEY_free (privKey);
	BN_free (bnKb);
	BN_free (bnS);
	BN_CTX_free(ctx);
	OPENSSL_free(derivedKey);

	// verify mac code
	for (int i=0; i<256/8; i++)
		if (*(mac+i) != *(d+i))
			return (NOTOK);

	return (OK);
}

