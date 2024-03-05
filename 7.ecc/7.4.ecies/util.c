#include "common.h"

// read peer cert file ('certFileName')
// verify peer cert using 'certCaFileName'
// return parameter: 'certPeer' contains a verified peer cert
void readCertFile (char *certFileName, char *certCaFileName, X509 **certPeer)
{
	BIO *certBio = NULL;

	// read cert from file
	certBio = BIO_new(BIO_s_file());
	BIO_read_filename(certBio, certFileName);
	assert ((*certPeer = PEM_read_bio_X509(certBio, NULL, 0, NULL)) != 0);
	
	verifyCert (*certPeer, certCaFileName);

	BIO_free_all(certBio);
}


// veryfy 'cert' using CA cert ('certFileName')
void verifyCert (X509 *cert, char *certCaFileName)
{
	X509_STORE *store = NULL;
	X509_STORE_CTX *verifyCtx = NULL;
	
	// save CA cert to the store
	assert ((store = X509_STORE_new()) != 0);
	assert ((X509_STORE_load_locations(store, certCaFileName, NULL)) == 1);
	
	// init 'verifyCtx' for the validation of 'cert'
	// 		CA cert stored in 'store'
	verifyCtx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(verifyCtx, store, cert, NULL);
	
	assert (X509_verify_cert(verifyCtx)==1);
	
	X509_STORE_CTX_free(verifyCtx);
	X509_STORE_free(store);
}


void getPubkeyFromCert (EC_POINT **peerPubKey, X509 *certPeer, EC_GROUP *ecg)
{
	EVP_PKEY *pkeyPeer = EVP_PKEY_new();	// for KB 
	OSSL_PARAM *params, *p;

	assert (0 != (pkeyPeer = X509_get0_pubkey(certPeer)));

	assert (1 == (EVP_PKEY_todata(pkeyPeer, EVP_PKEY_PUBLIC_KEY, &params)));
	
	p = OSSL_PARAM_locate (params, "pub");
	assert (1 == EC_POINT_oct2point(ecg, *peerPubKey, p->data, p->data_size, 0));

	EVP_PKEY_free(pkeyPeer);
}


void getPrivFromEvpPkey (BIGNUM **bn, EVP_PKEY *pkey)
{
	//assert (1 == EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, bn));
	assert (1 == EVP_PKEY_get_bn_param(pkey, "priv", bn));
}


/* return: derivedKey
 * 		derivedKey[0 ~ (neededKeyLen-256/8)-1]: Ke
 *		derivedKey[(neededKeyLen-256/8) ~ (neededKeyLen-1)]: Km (Km is HMAC)
 */
void x963kdf (uchar *s, short sLen, uchar *s1, short s1Len, uchar *derivedKey, int neededKeyLen)
{
	EVP_KDF *kdf;
	EVP_KDF_CTX *kctx = NULL;
	OSSL_PARAM params[5], *p = params;
	
	assert (0 != (kdf = EVP_KDF_fetch(NULL, "x963kdf", NULL)));
	assert (0 != (kctx = EVP_KDF_CTX_new(kdf)));
	EVP_KDF_free(kdf);		/* The kctx keeps a reference so this is safe */
	
	/* Build up the parameters for the derivation */ 
	*p++ = OSSL_PARAM_construct_utf8_string("digest", "sha256", (size_t) 7);
	//*p++ = OSSL_PARAM_construct_octet_string("salt", "salt", (size_t) 4);
	*p++ = OSSL_PARAM_construct_octet_string("key", s, (size_t) sLen);
	*p++ = OSSL_PARAM_construct_octet_string("info", s1, (size_t) s1Len);
	*p = OSSL_PARAM_construct_end();
	assert (1 == EVP_KDF_CTX_set_params(kctx, params)); 
	
	/* Do the derivation */ 
	if (1 == EVP_KDF_derive(kctx, derivedKey, neededKeyLen, NULL)); 
	
	/* print key */ 
	const unsigned char *key = derivedKey;
	int tmpLen;
	tmpLen = neededKeyLen - 256/8;
	const unsigned char *km = derivedKey + tmpLen;
	printf("Ke: ");
	for (size_t i = 0; i < tmpLen; ++i)
		printf("%02x ", key[i]);
	printf("\n");
	printf("Km:  ");
	for (size_t i = 0; i < 256/8; ++i)
		printf("%02x ", km[i]);
	printf("\n");
	
	EVP_KDF_CTX_free(kctx);
}


EVP_PKEY * readPrivKey (char *filename, EVP_PKEY **privKey)
{
	FILE *fp;
    char file[128];

    assert ((fp = fopen(filename, "r")) != 0);
    assert (PEM_read_PrivateKey(fp, privKey, 0, 0) != 0);
    fclose (fp);
}


void calSkdf (EC_POINT *ecp, EC_POINT *P, BIGNUM *bn, BN_CTX *ctx, EC_GROUP *ecg,
			unsigned char *derivedKey, size_t msgLen)
{
	unsigned char *key;
		
	assert (1 == EC_POINT_mul(ecg, P, 0, ecp, bn, ctx)); // P = r * Kb
	assert (1 == EC_POINT_get_affine_coordinates(ecg, P, bn, 0, ctx));	// get S (== Px --> bnS)
	assert (0 != (key = OPENSSL_malloc (BN_num_bytes(bn))));
	assert (0 != BN_bn2bin(bn, key));		// save S to 'key' (binary)

	// MAC: HMAC with sha256
	x963kdf (key, BN_num_bytes(bn), S1, strlen(S1), derivedKey, msgLen + 256/8);
	// 		-----------derivedKey-----------
	// 		<---strlen(msg)--->|<---256/8--->
	// 		         Ke				  Km

	OPENSSL_free (key);
}


