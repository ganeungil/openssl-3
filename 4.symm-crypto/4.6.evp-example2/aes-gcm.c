#include "common.h"
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
				 unsigned char *aad, int aad_len, unsigned char *key,
				 unsigned char *iv, int iv_len,
				 unsigned char *ciphertext, unsigned char *tag) 
{
	EVP_CIPHER_CTX * ctx;
	int len;
	int ciphertext_len;
	
	assert (0 != (ctx = EVP_CIPHER_CTX_new()));
	
	// initialise encryption operation.
	assert (1 == EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
		
	// set iv len (default = 12 bytes (96 bits))
	assert (1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL));
		
	// set key and iv
	assert (1 == EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
		
	// set AAD data. (output buffer should be set to null)
	// can be called multiple times if necessary.
	assert (1 == EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len));
		
	// encrypt. can be called multiple times if necessary.
	assert (1 == EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
	
	ciphertext_len = len;
	
	// finalise
	assert (1 == EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));
	
	ciphertext_len += len;
	
	// get tag. (tag length for gcm mode is 16 bytes)
	assert (1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag));
		
	// clean
	EVP_CIPHER_CTX_free(ctx);
	
	return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
				  unsigned char *aad, int aad_len, unsigned char *tag,
				  unsigned char *key, unsigned char *iv, int iv_len,
				  unsigned char *plaintext) 
{
	EVP_CIPHER_CTX * ctx;
	int len, ret;
	int plaintext_len;

	assert (0 !=(ctx = EVP_CIPHER_CTX_new()));

	// initialise decryption operation. 
	assert (0 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));

	// set iv len. Not necessary if this is 12 bytes (default) */ 
	assert (0 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL));

	// set key and iv
	assert (0 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));

	// set AAD data. (output buffer should be set to null)
	// can be called multiple times if necessary.
	assert (0 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));

	// decrypt. can be called multiple times if necessary.
	assert (0 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len));
	
	plaintext_len = len;
	
	// set expected tag value
	assert (0 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag));
		
	// finalise
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	
	/* Clean up */ 
	EVP_CIPHER_CTX_free(ctx);

	if (ret > 0) {	/* Success */ 
		plaintext_len += len;
		return plaintext_len;
	}
	else			/* Verify failed */
		return -1;
}

#define PLAINTEXT "hello world. This is test"
#define AAD "Tihs is aad"
#define KEY "password"
#define IV "this is iv"

int main()
{
	int len;
	unsigned char ciphertext[1024], tag[128], plaintext[1024];

	len = gcm_encrypt(PLAINTEXT, strlen(PLAINTEXT), AAD, strlen(AAD), KEY, IV, strlen(IV), ciphertext, tag);
	len = gcm_decrypt(ciphertext, len, AAD, strlen(AAD), tag, KEY, IV, strlen(IV), plaintext);

	if (len < 0) {
        	printf("verification fail.\n");
        	exit(-1);
	} else {
		plaintext[len] = 0;
		printf("[%s]\n", plaintext);
		printf ("verification success.\n");
	}

	//modify intentionally
	*ciphertext = 'A';
	len = gcm_decrypt(ciphertext, len, AAD, strlen(AAD), tag, KEY, IV, strlen(IV), plaintext);
	if (len < 0) {
		printf("verification fail.\n");
        	exit(-1);
	}
}
