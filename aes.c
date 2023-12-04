#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "aes.h"

static unsigned char* generateRandomBytes(int numberOfBytes){
    unsigned char* bytes = malloc(numberOfBytes);

    if(RAND_bytes(bytes, numberOfBytes) != 1){
        free(bytes);
        return NULL;
    }
    return bytes;
}

unsigned char* generateAESKey(){
    return generateRandomBytes(AES_KEY_LENGTH);
}

unsigned char* generateInitializationVector(){
    return generateRandomBytes(AES_BLOCK_SIZE);
}


struct AESCipher {
    unsigned char* ciphertext;
    int ciphertextLength;
    int plaintextLength;
};

struct AESCipher AESencrypt(char* message, unsigned char* key, unsigned char* iv){
	unsigned char* ct = malloc(512);

	size_t len = strlen(message);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);

	int nWritten; /* stores number of written bytes (size of ciphertext) */

	if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message,len))
		ERR_print_errors_fp(stderr);

	EVP_CIPHER_CTX_free(ctx);

	size_t ctlen = nWritten;

    struct AESCipher aesCipher;
    aesCipher.ciphertext = ct;
    aesCipher.ciphertextLength = ctlen;
    aesCipher.plaintextLength = len;

    return aesCipher;
}

unsigned char* AESdecrypt(struct AESCipher aesCipher, unsigned char* key, unsigned char* iv){
    unsigned char* pt = malloc(512);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    int nWritten = aesCipher.ciphertextLength;
    int len = aesCipher.plaintextLength;
    unsigned char* ct = aesCipher.ciphertext;

	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);

	for (size_t i = 0; i < len; i++) {
		if (1!=EVP_DecryptUpdate(ctx,pt+i,&nWritten,ct+i,1))
			ERR_print_errors_fp(stderr);
	}

	printf("decrypted %lu bytes:\n%s\n",len,pt);
	EVP_CIPHER_CTX_free(ctx);
    return pt;
}

/* demonstrates AES in counter mode */
void testAES(unsigned char* key, unsigned char* iv, char* message)
{
	unsigned char ct[512];
	unsigned char pt[512];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,512);
	size_t len = strlen(message);
	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	int nWritten; /* stores number of written bytes (size of ciphertext) */
	if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message,len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	size_t ctlen = nWritten;
	printf("ciphertext of length %i:\n",nWritten);
	for (int i = 0; i < ctlen; i++) {
		printf("%02x",ct[i]);
	}
	printf("\n");
	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work.  Also
	 * note that it is crucial to make sure IVs are not reused.  */
	/* wipe out plaintext to be sure it worked: */
	memset(pt,0,512);
	ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	for (size_t i = 0; i < len; i++) {
		if (1!=EVP_DecryptUpdate(ctx,pt+i,&nWritten,ct+i,1))
			ERR_print_errors_fp(stderr);
	}
	printf("decrypted %lu bytes:\n%s\n",len,pt);
	EVP_CIPHER_CTX_free(ctx);
	/* NOTE: counter mode will preserve the length (although the person
	 * decrypting needs to know the IV) */
}

