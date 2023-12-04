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

	EVP_CIPHER_CTX_free(ctx);
    return pt;
}

unsigned char* convertStructToBuffer(const struct AESCipher *crypto) {
    // Calculate the total size needed for the buffer
    size_t bufferSize = sizeof(int) + sizeof(int) + 512;

    // Allocate memory for the buffer
    unsigned char *buffer = (unsigned char *)malloc(bufferSize);
    if (buffer == NULL) {
        // Handle memory allocation failure
        return NULL;
    }

    // Copy the struct members to the buffer
    size_t offset = 0;

    // Copy ciphertextLength to the buffer
    memcpy(buffer + offset, &(crypto->ciphertextLength), sizeof(int));
    offset += sizeof(int);

    // Copy plaintextLength to the buffer
    memcpy(buffer + offset, &(crypto->plaintextLength), sizeof(int));
    offset += sizeof(int);

    // Copy ciphertext to the buffer
    memcpy(buffer + offset, crypto->ciphertext, crypto->ciphertextLength);

    return buffer;
}


struct AESCipher convertBufferToStruct(const unsigned char* buffer) {
    struct AESCipher crypto;

    // Read ciphertextLength from the buffer
    memcpy(&(crypto.ciphertextLength), buffer, sizeof(int));
    buffer += sizeof(int);

    // Read plaintextLength from the buffer
    memcpy(&(crypto.plaintextLength), buffer, sizeof(int));
    buffer += sizeof(int);

    // Allocate memory for the ciphertext array and copy data
    crypto.ciphertext = (unsigned char *)malloc(512);
    memcpy(crypto.ciphertext, buffer, 512);

    return crypto;
}

