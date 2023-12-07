#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "aes.h"
#include "logging.h"
#include "logging.c"

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
    unsigned char* initializationVector;
};

int getAESCipherBufferSize() {
    size_t bufferSize = 2 * sizeof(int) + AES_CIPHERTEXT_BUFFER_SIZE + AES_BLOCK_SIZE;

    return bufferSize;
}

struct AESCipher AESencrypt(char* message, unsigned char* key){
	unsigned char* ct = malloc(AES_CIPHERTEXT_BUFFER_SIZE);
    unsigned char* iv = generateInitializationVector();

    fprintf(stderr, "Encrypted with IV: ");
    printHex(iv, AES_BLOCK_SIZE);

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
    aesCipher.initializationVector = iv;

    return aesCipher;
}

unsigned char* AESdecrypt(struct AESCipher aesCipher, unsigned char* key){
    unsigned char* pt = malloc(AES_CIPHERTEXT_BUFFER_SIZE);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    int nWritten = aesCipher.ciphertextLength;
    int len = aesCipher.plaintextLength;
    unsigned char* ct = aesCipher.ciphertext;
    unsigned char* iv = aesCipher.initializationVector;

    fprintf(stderr, "Decrypted with IV: ");
    printHex(iv, AES_BLOCK_SIZE);


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
    size_t bufferSize = getAESCipherBufferSize();

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
    offset += AES_CIPHERTEXT_BUFFER_SIZE;

    //Copy initializationVector to the buffer
    memcpy(buffer + offset, crypto->initializationVector, AES_BLOCK_SIZE);

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
    crypto.ciphertext = (unsigned char *)malloc(AES_CIPHERTEXT_BUFFER_SIZE);
    memcpy(crypto.ciphertext, buffer, AES_CIPHERTEXT_BUFFER_SIZE);
    buffer += AES_CIPHERTEXT_BUFFER_SIZE;

    // Allocate memory for the initializationVector array and copy data
    crypto.initializationVector = (unsigned char *)malloc(AES_BLOCK_SIZE);
    memcpy(crypto.initializationVector, buffer, AES_BLOCK_SIZE);


    return crypto;
}

