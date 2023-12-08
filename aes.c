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
    unsigned char* signature;
};

int getAESCipherBufferSize() {
    size_t bufferSize = sizeof(int) + sizeof(int) + AES_CIPHERTEXT_BUFFER_SIZE +
                  AES_BLOCK_SIZE + SHA256_DIGEST_LENGTH;
    
    return bufferSize;
}

struct AESCipher AESencrypt(char* message, unsigned char* key){
	unsigned char* ct = malloc(AES_CIPHERTEXT_BUFFER_SIZE);
    unsigned char* iv = generateInitializationVector();

    fprintf(stderr, "Encrypted with IV: ");
    printHex(iv, AES_BLOCK_SIZE);

    fprintf(stderr, "Message: %s\n", message);
	size_t len = strlen(message);
    fprintf(stderr, "Len::::%d\n", len);

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
    fprintf(stderr, "Len during encryption:\n", len);
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
    fprintf(stderr, "Len during decryption:\n", len);

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

    // Allocate memory for the buffer
    unsigned char* buffer = (unsigned char*)malloc(getAESCipherBufferSize());

    // Copy data to the buffer
    unsigned char* ptr = *buffer;

    memcpy(ptr, &(crypto->ciphertextLength), sizeof(int));
    ptr += sizeof(int);

    memcpy(ptr, &(crypto->plaintextLength), sizeof(int));
    ptr += sizeof(int);

    memcpy(ptr, crypto->ciphertext, AES_CIPHERTEXT_BUFFER_SIZE);
    ptr += AES_CIPHERTEXT_BUFFER_SIZE;

    memcpy(ptr, crypto->initializationVector, AES_BLOCK_SIZE);
    ptr += AES_BLOCK_SIZE;

    memcpy(ptr, crypto->signature, SHA_DIGEST_LENGTH);

    return buffer;
}


struct AESCipher convertBufferToStruct(const unsigned char* buffer) {
    struct AESCipher crypto;

    size_t offset = 0; 
    // Read ciphertextLength from the buffer
    memcpy(&(crypto.ciphertextLength), buffer, sizeof(int));
    offset += sizeof(int);

    // Read plaintextLength from the buffer
    memcpy(&(crypto.plaintextLength), buffer + offset, sizeof(int));
    offset += sizeof(int);

    // Allocate memory for the ciphertext array and copy data
    crypto.ciphertext = (unsigned char *)malloc(AES_CIPHERTEXT_BUFFER_SIZE);
    memcpy(crypto.ciphertext, buffer + offset, AES_CIPHERTEXT_BUFFER_SIZE);
    offset += AES_CIPHERTEXT_BUFFER_SIZE;

    // Allocate memory for the initializationVector array and copy data
    crypto.initializationVector = (unsigned char *)malloc(AES_BLOCK_SIZE);
    memcpy(crypto.initializationVector, buffer + offset, AES_BLOCK_SIZE);
    offset += AES_BLOCK_SIZE;

    crypto.signature = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    memcpy(crypto.signature, buffer + offset, SHA256_DIGEST_LENGTH);


    return crypto;
}

