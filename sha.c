#include <openssl/sha.h>
#include "sha.h"
#include "aes.h"
/* demonstrates hashing (SHA family) */
void sha_example()
{
	/* hash a string with sha256 */ char* message = "this is a test message :D"; unsigned char hash[32]; /* change 32 to 64 if you use sha512 */
	SHA256((unsigned char*)message,strlen(message),hash);
	for (size_t i = 0; i < 32; i++) {
		printf("%02x",hash[i]);
	}
	printf("\n");
	/* you can check that this is correct by running
	 * $ echo -n 'this is a test message :D' | sha256sum */
}


unsigned char* signMessage(unsigned char* plaintext, int plaintextLength, int ciphertextLength, unsigned char* iv){
    size_t bufferSize = plaintextLength + 2 * sizeof(int) + AES_BLOCK_SIZE;
    unsigned char* buffer = malloc(bufferSize);

    size_t offset = 0;
    memcpy(buffer, &plaintextLength, sizeof(int));
    offset += sizeof(int);

    memcpy(buffer + offset, &ciphertextLength, sizeof(int));
    offset += sizeof(int);

    memcpy(buffer + offset, plaintext, plaintextLength);
    offset += plaintextLength;

    memcpy(buffer + offset, iv, AES_BLOCK_SIZE);

    unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
    
    return SHA256(buffer, bufferSize, hash);
}

int verifySignature(unsigned char* plaintext, int plaintextLength, int ciphertextLength, unsigned char* iv, unsigned char* signature){
    unsigned char* hash = signMessage(plaintext, plaintextLength, ciphertextLength, iv);

    return memcmp(hash, signature, SHA256_DIGEST_LENGTH) == 0;
}