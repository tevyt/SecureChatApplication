#define SHA256_DIGEST_LENGTH 32

unsigned char* signMessage(unsigned char* plaintext, int plaintextLength, int ciphertextLength, unsigned char* iv);
int verifySignature(unsigned char* plaintext, int plaintextLength, int ciphetextLength, unsigned char* iv, unsigned char* signature);