#define RSA_KEY_LENGTH 512

unsigned char* RSAencrypt(unsigned char* plainText, char* publicKeyPath);
unsigned char* RSAdecrypt(unsigned char* ciphertext, char* privateKeyPath, int ciphertextLength);