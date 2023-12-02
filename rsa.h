#define RSA_KEY_LENGTH 256

unsigned char* RSAencrypt(unsigned char* plainText, char* publicKeyPath);
unsigned char* RSAdecrypt(unsigned char* ciphertext, char* privateKeyPath);