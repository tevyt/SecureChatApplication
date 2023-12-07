#define AES_KEY_LENGTH 32
#define AES_BLOCK_SIZE 16
#define AES_CIPHERTEXT_BUFFER_SIZE 512


unsigned char* generateAESKey();
unsigned char* generateInitializationVector();
struct AESCipher AESencrypt(char* message, unsigned char* key);
unsigned char* AESdecrypt(struct AESCipher aesCipher, unsigned char* key);