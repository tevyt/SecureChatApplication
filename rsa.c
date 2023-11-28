#include <openssl/rsa.h>

#define MAX_BUF_SIZE 4096


unsigned char* encrypt(unsigned char* message, RSA* key){
	size_t messageLength = strlen(message);


    size_t keySize =  RSA_size(key);
    unsigned char* ciphertext = malloc(keySize);

    int ciphertextLength = RSA_public_encrypt(messageLength + 1, message, ciphertext, key, RSA_PKCS1_OAEP_PADDING);

    if(ciphertextLength == -1){
        return NULL;
    }

    return ciphertext;
}

RSA* readPublicKeyFromFile(const char* publicKeyPath) {
    FILE* publicKeyFile = fopen(publicKeyPath, "r");
    if (!publicKeyFile) {
        perror("Error opening public key file");
        return NULL;
    }

    RSA* rsaKey = RSA_new();

    PEM_read_RSA_PUBKEY(publicKeyFile, &rsaKey, NULL, NULL);
    if (!rsaKey) {
        ERR_print_errors_fp(stderr);
        fclose(publicKeyFile);
        return NULL;
    }

    fclose(publicKeyFile);
    return rsaKey;
}


unsigned char* encryptMessage(RSA* publicKey, unsigned char* plainText) {

    int rsaKeySize = RSA_size(publicKey);
    int plainTextLen = strlen(plainText);

    unsigned char* encryptedText = malloc(rsaKeySize);

    int encryptedLen = RSA_public_encrypt(plainTextLen, (const unsigned char*)plainText, encryptedText, publicKey, RSA_PKCS1_PADDING);

    if (encryptedLen == -1) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return encryptedText;
}

// unsigned char* decrypt(unsigned char* ciphertext, RSA* key){
//     unsigned char* decrypted = malloc(RSA_size(key));
//     int len = RSA_private_decrypt(RSA_size(key), ciphertext, decrypted, key, RSA_PKCS1_OAEP_PADDING);
//     if(len == -1){
//         return NULL;
//     }
//     return decrypted;
// }