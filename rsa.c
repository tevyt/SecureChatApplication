#include <openssl/rsa.h>
#include "rsa.h"



static RSA* readPublicKeyFromFile(char* publicKeyPath) {
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

static RSA* readPrivateKeyFromFile(char* privateKeyPath) {
    FILE* privateKeyFile = fopen(privateKeyPath, "r");
    if (!privateKeyFile) {
        perror("Error opening private key file");
        return NULL;
    }

    RSA* rsaKey = RSA_new();

    PEM_read_RSAPrivateKey(privateKeyFile, &rsaKey, NULL, NULL);
    if (!rsaKey) {
        ERR_print_errors_fp(stderr);
        fclose(privateKeyFile);
        return NULL;
    }

    fclose(privateKeyFile);
    return rsaKey;
}

unsigned char* RSAencrypt(unsigned char* plainText, char* publicKeyPath){
    RSA* publicKey = readPublicKeyFromFile(publicKeyPath);

    if(publicKey == NULL){
        return NULL;
    }

    size_t plainTextLength = strlen(plainText);

    unsigned char* ciphertext = malloc(RSA_size(publicKey));

    int ciphertextLength = RSA_public_encrypt(plainTextLength + 1, plainText, ciphertext, publicKey, RSA_PKCS1_OAEP_PADDING);

    if(ciphertextLength == -1){
        RSA_free(publicKey);
        free(ciphertext);
        return NULL;
    }

    RSA_free(publicKey);
    return ciphertext;
}

unsigned char* RSAdecrypt(unsigned char* ciphertext, char* privateKeyPath){
    RSA* privateKey = readPrivateKeyFromFile(privateKeyPath);

    if(privateKey == NULL){
        return NULL;
    }

    unsigned char* plaintext = malloc(RSA_size(privateKey));

    int plaintextLength = RSA_private_decrypt(RSA_size(privateKey), ciphertext, plaintext, privateKey, RSA_PKCS1_OAEP_PADDING);

    if(plaintextLength == -1){
        RSA_free(privateKey);
        free(plaintext);
        return NULL;
    }

    RSA_free(privateKey);
    return plaintext;
}


