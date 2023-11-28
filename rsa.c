#include <openssl/rsa.h>

unsigned char* encrypt(unsigned char* message, RSA* key){
    unsigned char* encrypted = malloc(RSA_size(key));
    int len = RSA_public_encrypt(strlen(message), (unsigned char*)message, encrypted, key, RSA_PKCS1_OAEP_PADDING);
    if(len == -1){
        return NULL;
    }
    return encrypted;
}

// unsigned char* decrypt(unsigned char* ciphertext, RSA* key){
//     unsigned char* decrypted = malloc(RSA_size(key));
//     int len = RSA_private_decrypt(RSA_size(key), ciphertext, decrypted, key, RSA_PKCS1_OAEP_PADDING);
//     if(len == -1){
//         return NULL;
//     }
//     return decrypted;
// }