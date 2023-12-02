#include <openssl/rand.h>
#include "aes.h"

unsigned char* generateAESKey(){

    unsigned char* key = malloc(AES_KEY_LENGTH);

    if(RAND_bytes(key, AES_KEY_LENGTH) != 1){
        free(key);

        return NULL;
    }
    return key;
 }