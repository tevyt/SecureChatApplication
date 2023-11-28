#include <openssl/rand.h>
#include "session-key.h"

int generate_session_key(unsigned char* key){
    if(RAND_bytes(key, SESSION_KEY_LEN) != 1){
        return 1;
    }
    return 0;
 }