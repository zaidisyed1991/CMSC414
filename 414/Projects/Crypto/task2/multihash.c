#include <inttypes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t byte;

int get_file_size(FILE *fd){
    fseek(fd, 0L, SEEK_END);
    int ret = ftell(fd);
    fseek (fd, 0, SEEK_SET);

    return ret;
}

int main(int argc, char *argv[]){
    if (argc != 5)
        return 1;

    const char* ALG = argv[1];

    OpenSSL_add_all_digests();
    const EVP_MD *hash = EVP_get_digestbyname(ALG);
    if (hash == NULL)
        return 1;

    int times;

    if (sscanf(argv[2], "%d", &times) != 1)
        return 1;

    if (times < 1){
        return 1;
    }

    FILE *salt_f = fopen(argv[3], "rb"),
         *message_f = fopen(argv[4], "rb");


    if (!salt_f || !message_f)
        return 1;
    

    int SALT_SIZE = get_file_size(salt_f),
        MESSAGE_SIZE = get_file_size(message_f);

    unsigned char *buffer = calloc(sizeof(unsigned char), SALT_SIZE + MESSAGE_SIZE);
    if(buffer){
        fread (buffer, 1, SALT_SIZE, salt_f);
        fread (buffer + SALT_SIZE, 1, MESSAGE_SIZE, message_f);
        fclose(salt_f);
        fclose(message_f);
    } else {
        fclose(salt_f);
        fclose(message_f);
        return 1;
    }
    

    const int HASH_SIZE = EVP_MD_size(hash);
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

    byte *prev_hash = calloc(1, HASH_SIZE),
         *curr_hash = calloc(1, HASH_SIZE);

    EVP_DigestInit_ex(ctx, hash, NULL);
    EVP_DigestUpdate(ctx, buffer, MESSAGE_SIZE + SALT_SIZE);
    EVP_DigestFinal_ex(ctx, curr_hash, NULL);

    for(int i=1 ; i<times ; i++){
        prev_hash = curr_hash;
        EVP_DigestInit_ex(ctx, hash, NULL);
        EVP_DigestUpdate(ctx, prev_hash, HASH_SIZE);
        EVP_DigestFinal_ex(ctx, curr_hash, NULL);
    }

    for(int i=0 ; i<HASH_SIZE; i++){
        printf("%x", *(curr_hash + i));
    }
    
    EVP_MD_CTX_destroy(ctx);

    free(buffer);

    return 0;

}