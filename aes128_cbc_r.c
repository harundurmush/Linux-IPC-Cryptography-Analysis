// AES_reader.c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define FIFO_FILE "myfifo_aes"
#define MAX_SIZE 256 // maximum message size
#define MAX_KEY_SIZE_MODE 256
#define MAX_IV_SIZE_MODE 256

void append_to_csv(const char *filename, long double value){
    FILE *fp = fopen(filename, "a");
    if (!fp){
        ERR_print_errors_fp(stderr);
    }

    fprintf(fp, "%Lf\n", value);

    fclose(fp);
}

int main(){
    long double start_rsa_dec_time, end_rsa_dec_time, start_aes_dec_time, end_aes_dec_time, elapsed_rsa_dec_time, elapsed_aes_dec_time, total_duration_1, total_duration_2, total_duration_3, total_duration_4, total_duration_5, total_duration_6, total_duration_all;
    total_duration_all = 0;
    total_duration_1 = clock();

    // Initializing OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    int fd;
    int plaintext_len, final_len;

    unsigned char received_key[MAX_KEY_SIZE_MODE];
    unsigned char received_iv[MAX_IV_SIZE_MODE];
    unsigned char received_message[MAX_SIZE];
    unsigned char decrypted_message[MAX_SIZE];

    const char *filename_1 = "tables/td_rsakey_dec_aes_128cbc_reader.csv";
    const char *filename_2 = "tables/td_dec_aes_128cbc_reader.csv";
    const char *filename_3 = "tables/td_aes_128cbc_reader.csv";

    memset(received_message, 0, MAX_SIZE);
    memset(decrypted_message, 0, MAX_SIZE);

    // Loading the private key 1
    FILE* privKeyFile_key = fopen("private.pem", "rb");
    if (!privKeyFile_key) ERR_print_errors_fp(stderr);
    EVP_PKEY* privKey_key = PEM_read_PrivateKey(privKeyFile_key, NULL, NULL, NULL);
    fclose(privKeyFile_key);
    if (!privKey_key) ERR_print_errors_fp(stderr);

    // Loading the private key 2
    FILE* privKeyFile_iv = fopen("private2.pem", "rb");
    if (!privKeyFile_iv) ERR_print_errors_fp(stderr);
    EVP_PKEY* privKey_iv = PEM_read_PrivateKey(privKeyFile_iv, NULL, NULL, NULL);
    fclose(privKeyFile_iv);
    if (!privKey_iv) ERR_print_errors_fp(stderr);

    // Encrypted key and iv from the writer
    size_t received_key_len = sizeof(received_key);
    size_t received_iv_len = sizeof(received_iv);
    size_t received_message_len = strlen(received_message);
    size_t decrypted_key_len, decrypted_iv_len, decrypted_message_len;

    fd = open(FIFO_FILE, O_RDONLY);
    if (fd == -1) ERR_print_errors_fp(stderr);

    total_duration_2 = clock();
    total_duration_all = (total_duration_2 - total_duration_1)/CLOCKS_PER_SEC + total_duration_all;

    if (read(fd, received_key, sizeof(received_key)) == -1){ 
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    if (read(fd, received_iv, sizeof(received_iv)) == -1){ 
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    total_duration_3 = clock();

    start_rsa_dec_time = clock();

    EVP_PKEY_CTX* ctx_rsa_key = EVP_PKEY_CTX_new(privKey_key, NULL);
    if (!ctx_rsa_key) ERR_print_errors_fp(stderr);
    if (EVP_PKEY_decrypt_init(ctx_rsa_key) <= 0) ERR_print_errors_fp(stderr);

    EVP_PKEY_CTX* ctx_rsa_iv = EVP_PKEY_CTX_new(privKey_iv, NULL);
    if (!ctx_rsa_iv) ERR_print_errors_fp(stderr);
    if (EVP_PKEY_decrypt_init(ctx_rsa_iv) <= 0) ERR_print_errors_fp(stderr);

    if (EVP_PKEY_decrypt(ctx_rsa_key, NULL, &decrypted_key_len, received_key, received_key_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);
    if (EVP_PKEY_decrypt(ctx_rsa_iv, NULL, &decrypted_iv_len, received_iv, received_iv_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);

    unsigned char* decrypted_key = malloc(decrypted_key_len);
    unsigned char* decrypted_iv = malloc(decrypted_iv_len);

    if (EVP_PKEY_decrypt(ctx_rsa_key, decrypted_key, &decrypted_key_len, received_key, received_key_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);
    if (EVP_PKEY_decrypt(ctx_rsa_iv, decrypted_iv, &decrypted_iv_len, received_iv, received_iv_len) <= 0) ERR_print_errors_fp(stderr);  
    //sleep(2);

    end_rsa_dec_time = clock();

    elapsed_rsa_dec_time = (end_rsa_dec_time - start_rsa_dec_time)/CLOCKS_PER_SEC;

    // Printing key and iv on terminal (will be deleted after)
    printf("Received key is: ");
    for(int i=0; i<received_key_len;i++){
        printf("%02X ", received_key[i]);
    }
    printf("\n\n");
    //sleep(2);
    printf("Received iv is: ");
    for(int i=0; i<received_iv_len;i++){
        printf("%02X ", received_iv[i]);
    }
    printf("\n\n");
    //sleep(2);
    printf("Decrypted key is: ");
    for(int i=0; i<decrypted_key_len;i++){
        printf("%02X ", decrypted_key[i]);
    }
    printf("\n\n");
    //sleep(2);
    printf("Decrypted iv is: ");
    for(int i=0; i<decrypted_iv_len;i++){
        printf("%02X ", decrypted_iv[i]);
    }
    printf("\n\n");
    //sleep(2);
    
    // AES Decryption

    EVP_CIPHER_CTX *ctx_aes = EVP_CIPHER_CTX_new();

    if (!ctx_aes) {
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }
    
    total_duration_4 = clock();
    total_duration_all = (total_duration_4 - total_duration_3)/CLOCKS_PER_SEC + total_duration_all;

    int len = read(fd, received_message, sizeof(received_message));

    total_duration_5 = clock();

    if (len > 0){
        //if (len>0){
        printf("Received text: ");
        for(int i = 0; i < sizeof(received_message); i++)
            printf("%X%X ", (received_message[i] >> 4) & 0xf, received_message[i] & 0xf);
        printf("\n\n");
        
        start_aes_dec_time = clock();

        /*
        // For AES-128 (in ECB mode)
        if (!EVP_DecryptInit_ex(ctx_aes, EVP_aes_128_ecb(), NULL, decrypted_key, decrypted_iv)) {
            ERR_print_errors_fp(stderr);
            close(fd);
        }
        */
        /***************************************************/
        /*
        // For AES-192 (in ECB mode)
        if (!EVP_DecryptInit_ex(ctx_aes, EVP_aes_192_ecb(), NULL, decrypted_key, decrypted_iv)) {
            ERR_print_errors_fp(stderr);
            close(fd);
        }
        */
        /***************************************************/
        /*
        // For AES-256 (in ECB mode)
        if (!EVP_DecryptInit_ex(ctx_aes, EVP_aes_256_ecb(), NULL, decrypted_key, decrypted_iv)) {
            ERR_print_errors_fp(stderr);
            close(fd);
        }
        */
        /***************************************************/
        
        // For AES-128 (in CBC mode)
        if (!EVP_DecryptInit_ex(ctx_aes, EVP_aes_128_cbc(), NULL, decrypted_key, decrypted_iv)) {
            ERR_print_errors_fp(stderr);
        }
        
        /***************************************************/
        /*
        // For AES-192 (in CBC mode)
        if (!EVP_DecryptInit_ex(ctx_aes, EVP_aes_192_cbc(), NULL, decrypted_key, decrypted_iv)) {
            ERR_print_errors_fp(stderr);
            close(fd);
        }
        */
        /***************************************************/
        /*
        // For AES-256 (in CBC mode)
        if (!EVP_DecryptInit_ex(ctx_aes, EVP_aes_256_cbc(), NULL, decrypted_key, decrypted_iv)) {
            ERR_print_errors_fp(stderr);
            close(fd);
        }
        */

        if (!EVP_DecryptUpdate(ctx_aes, decrypted_message, &plaintext_len, received_message, len)) {
            ERR_print_errors_fp(stderr);
        }

        if (!EVP_DecryptFinal_ex(ctx_aes, decrypted_message + plaintext_len, &final_len)) {
            ERR_print_errors_fp(stderr);
        }
        
        plaintext_len += final_len;

        decrypted_message[plaintext_len] = '\0'; // Ensure null terminator to treat as C string

        end_aes_dec_time = clock();

        elapsed_aes_dec_time = (end_aes_dec_time - start_aes_dec_time)/CLOCKS_PER_SEC;

        printf("Length of the message: %d\n\n",plaintext_len);
        printf("Decrypted plain-text: %s\n\n", decrypted_message);

        printf("RSA Key Decryption Duration: %Lf us.\n\n", elapsed_rsa_dec_time*1000000);
        printf("AES Decryption Duration: %Lf us.\n\n", elapsed_aes_dec_time*1000000);
    }

    EVP_CIPHER_CTX_free(ctx_aes);
    EVP_PKEY_free(privKey_key);
    EVP_PKEY_free(privKey_iv);
    EVP_PKEY_CTX_free(ctx_rsa_key);
    EVP_PKEY_CTX_free(ctx_rsa_iv);
    free(decrypted_key);
    free(decrypted_iv);
    EVP_cleanup();
    ERR_free_strings();
    close(fd);

    total_duration_6 = clock();
    total_duration_all = (total_duration_6 - total_duration_5)/CLOCKS_PER_SEC + total_duration_all;
    printf("Total Duration: %Lf us.\n\n", total_duration_all*1000000);

    append_to_csv(filename_1, elapsed_rsa_dec_time*1000000);
    append_to_csv(filename_2, elapsed_aes_dec_time*1000000);
    append_to_csv(filename_3, total_duration_all*1000000);

    return 0;
}