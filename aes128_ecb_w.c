// AES_writer.c
#include <fcntl.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define FIFO_FILE "myfifo_aes"
#define MAX_SIZE 256 // maximum message size

void append_to_csv(const char *filename, long double value){
    FILE *fp = fopen(filename, "a");
    if (!fp){
        ERR_print_errors_fp(stderr);
    }

    fprintf(fp, "%Lf\n", value);

    fclose(fp);
}

int main(){
    long double start_rsa_enc_time, end_rsa_enc_time, start_aes_enc_time, end_aes_enc_time, elapsed_rsa_enc_time, elapsed_aes_enc_time, total_duration_1, total_duration_2, total_duration_3, total_duration_4, total_duration_5, total_duration_6, total_duration_all;
    
    total_duration_all = 0;
    total_duration_1 = clock();

    // For AES-128
    // unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    
    /***************************************************/
    /*
    // For AES-192
    unsigned char key[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    */
    /***************************************************/
    /*
    // For AES-256 
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    */

    // For CBC mode
    // unsigned char iv[16] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};

    int fd;
    int len;
    int aes_len;
    char basemsg[MAX_SIZE] = "This is a plain-text.";
    unsigned char encrypted_aes[MAX_SIZE];

    const char *filename_1 = "tables/td_rsakey_enc_aes_128ecb_writer.csv";
    const char *filename_2 = "tables/td_enc_aes_128ecb_writer.csv";
    const char *filename_3 = "tables/td_aes_128ecb_writer.csv";

    // Initializing OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    
    // AES random key and iv generation
    // AES-128: 16
    // AES-192: 24
    // AES-256: 32
    unsigned char key[16];
    unsigned char iv[16];
    srand(time(NULL));
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        perror("RAND_bytes failed.\n");
        return EXIT_FAILURE;
    }
    

    // Loading the public key
    FILE* pubKeyFile_key = fopen("public.pem", "rb");
    if (!pubKeyFile_key) ERR_print_errors_fp(stderr);
    EVP_PKEY* pubKey_key = PEM_read_PUBKEY(pubKeyFile_key, NULL, NULL, NULL);
    fclose(pubKeyFile_key);
    if (!pubKey_key) ERR_print_errors_fp(stderr);

    FILE* pubKeyFile_iv = fopen("public2.pem", "rb");
    if (!pubKeyFile_iv) ERR_print_errors_fp(stderr);
    EVP_PKEY* pubKey_iv = PEM_read_PUBKEY(pubKeyFile_iv, NULL, NULL, NULL);
    fclose(pubKeyFile_iv);
    if (!pubKey_iv) ERR_print_errors_fp(stderr);

    start_rsa_enc_time = clock();

    EVP_PKEY_CTX* ctx_rsa_key = EVP_PKEY_CTX_new(pubKey_key, NULL);
    if (!ctx_rsa_key) ERR_print_errors_fp(stderr);
    if (EVP_PKEY_encrypt_init(ctx_rsa_key) <= 0) ERR_print_errors_fp(stderr);

    //sleep(2);

    EVP_PKEY_CTX* ctx_rsa_iv = EVP_PKEY_CTX_new(pubKey_iv, NULL);
    if (!ctx_rsa_iv) ERR_print_errors_fp(stderr);
    if (EVP_PKEY_encrypt_init(ctx_rsa_iv) <= 0) ERR_print_errors_fp(stderr);

    // Encrypting key and iv
    size_t key_len = sizeof(key);
    size_t encrypted_key_len, encrypted_iv_len;
    size_t iv_len = sizeof(iv);

    if (EVP_PKEY_encrypt(ctx_rsa_key, NULL, &encrypted_key_len, key, key_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);
    if (EVP_PKEY_encrypt(ctx_rsa_iv, NULL, &encrypted_iv_len, iv, iv_len) <= 0) ERR_print_errors_fp(stderr);
    //leep(2);

    unsigned char* encrypted_key = malloc(encrypted_key_len);
    unsigned char* encrypted_iv = malloc(encrypted_iv_len);

    if (EVP_PKEY_encrypt(ctx_rsa_key, encrypted_key, &encrypted_key_len, key, key_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);
    if (EVP_PKEY_encrypt(ctx_rsa_iv, encrypted_iv, &encrypted_iv_len, iv, iv_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);

    end_rsa_enc_time = clock();

    elapsed_rsa_enc_time = (end_rsa_enc_time - start_rsa_enc_time)/CLOCKS_PER_SEC;

    // Printing key and iv on terminal (will be deleted after)
    printf("Randomly generated AES Key: ");
    for (int i=0; i<key_len; i++){
        printf("%02X ", key[i]);
    }
    printf("\n\n");
    //sleep(2);
    printf("Randomly generated AES IV: ");
    for (int i=0; i<iv_len; i++){
        printf("%02X ", iv[i]);
    }
    printf("\n\n");
    //sleep(2);
    printf("Encrypted key is: ");
    for (int i = 0; i < encrypted_key_len; i++) {
        printf("%02X ", encrypted_key[i]);
    }
    printf("\n\n");
    //sleep(2);
    printf("Encrypted iv is: ");
    for (int i = 0; i < encrypted_iv_len; i++) {
        printf("%02X ", encrypted_iv[i]);
    }
    printf("\n\n");
    //sleep(2);

    // Creating named pipe if it does not exist
    mkfifo(FIFO_FILE, 0640);

    // Writing key and iv to named pipe
    fd = open(FIFO_FILE, O_WRONLY);

    if (fd == -1){
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    total_duration_2 = clock();
    total_duration_all = (total_duration_2 - total_duration_1)/CLOCKS_PER_SEC + total_duration_all;

    if (write(fd, encrypted_key, encrypted_key_len) == -1){ 
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    //sleep(2);

    if (write(fd, encrypted_iv, encrypted_iv_len) == -1){ 
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    total_duration_3 = clock();

    // AES Encryption

    start_aes_enc_time = clock();

    EVP_CIPHER_CTX *ctx_aes = EVP_CIPHER_CTX_new();
    if (!ctx_aes) {
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    /*
    // For AES-128 (in ECB mode)
    if (1 != EVP_EncryptInit_ex(ctx_aes, EVP_aes_128_ecb(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }
    */
    /***************************************************/
    /*
    // For AES-192 (in ECB mode)
    if (1 != EVP_EncryptInit_ex(ctx_aes, EVP_aes_192_ecb(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }
    */
    /***************************************************/
    /*
    // For AES-256 (in ECB mode)
    if (1 != EVP_EncryptInit_ex(ctx_aes, EVP_aes_256_ecb(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }
    */
    /***************************************************/
    
    // For AES-128 (in CBC mode)
    if (1 != EVP_EncryptInit_ex(ctx_aes, EVP_aes_128_ecb(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }
    
    /***************************************************/
    /*
    // For AES-192 (in CBC mode)
    if (1 != EVP_EncryptInit_ex(ctx_aes, EVP_aes_192_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }
    */
    /***************************************************/
    /*
    // For AES-256 (in CBC mode)
    if (1 != EVP_EncryptInit_ex(ctx_aes, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }
    */

    if (1 != EVP_EncryptUpdate(ctx_aes, encrypted_aes, &len, (unsigned char*)basemsg, strlen(basemsg))) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }

    aes_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx_aes, encrypted_aes + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx_aes);
        close(fd);
        return EXIT_FAILURE;
    }

    aes_len += len;

    end_aes_enc_time = clock();

    elapsed_aes_enc_time = (end_aes_enc_time - start_aes_enc_time)/CLOCKS_PER_SEC;

    printf("Plain text: %s\n\n", basemsg);
    printf("Encrypted text: ");
    for(size_t i = 0; i < aes_len; i++)
        printf("%X%X ", (encrypted_aes[i] >> 4) & 0xf, encrypted_aes[i] & 0xf);
    printf("\n\n");

    printf("RSA Key Encryption Duration: %Lf us.\n\n", elapsed_rsa_enc_time*1000000);
    printf("AES Encryption Duration: %Lf us.\n\n", elapsed_aes_enc_time*1000000);

    total_duration_4 = clock();
    total_duration_all = (total_duration_4 - total_duration_3)/CLOCKS_PER_SEC + total_duration_all;

    if(write(fd, encrypted_aes, aes_len) == -1){
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    total_duration_5 = clock();

    close(fd);
    EVP_PKEY_free(pubKey_key);
    EVP_PKEY_free(pubKey_iv);
    EVP_PKEY_CTX_free(ctx_rsa_key);
    EVP_PKEY_CTX_free(ctx_rsa_iv);
    EVP_CIPHER_CTX_free(ctx_aes);
    free(encrypted_key);
    free(encrypted_iv);
    EVP_cleanup();
    ERR_free_strings();

    total_duration_6 = clock();
    total_duration_all = (total_duration_6 - total_duration_5)/CLOCKS_PER_SEC + total_duration_all;
    printf("Total Duration: %Lf us.\n\n", total_duration_all*1000000);

    append_to_csv(filename_1, elapsed_rsa_enc_time*1000000);
    append_to_csv(filename_2, elapsed_aes_enc_time*1000000);
    append_to_csv(filename_3, total_duration_all*1000000);

    return 0;
}