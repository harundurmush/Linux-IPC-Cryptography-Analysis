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

#define FIFO_FILE "myfifo_ceasar"
#define MAX_SIZE 256 // maximum message size

char* encrypt(const char *plaintext, int shift) {
    char *encrypted = (char *)malloc(strlen(plaintext) + 1); // Allocate memory for the encrypted string
    
    for(int i = 0; plaintext[i] != '\0'; ++i) {
        char ch = plaintext[i];
        
        if(ch >= 'a' && ch <= 'z') {
            ch = ((ch - 'a') + shift) % 26 + 'a';
        }
        else if(ch >= 'A' && ch <= 'Z') {
            ch = ((ch - 'A') + shift) % 26 + 'A';
        }
        encrypted[i] = ch;
    }
    encrypted[strlen(plaintext)] = '\0'; // Null-terminate the encrypted string
    
    return encrypted;
}

void append_to_csv(const char *filename, long double value){
    FILE *fp = fopen(filename, "a");
    if (!fp){
        ERR_print_errors_fp(stderr);
    }

    fprintf(fp, "%Lf\n", value);

    fclose(fp);
}

int main(){
    long double start_rsa_enc_time, end_rsa_enc_time, start_ceasar_enc_time, end_ceasar_enc_time, elapsed_rsa_enc_time, elapsed_ceasar_enc_time, total_duration_1, total_duration_2, total_duration_3, total_duration_4, total_duration_5, total_duration_6, total_duration_all;
    total_duration_all = 0;
    total_duration_1 = clock();

    int fd;
    srand(time(NULL));
    int shift_key = rand() % 26;
    char basemsg[MAX_SIZE] = "This is a plain-text.";
    unsigned char key[16];

    const char *filename_1 = "tables/td_rsakey_enc_ceasar_writer.csv";
    const char *filename_2 = "tables/td_enc_ceasar_writer.csv";
    const char *filename_3 = "tables/td_ceasar_writer.csv";

    sprintf(key, "%d", shift_key);

    // Initializing OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Loading the public key
    FILE* pubKeyFile_key = fopen("public.pem", "rb");
    if (!pubKeyFile_key) ERR_print_errors_fp(stderr);
    EVP_PKEY* pubKey_key = PEM_read_PUBKEY(pubKeyFile_key, NULL, NULL, NULL);
    fclose(pubKeyFile_key);
    if (!pubKey_key) ERR_print_errors_fp(stderr);

    start_rsa_enc_time = clock();
    
    EVP_PKEY_CTX* ctx_ceasar_key = EVP_PKEY_CTX_new(pubKey_key, NULL);
    if (!ctx_ceasar_key) ERR_print_errors_fp(stderr);
    if (EVP_PKEY_encrypt_init(ctx_ceasar_key) <= 0) ERR_print_errors_fp(stderr);

    // Encrypting key and iv
    size_t key_len = sizeof(key);
    size_t encrypted_key_len;

    if (EVP_PKEY_encrypt(ctx_ceasar_key, NULL, &encrypted_key_len, key, key_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);

    unsigned char* encrypted_key = malloc(encrypted_key_len);

    if (EVP_PKEY_encrypt(ctx_ceasar_key, encrypted_key, &encrypted_key_len, key, key_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);

    end_rsa_enc_time = clock();

    elapsed_rsa_enc_time = (end_rsa_enc_time - start_rsa_enc_time)/CLOCKS_PER_SEC;

    // Printing key on terminal (will be deleted after)
    printf("Randomly Generated Ceasar Shift Key: %d\n\n", shift_key);
    //sleep(2);
    printf("Encrypted key is: ");
    for (size_t i = 0; i < encrypted_key_len; i++) {
        printf("%02X ", encrypted_key[i]);
    }
    printf("\n\n");

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

    total_duration_3 = clock();

    start_ceasar_enc_time = clock();

    // Ceasar Encryption
    unsigned char* encrypted_ceasar = encrypt(basemsg, shift_key);

    end_ceasar_enc_time = clock();

    elapsed_ceasar_enc_time = (end_ceasar_enc_time - start_ceasar_enc_time)/CLOCKS_PER_SEC;

    printf("Plain text: %s\n\n", basemsg);
    printf("Encrypted text: %s\n\n", encrypted_ceasar);
    printf("RSA Key Encryption Duration: %Lf us.\n\n", elapsed_rsa_enc_time*1000000);
    printf("Ceasar Encryption Duration: %Lf us.\n\n", elapsed_ceasar_enc_time*1000000);

    total_duration_4 = clock();
    total_duration_all = (total_duration_4 - total_duration_3)/CLOCKS_PER_SEC + total_duration_all;

    if(write(fd, encrypted_ceasar, strlen(encrypted_ceasar)) == -1){
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    total_duration_5 = clock();

    close(fd);
    EVP_PKEY_free(pubKey_key);
    free(encrypted_key);
    EVP_cleanup();
    ERR_free_strings();

    total_duration_6 = clock();
    total_duration_all = (total_duration_6 - total_duration_5)/CLOCKS_PER_SEC + total_duration_all;
    printf("Total Duration: %Lf us.\n\n", total_duration_all*1000000);

    append_to_csv(filename_1, elapsed_rsa_enc_time*1000000);
    append_to_csv(filename_2, elapsed_ceasar_enc_time*1000000);
    append_to_csv(filename_3, total_duration_all*1000000);

    return 0;
}