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

#define FIFO_FILE "myfifo_ceasar"
#define MAX_SIZE 256 // maximum message size
#define MAX_KEY_SIZE_MODE 256

char* decrypt(const char *ciphertext, int shift) {
    char *decrypted = (char *)malloc(strlen(ciphertext) + 1); // Allocate memory for the decrypted string
    
    for(int i = 0; ciphertext[i] != '\0'; ++i) {
        char ch = ciphertext[i];
        
        if(ch >= 'a' && ch <= 'z') {
            ch = ((ch - 'a') - shift + 26) % 26 + 'a';
        }
        else if(ch >= 'A' && ch <= 'Z') {
            ch = ((ch - 'A') - shift + 26) % 26 + 'A';
        }
        decrypted[i] = ch;
    }
    decrypted[strlen(ciphertext)] = '\0'; // Null-terminate the decrypted string
    
    return decrypted;
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
    long double start_rsa_dec_time, end_rsa_dec_time, start_ceasar_dec_time, end_ceasar_dec_time, elapsed_rsa_dec_time, elapsed_ceasar_dec_time, total_duration_1, total_duration_2, total_duration_3, total_duration_4, total_duration_5, total_duration_6, total_duration_all;
    total_duration_all = 0;
    total_duration_1 = clock();

    // Initializing OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    int fd;
    int plaintext_len, final_len;

    unsigned char received_key[MAX_KEY_SIZE_MODE];
    unsigned char received_message[MAX_SIZE];

    const char *filename_1 = "tables/td_rsakey_dec_ceasar_reader.csv";
    const char *filename_2 = "tables/td_dec_ceasar_reader.csv";
    const char *filename_3 = "tables/td_ceasar_reader.csv";

    memset(received_message, 0, MAX_SIZE);

    // Loading the private key
    FILE* privKeyFile_key = fopen("private.pem", "rb");
    if (!privKeyFile_key) ERR_print_errors_fp(stderr);
    EVP_PKEY* privKey_key = PEM_read_PrivateKey(privKeyFile_key, NULL, NULL, NULL);
    fclose(privKeyFile_key);
    if (!privKey_key) ERR_print_errors_fp(stderr);

    // Encrypted key and iv from the writer
    size_t received_key_len = sizeof(received_key);
    size_t received_message_len = strlen(received_message);
    size_t decrypted_key_len, decrypted_message_len;

    fd = open(FIFO_FILE, O_RDONLY);
    if (fd == -1) ERR_print_errors_fp(stderr);

    total_duration_2 = clock();
    total_duration_all = (total_duration_2 - total_duration_1)/CLOCKS_PER_SEC + total_duration_all;

    if (read(fd, received_key, sizeof(received_key)) == -1){ 
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    total_duration_3 = clock();

    //sleep(2);

    start_rsa_dec_time = clock();

    EVP_PKEY_CTX* ctx_rsa_key = EVP_PKEY_CTX_new(privKey_key, NULL);
    if (!ctx_rsa_key) ERR_print_errors_fp(stderr);
    if (EVP_PKEY_decrypt_init(ctx_rsa_key) <= 0) ERR_print_errors_fp(stderr);

    if (EVP_PKEY_decrypt(ctx_rsa_key, NULL, &decrypted_key_len, received_key, received_key_len) <= 0) ERR_print_errors_fp(stderr);
    //sleep(2);

    unsigned char* decrypted_key = malloc(decrypted_key_len);

    if (EVP_PKEY_decrypt(ctx_rsa_key, decrypted_key, &decrypted_key_len, received_key, received_key_len) <= 0) ERR_print_errors_fp(stderr);
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
    int decrypted_integer_key = atoi(decrypted_key);
    printf("Decrypted key is: %d\n\n" ,decrypted_integer_key);
    //sleep(2);

    total_duration_4 = clock();
    total_duration_all = (total_duration_4 - total_duration_3)/CLOCKS_PER_SEC + total_duration_all;

    if (read(fd, received_message, sizeof(received_message)) == -1){
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    total_duration_5 = clock();

    start_ceasar_dec_time = clock();

    char* decrypted_message = decrypt(received_message, decrypted_integer_key);

    end_ceasar_dec_time = clock();

    elapsed_ceasar_dec_time = (end_ceasar_dec_time - start_ceasar_dec_time)/CLOCKS_PER_SEC;

    printf("Received text: %s\n\n", received_message);
    printf("Decrypted plain-text: %s\n\n", decrypted_message);

    printf("RSA Key Decryption Duration: %Lf us.\n\n", elapsed_rsa_dec_time*1000000);
    printf("Ceasar Decryption Duration: %Lf us.\n\n", elapsed_ceasar_dec_time*1000000);

    EVP_PKEY_free(privKey_key);
    EVP_PKEY_CTX_free(ctx_rsa_key);
    free(decrypted_key);
    EVP_cleanup();
    ERR_free_strings();
    close(fd);

    total_duration_6 = clock();
    total_duration_all = (total_duration_6 - total_duration_5)/CLOCKS_PER_SEC + total_duration_all;
    printf("Total Duration: %Lf us.\n\n", total_duration_all*1000000);
    
    append_to_csv(filename_1, elapsed_rsa_dec_time*1000000);
    append_to_csv(filename_2, elapsed_ceasar_dec_time*1000000);
    append_to_csv(filename_3, total_duration_all*1000000);

    return 0;
}