// DES_RSA_writer.c
#include <fcntl.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define FIFO_FILE "myfifo_des"
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
    long double start_rsa_enc_time, end_rsa_enc_time, start_des_enc_time, end_des_enc_time, elapsed_rsa_enc_time, elapsed_des_enc_time, total_duration_1, total_duration_2, total_duration_3, total_duration_4, total_duration_5, total_duration_6, total_duration_all;
    total_duration_all = 0;
    total_duration_1 = clock();

    OSSL_PROVIDER *legacy_provider = NULL;
    legacy_provider = OSSL_PROVIDER_load(NULL, "default");
    legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (legacy_provider == NULL){
        fprintf(stderr, "Failed to load legacy provider.\n");
        return 1;
    }

    // For DES
    // unsigned char key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    // For CBC mode
    // unsigned char iv[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

    
    // DES random key and iv generation
    unsigned char key[8];
    unsigned char iv[8];
    srand(time(NULL));
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        perror("RAND_bytes failed.\n");
        return EXIT_FAILURE;
    }
    

    int len, fd;
    int ciphertext_len;
    char basemsg[MAX_SIZE] = "This is a plain-text.";
    unsigned char encrypted_des[MAX_SIZE];

    const char *filename_1 = "tables/td_rsakey_enc_des_ecb_writer.csv";
    const char *filename_2 = "tables/td_enc_des_ecb_writer.csv";
    const char *filename_3 = "tables/td_des_ecb_writer.csv";

    // Initializing OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

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

    elapsed_rsa_enc_time = (end_rsa_enc_time - start_des_enc_time)/CLOCKS_PER_SEC;

    // Printing key and iv on terminal (will be deleted after)
    printf("Randomly generated DES Key: ");
    for (int i=0; i<key_len; i++){
        printf("%02X ", key[i]);
    }
    printf("\n\n");
    //sleep(2);
    printf("Randomly generated DES IV: ");
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

    if (write(fd, encrypted_iv, encrypted_iv_len) == -1){ 
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    total_duration_3 = clock();

    // DES Encryption

    start_des_enc_time = clock();

    EVP_CIPHER_CTX *ctx_des = EVP_CIPHER_CTX_new();

    if (!ctx_des) {
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    //
    // For DES (in ECB mode)
    if (1 != EVP_EncryptInit_ex(ctx_des, EVP_des_ecb(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }
    //

    /*/
    // For DES (in CBC mode)
    if (1 != EVP_EncryptInit_ex(ctx_des, EVP_des_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx_des);
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }
    /*/

    if (1 != EVP_EncryptUpdate(ctx_des, encrypted_des, &len, (unsigned char*)basemsg, strlen(basemsg))) {
        EVP_CIPHER_CTX_free(ctx_des);
        ERR_print_errors_fp(stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx_des, encrypted_des + len, &len)) {
        perror("EVP_EncryptFinal_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx_des);
        close(fd);
        return EXIT_FAILURE;
    }

    ciphertext_len += len;

    end_des_enc_time = clock();

    elapsed_des_enc_time = (end_des_enc_time - start_des_enc_time)/CLOCKS_PER_SEC;

    printf("Plain text: %s\n\n", basemsg);
    printf("Encrypted text: ");
    for(size_t i = 0; i < sizeof(encrypted_des); i++)
        printf("%X%X ", (encrypted_des[i] >> 4) & 0xf, encrypted_des[i] & 0xf);
    printf("\n\n");

    printf("RSA Key Encryption Duration: %Lf us.\n\n", elapsed_rsa_enc_time*1000000);
    printf("DES Encryption Duration: %Lf us.\n\n", elapsed_des_enc_time*1000000);

    total_duration_4 = clock();
    total_duration_all = (total_duration_4 - total_duration_3)/CLOCKS_PER_SEC + total_duration_all;

    if(write(fd, encrypted_des, ciphertext_len) == -1){
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
    EVP_CIPHER_CTX_free(ctx_des);
    OSSL_PROVIDER_unload(legacy_provider);
    free(encrypted_key);
    free(encrypted_iv);
    EVP_cleanup();
    ERR_free_strings();

    total_duration_6 = clock();
    total_duration_all = (total_duration_6 - total_duration_5)/CLOCKS_PER_SEC + total_duration_all;
    printf("Total Duration: %Lf us.\n\n", total_duration_all*1000000);

    append_to_csv(filename_1, elapsed_rsa_enc_time*1000000);
    append_to_csv(filename_2, elapsed_des_enc_time*1000000);
    append_to_csv(filename_3, total_duration_all*1000000);

    return 0;
}