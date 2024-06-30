#include <stdio.h>
#include <stdlib.h>

// Function to compute the average of values in a CSV file.
long double compute_average_from_csv(const char* filename) {
    FILE* file;
    long double value; 
    long double count = 0.0;
    long double sum = 0.0;

    // Open the CSV file for reading.
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Unable to open the file");
        return EXIT_FAILURE;
    }

    // Read values from the file, assuming they're separated by commas or newlines.
    while (fscanf(file, "%Lf,", &value) == 1) {
        sum += value;
        count++;
    }

    fclose(file);

    // Compute the average. Avoid division by zero.
    if (count == 0) {
        return 0.0;
    }

    return sum / count;
}

void append_to_csv(const char *filename, const char *category1, const char *category2, const char *category3, int value) {
    FILE *file = fopen(filename, "a"); // Open the file in append mode
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }
    fprintf(file, "%s,%s,%s,%d\n", category1, category2, category3, value); // Write category and value to the file
    fclose(file); // Close the file
}

int main() {
    // Ceasar
    const char* filename_1 = "tables/td_rsakey_enc_ceasar_writer.csv";
    const char* filename_2 = "tables/td_rsakey_dec_ceasar_reader.csv";
    const char* filename_3 = "tables/td_enc_ceasar_writer.csv";
    const char* filename_4 = "tables/td_dec_ceasar_reader.csv";
    const char* filename_5 = "tables/td_ceasar_writer.csv";
    const char* filename_6 = "tables/td_ceasar_reader.csv";

    // AES-128 (CBC)
    const char* filename_7 = "tables/td_rsakey_enc_aes_128cbc_writer.csv";
    const char* filename_8 = "tables/td_rsakey_dec_aes_128cbc_reader.csv";
    const char* filename_9 = "tables/td_enc_aes_128cbc_writer.csv";
    const char* filename_10 = "tables/td_dec_aes_128cbc_reader.csv";
    const char* filename_11 = "tables/td_aes_128cbc_writer.csv";
    const char* filename_12 = "tables/td_aes_128cbc_reader.csv";

    // AES-128 (ECB)
    const char* filename_13 = "tables/td_rsakey_enc_aes_128ecb_writer.csv";
    const char* filename_14 = "tables/td_rsakey_dec_aes_128ecb_reader.csv";
    const char* filename_15 = "tables/td_enc_aes_128ecb_writer.csv";
    const char* filename_16 = "tables/td_dec_aes_128ecb_reader.csv";
    const char* filename_17 = "tables/td_aes_128ecb_writer.csv";
    const char* filename_18 = "tables/td_aes_128ecb_reader.csv";

    // AES-192 (CBC)
    const char* filename_19 = "tables/td_rsakey_enc_aes_192cbc_writer.csv";
    const char* filename_20 = "tables/td_rsakey_dec_aes_192cbc_reader.csv";
    const char* filename_21 = "tables/td_enc_aes_192cbc_writer.csv";
    const char* filename_22 = "tables/td_dec_aes_192cbc_reader.csv";
    const char* filename_23 = "tables/td_aes_192cbc_writer.csv";
    const char* filename_24 = "tables/td_aes_192cbc_reader.csv";

    // AES-192 (ECB)
    const char* filename_25 = "tables/td_rsakey_enc_aes_192ecb_writer.csv";
    const char* filename_26 = "tables/td_rsakey_dec_aes_192ecb_reader.csv";
    const char* filename_27 = "tables/td_enc_aes_192ecb_writer.csv";
    const char* filename_28 = "tables/td_dec_aes_192ecb_reader.csv";
    const char* filename_29 = "tables/td_aes_192ecb_writer.csv";
    const char* filename_30 = "tables/td_aes_192ecb_reader.csv";

    // AES-256 (CBC)
    const char* filename_31 = "tables/td_rsakey_enc_aes_256cbc_writer.csv";
    const char* filename_32 = "tables/td_rsakey_dec_aes_256cbc_reader.csv";
    const char* filename_33 = "tables/td_enc_aes_256cbc_writer.csv";
    const char* filename_34 = "tables/td_dec_aes_256cbc_reader.csv";
    const char* filename_35 = "tables/td_aes_256cbc_writer.csv";
    const char* filename_36 = "tables/td_aes_256cbc_reader.csv";

    // AES-256 (ECB)
    const char* filename_37 = "tables/td_rsakey_enc_aes_256ecb_writer.csv";
    const char* filename_38 = "tables/td_rsakey_dec_aes_256ecb_reader.csv";
    const char* filename_39 = "tables/td_enc_aes_256ecb_writer.csv";
    const char* filename_40 = "tables/td_dec_aes_256ecb_reader.csv";
    const char* filename_41 = "tables/td_aes_256ecb_writer.csv";
    const char* filename_42 = "tables/td_aes_256ecb_reader.csv";

    // DES (CBC)
    const char* filename_43 = "tables/td_rsakey_enc_des_cbc_writer.csv";
    const char* filename_44 = "tables/td_rsakey_dec_des_cbc_reader.csv";
    const char* filename_45 = "tables/td_enc_des_cbc_writer.csv";
    const char* filename_46 = "tables/td_dec_des_cbc_reader.csv";
    const char* filename_47 = "tables/td_des_cbc_writer.csv";
    const char* filename_48 = "tables/td_des_cbc_reader.csv";

    // DES (ECB)
    const char* filename_49 = "tables/td_rsakey_enc_des_cbc_writer.csv";
    const char* filename_50 = "tables/td_rsakey_dec_des_cbc_reader.csv";
    const char* filename_51 = "tables/td_enc_des_cbc_writer.csv";
    const char* filename_52 = "tables/td_dec_des_cbc_reader.csv";
    const char* filename_53 = "tables/td_des_cbc_writer.csv";
    const char* filename_54 = "tables/td_des_cbc_reader.csv";

    // Ceasar           1-6
    // AES-128 (CBC)    7-12
    // AES-128 (ECB)    13-18
    // AES-192 (CBC)    19-24
    // AES-192 (ECB)    25-30
    // AES-256 (CBC)    31-36
    // AES-256 (ECB)    37-42
    // DES (CBC)        43-48
    // DES (ECB)        49-54

    long double average_1 = compute_average_from_csv(filename_1);
    long double average_2 = compute_average_from_csv(filename_2);
    long double average_3 = compute_average_from_csv(filename_3);
    long double average_4 = compute_average_from_csv(filename_4);
    long double average_5 = compute_average_from_csv(filename_5);
    long double average_6 = compute_average_from_csv(filename_6);
    long double average_7 = compute_average_from_csv(filename_7);
    long double average_8 = compute_average_from_csv(filename_8);
    long double average_9 = compute_average_from_csv(filename_9);
    long double average_10 = compute_average_from_csv(filename_10);
    long double average_11 = compute_average_from_csv(filename_11);
    long double average_12 = compute_average_from_csv(filename_12);
    long double average_13 = compute_average_from_csv(filename_13);
    long double average_14 = compute_average_from_csv(filename_14);
    long double average_15 = compute_average_from_csv(filename_15);
    long double average_16 = compute_average_from_csv(filename_16);
    long double average_17 = compute_average_from_csv(filename_17);
    long double average_18 = compute_average_from_csv(filename_18);
    long double average_19 = compute_average_from_csv(filename_19);
    long double average_20 = compute_average_from_csv(filename_20);
    long double average_21 = compute_average_from_csv(filename_21);
    long double average_22 = compute_average_from_csv(filename_22);
    long double average_23 = compute_average_from_csv(filename_23);
    long double average_24 = compute_average_from_csv(filename_24);
    long double average_25 = compute_average_from_csv(filename_25);
    long double average_26 = compute_average_from_csv(filename_26);
    long double average_27 = compute_average_from_csv(filename_27);
    long double average_28 = compute_average_from_csv(filename_28);
    long double average_29 = compute_average_from_csv(filename_29);
    long double average_30 = compute_average_from_csv(filename_30);
    long double average_31 = compute_average_from_csv(filename_31);
    long double average_32 = compute_average_from_csv(filename_32);
    long double average_33 = compute_average_from_csv(filename_33);
    long double average_34 = compute_average_from_csv(filename_34);
    long double average_35 = compute_average_from_csv(filename_35);
    long double average_36 = compute_average_from_csv(filename_36);
    long double average_37 = compute_average_from_csv(filename_37);
    long double average_38 = compute_average_from_csv(filename_38);
    long double average_39 = compute_average_from_csv(filename_39);
    long double average_40 = compute_average_from_csv(filename_40);
    long double average_41 = compute_average_from_csv(filename_41);
    long double average_42 = compute_average_from_csv(filename_42);
    long double average_43 = compute_average_from_csv(filename_43);
    long double average_44 = compute_average_from_csv(filename_44);
    long double average_45 = compute_average_from_csv(filename_45);
    long double average_46 = compute_average_from_csv(filename_46);
    long double average_47 = compute_average_from_csv(filename_47);
    long double average_48 = compute_average_from_csv(filename_48);
    long double average_49 = compute_average_from_csv(filename_49);
    long double average_50 = compute_average_from_csv(filename_50);
    long double average_51 = compute_average_from_csv(filename_51);
    long double average_52 = compute_average_from_csv(filename_52);
    long double average_53 = compute_average_from_csv(filename_53);
    long double average_54 = compute_average_from_csv(filename_54);
    
    append_to_csv("tables/data.csv", "Ceasar", "None", "RSA_key_enc", average_1);
    append_to_csv("tables/data.csv", "Ceasar", "None", "RSA_key_dec", average_2);
    append_to_csv("tables/data.csv", "Ceasar", "None", "enc", average_3);
    append_to_csv("tables/data.csv", "Ceasar", "None", "dec", average_4);
    append_to_csv("tables/data.csv", "Ceasar", "None", "writer", average_5);
    append_to_csv("tables/data.csv", "Ceasar", "None", "reader", average_6);

    append_to_csv("tables/data.csv", "AES-128", "CBC", "RSA_key_enc", average_7);
    append_to_csv("tables/data.csv", "AES-128", "CBC", "RSA_key_dec", average_8);
    append_to_csv("tables/data.csv", "AES-128", "CBC", "enc", average_9);
    append_to_csv("tables/data.csv", "AES-128", "CBC", "dec", average_10);
    append_to_csv("tables/data.csv", "AES-128", "CBC", "writer", average_11);
    append_to_csv("tables/data.csv", "AES-128", "CBC", "reader", average_12);

    append_to_csv("tables/data.csv", "AES-128", "ECB", "RSA_key_enc", average_13);
    append_to_csv("tables/data.csv", "AES-128", "ECB", "RSA_key_dec", average_14);
    append_to_csv("tables/data.csv", "AES-128", "ECB", "enc", average_15);
    append_to_csv("tables/data.csv", "AES-128", "ECB", "dec", average_16);
    append_to_csv("tables/data.csv", "AES-128", "ECB", "writer", average_17);
    append_to_csv("tables/data.csv", "AES-128", "ECB", "reader", average_18);

    append_to_csv("tables/data.csv", "AES-192", "CBC", "RSA_key_enc", average_19);
    append_to_csv("tables/data.csv", "AES-192", "CBC", "RSA_key_dec", average_20);
    append_to_csv("tables/data.csv", "AES-192", "CBC", "enc", average_21);
    append_to_csv("tables/data.csv", "AES-192", "CBC", "dec", average_22);
    append_to_csv("tables/data.csv", "AES-192", "CBC", "writer", average_23);
    append_to_csv("tables/data.csv", "AES-192", "CBC", "reader", average_24);

    append_to_csv("tables/data.csv", "AES-192", "ECB", "RSA_key_enc", average_25);
    append_to_csv("tables/data.csv", "AES-192", "ECB", "RSA_key_dec", average_26);
    append_to_csv("tables/data.csv", "AES-192", "ECB", "enc", average_27);
    append_to_csv("tables/data.csv", "AES-192", "ECB", "dec", average_28);
    append_to_csv("tables/data.csv", "AES-192", "ECB", "writer", average_29);
    append_to_csv("tables/data.csv", "AES-192", "ECB", "reader", average_30);

    append_to_csv("tables/data.csv", "AES-256", "CBC", "RSA_key_enc", average_31);
    append_to_csv("tables/data.csv", "AES-256", "CBC", "RSA_key_dec", average_32);
    append_to_csv("tables/data.csv", "AES-256", "CBC", "enc", average_33);
    append_to_csv("tables/data.csv", "AES-256", "CBC", "dec", average_34);
    append_to_csv("tables/data.csv", "AES-256", "CBC", "writer", average_35);
    append_to_csv("tables/data.csv", "AES-256", "CBC", "reader", average_36);

    append_to_csv("tables/data.csv", "AES-256", "ECB", "RSA_key_enc", average_37);
    append_to_csv("tables/data.csv", "AES-256", "ECB", "RSA_key_dec", average_38);
    append_to_csv("tables/data.csv", "AES-256", "ECB", "enc", average_39);
    append_to_csv("tables/data.csv", "AES-256", "ECB", "dec", average_40);
    append_to_csv("tables/data.csv", "AES-256", "ECB", "writer", average_41);
    append_to_csv("tables/data.csv", "AES-256", "ECB", "reader", average_42);

    append_to_csv("tables/data.csv", "DES", "CBC", "RSA_key_enc", average_43);
    append_to_csv("tables/data.csv", "DES", "CBC", "RSA_key_dec", average_44);
    append_to_csv("tables/data.csv", "DES", "CBC", "enc", average_45);
    append_to_csv("tables/data.csv", "DES", "CBC", "dec", average_46);
    append_to_csv("tables/data.csv", "DES", "CBC", "writer", average_47);
    append_to_csv("tables/data.csv", "DES", "CBC", "reader", average_48);

    append_to_csv("tables/data.csv", "DES", "ECB", "RSA_key_enc", average_49);
    append_to_csv("tables/data.csv", "DES", "ECB", "RSA_key_dec", average_50);
    append_to_csv("tables/data.csv", "DES", "ECB", "enc", average_51);
    append_to_csv("tables/data.csv", "DES", "ECB", "dec", average_52);
    append_to_csv("tables/data.csv", "DES", "ECB", "writer", average_53);
    append_to_csv("tables/data.csv", "DES", "ECB", "reader", average_54);

    return 0;
}