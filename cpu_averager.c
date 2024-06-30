#include <stdio.h>
#include <stdlib.h>

// Function to compute the average of values in a CSV file.
long double compute_average_from_txt(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Unable to open the file");
        return -1; // Using -1 to indicate an error condition
    }

    long double value, sum = 0.0;
    int count = 0;
    char line[128]; // Buffer to hold each line

    // Read each line and extract the CPU utilization value
    while (fgets(line, sizeof(line), file)) {
        value = atof(line);
        if (value > 2){
            value = 0.5;
        }
        sum += value;
        count++;
    }

    fclose(file);

    if (count == 0) {
        fprintf(stderr, "No valid data found in the file.\n");
        return 0;
    }

    return 1000*sum/count; // Return the average
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
    const char* filename_1 = "tables/cpu_ceasar_writer.txt";
    const char* filename_2 = "tables/cpu_ceasar_reader.txt";
    // AES-128 (CBC)
    const char* filename_3 = "tables/cpu_aes128_cbc_writer.txt";
    const char* filename_4 = "tables/cpu_aes128_cbc_reader.txt";
    // AES-128 (ECB)
    const char* filename_5 = "tables/cpu_aes128_ecb_writer.txt";
    const char* filename_6 = "tables/cpu_aes128_ecb_reader.txt";
    // AES-192 (CBC)
    const char* filename_7 = "tables/cpu_aes192_cbc_writer.txt";
    const char* filename_8 = "tables/cpu_aes192_cbc_reader.txt";
    // AES-192 (ECB)
    const char* filename_9 = "tables/cpu_aes192_ecb_writer.txt";
    const char* filename_10 = "tables/cpu_aes192_ecb_reader.txt";
    // AES-256 (CBC)
    const char* filename_11 = "tables/cpu_aes256_cbc_writer.txt";
    const char* filename_12 = "tables/cpu_aes256_cbc_reader.txt";
    // AES-256 (ECB)
    const char* filename_13 = "tables/cpu_aes256_ecb_writer.txt";
    const char* filename_14 = "tables/cpu_aes256_ecb_reader.txt";
    // DES (CBC)
    const char* filename_15 = "tables/cpu_des_cbc_writer.txt";
    const char* filename_16 = "tables/cpu_des_cbc_reader.txt";
    // DES (ECB)
    const char* filename_17 = "tables/cpu_des_ecb_writer.txt";
    const char* filename_18 = "tables/cpu_des_ecb_reader.txt";

    long double average_1 = compute_average_from_txt(filename_1);
    long double average_2 = compute_average_from_txt(filename_2);
    long double average_3 = compute_average_from_txt(filename_3);
    long double average_4 = compute_average_from_txt(filename_4);
    long double average_5 = compute_average_from_txt(filename_5);
    long double average_6 = compute_average_from_txt(filename_6);
    long double average_7 = compute_average_from_txt(filename_7);
    long double average_8 = compute_average_from_txt(filename_8);
    long double average_9 = compute_average_from_txt(filename_9);
    long double average_10 = compute_average_from_txt(filename_10);
    long double average_11 = compute_average_from_txt(filename_11);
    long double average_12 = compute_average_from_txt(filename_12);
    long double average_13 = compute_average_from_txt(filename_13);
    long double average_14 = compute_average_from_txt(filename_14);
    long double average_15 = compute_average_from_txt(filename_15);
    long double average_16 = compute_average_from_txt(filename_16);
    long double average_17 = compute_average_from_txt(filename_17);
    long double average_18 = compute_average_from_txt(filename_18);
    

    append_to_csv("tables/cpu_data.csv", "Ceasar", "None", "writer", average_1);
    append_to_csv("tables/cpu_data.csv", "Ceasar", "None", "reader", average_2);

    append_to_csv("tables/cpu_data.csv", "AES-128", "CBC", "writer", average_3);
    append_to_csv("tables/cpu_data.csv", "AES-128", "CBC", "reader", average_4);

    append_to_csv("tables/cpu_data.csv", "AES-128", "ECB", "writer", average_5);
    append_to_csv("tables/cpu_data.csv", "AES-128", "ECB", "reader", average_6);

    append_to_csv("tables/cpu_data.csv", "AES-192", "CBC", "writer", average_7);
    append_to_csv("tables/cpu_data.csv", "AES-192", "CBC", "reader", average_8);

    append_to_csv("tables/cpu_data.csv", "AES-192", "ECB", "writer", average_9);
    append_to_csv("tables/cpu_data.csv", "AES-192", "ECB", "reader", average_10);

    append_to_csv("tables/cpu_data.csv", "AES-256", "CBC", "writer", average_11);
    append_to_csv("tables/cpu_data.csv", "AES-256", "CBC", "reader", average_12);

    append_to_csv("tables/cpu_data.csv", "AES-256", "ECB", "writer", average_13);
    append_to_csv("tables/cpu_data.csv", "AES-256", "ECB", "reader", average_14);

    append_to_csv("tables/cpu_data.csv", "DES", "CBC", "writer", average_15);
    append_to_csv("tables/cpu_data.csv", "DES", "CBC", "reader", average_16);

    append_to_csv("tables/cpu_data.csv", "DES", "ECB", "writer", average_17);
    append_to_csv("tables/cpu_data.csv", "DES", "ECB", "reader", average_18);

    return 0;
}