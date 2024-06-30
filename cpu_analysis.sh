#!/bin/bash

# Function to capture CPU utilization and append to file
capture_cpu_utilization() {
    local command="$1"
    local file="$2"
    taskset -c 0 perf stat $command 2>&1 | awk -F'[ %]+' '/CPUs utilized/ {gsub(",", ".", $6); print $6}' >> "$file"
}

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./ceasar_w" "tables/cpu_ceasar_writer.txt" &
    capture_cpu_utilization "./ceasar_r" "tables/cpu_ceasar_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./aes128_cbc_w" "tables/cpu_aes128_cbc_writer.txt" &
    capture_cpu_utilization "./aes128_cbc_r" "tables/cpu_aes128_cbc_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./aes128_ecb_w" "tables/cpu_aes128_ecb_writer.txt" &
    capture_cpu_utilization "./aes128_ecb_r" "tables/cpu_aes128_ecb_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./aes192_cbc_w" "tables/cpu_aes192_cbc_writer.txt" &
    capture_cpu_utilization "./aes192_cbc_r" "tables/cpu_aes192_cbc_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./aes192_ecb_w" "tables/cpu_aes192_ecb_writer.txt" &
    capture_cpu_utilization "./aes192_ecb_r" "tables/cpu_aes192_ecb_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./aes256_cbc_w" "tables/cpu_aes256_cbc_writer.txt" &
    capture_cpu_utilization "./aes256_cbc_r" "tables/cpu_aes256_cbc_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./aes256_ecb_w" "tables/cpu_aes256_ecb_writer.txt" &
    capture_cpu_utilization "./aes256_ecb_r" "tables/cpu_aes256_ecb_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./des_cbc_w" "tables/cpu_des_cbc_writer.txt" &
    capture_cpu_utilization "./des_cbc_r" "tables/cpu_des_cbc_reader.txt"
done

for i in {1..1000}; do
    echo "Iteration $i"
    capture_cpu_utilization "./des_ecb_w" "tables/cpu_des_ecb_writer.txt" &
    capture_cpu_utilization "./des_ecb_r" "tables/cpu_des_ecb_reader.txt"
done

echo "All iterations completed."

sleep 1
./cpu_averager

sleep 1
python3 cpu_plotter.py