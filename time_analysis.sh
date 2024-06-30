#!/bin/bash
sleep 1
# Loop for running each pair of writer-reader scripts 1000 times
for i in {1..1000}; do
    ./ceasar_w &
    ./ceasar_r
    # sleep 1
done

for i in {1..1000}; do
    ./aes128_cbc_w &
    ./aes128_cbc_r
    # sleep 1
done

for i in {1..1000}; do
    ./aes128_ecb_w &
    ./aes128_ecb_r
    # sleep 1
done

for i in {1..1000}; do
    ./aes192_cbc_w &
    ./aes192_cbc_r
    # sleep 1
done

for i in {1..1000}; do
    ./aes192_ecb_w &
    ./aes192_ecb_r
    # sleep 1
done

for i in {1..1000}; do
    ./aes256_cbc_w &
    ./aes256_cbc_r
    # sleep 1
done

for i in {1..1000}; do
    ./aes256_ecb_w &
    ./aes256_ecb_r
    # sleep 1
done

for i in {1..1000}; do
    ./des_cbc_w &
    ./des_cbc_r
    # sleep 1
done

for i in {1..1000}; do
    ./des_ecb_w &
    ./des_ecb_r
    # sleep 1
done

sleep 1
# Run the averager script after all the loops are done
./averager
sleep 1
python3 plotter.py