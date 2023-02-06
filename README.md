# des-avx

[![Go Reference](https://pkg.go.dev/badge/github.com/andjam/des-avx.svg)](https://pkg.go.dev/github.com/andjam/des-avx)

Package des-avx implements the Data Encryption Standard (DES) as described in
chapter 7.4 of Handbook of Applied Cryptography. DES proceeds in 16 rounds,
processing 64-bit plaintext blocks into 64-bit ciphertext blocks using a
56-bit key. This implementation utilises x86 AVX extensions to work on
multiple blocks of plaintext simultaneously.
