# desavx

[![Go Reference](https://pkg.go.dev/badge/github.com/andjam/desavx.svg)](https://pkg.go.dev/github.com/andjam/desavx)

Package desavx is an experimental implementation of the Data Encryption
Standard (DES) as described in chapter 7.4 of Handbook of Applied
Cryptography Menezes, van Oorschot, Vanstone, 1997. DES is a symmetric-key
block cipher. It proceeds in 16 rounds, processing 64-bit plaintext blocks
into 64-bit ciphertext blocks using a 56-bit key. This implementation uses
AVX extensions to work on multiple blocks of plaintext simultaneously.
