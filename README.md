# desavx

[![Go Reference](https://pkg.go.dev/badge/github.com/andjam/desavx.svg)](https://pkg.go.dev/github.com/andjam/desavx)

Package desavx implements the Data Encryption Standard (DES) as described
in chapter 7.4 of Handbook of Applied Cryptography, 1997. DES proceeds in 16
rounds, processing 64-bit plaintext blocks into 64-bit ciphertext blocks
using a 56-bit key. This implementation utilises x86 AVX extensions to work
on multiple blocks of plaintext simultaneously.
