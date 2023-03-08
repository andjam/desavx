# desavx

[![Go Reference](https://pkg.go.dev/badge/github.com/andjam/desavx.svg)](https://pkg.go.dev/github.com/andjam/desavx)

Package desavx implements the Data Encryption Standard (DES) as described
in chapter 7.4 of Handbook of Applied Cryptography (1997). DES proceeds in 16
rounds, processing 64-bit plaintext blocks into 64-bit ciphertext blocks
using a 56-bit key. This experimental implementation utilises Advanced
Vector Extensions to work on multiple blocks of plaintext simultaneously.
Exported are constructors for `cipher.BlockMode` objects which encrypt (or
decrypt) input in the form of a byte slice: `NewDESECBEncrypter` and
`NewDESECBDecrypter` for standard DES in electronic codebook mode; and
`NewDES3ECBEncrypter` and `NewDES3ECBDecrypter` for triple DES in electronic
codebook mode.
