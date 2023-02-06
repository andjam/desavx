# des-avx

[![Go Reference](https://pkg.go.dev/badge/github.com/andjam/des-avx.svg)](https://pkg.go.dev/github.com/andjam/des-avx)

Package des-avx implements the Data Encryption Standard (DES) as described in
chapter 7.4 of Handbook of Applied Cryptography. DES proceeds in 16 rounds,
processing 64-bit plaintext blocks into 64-bit ciphertext blocks using a
56-bit key. This implementation utilises x86 AVX extensions to work on
multiple blocks of plaintext simultaneously. It can be used as follows.

```go
// The length of plaintext must be a multiple of 8
plaintext := []byte("exampleplaintext")
ciphertext := make([]byte, len(plaintext))

// DES keys must be 8 bytes
key, _ := hex.DecodeString("deadbeefdeadc0de")
des.NewDESECBEncrypter(key).CryptBlocks(ciphertext, plaintext) // Encrypt
des.NewDESECBDecrypter(key).CryptBlocks(ciphertext, ciphertext) // Decrypt

// DES3 keys must be 24 bytes
key, _ = hex.DecodeString("deadbeefdeadc0defeedbabef00dbabebaadf00dbaaaaaad")
des.NewDES3ECBEncrypter(key).CryptBlocks(ciphertext, ciphertext) // Encrypt
des.NewDES3ECBDecrypter(key).CryptBlocks(ciphertext, ciphertext) // Decrypt

fmt.Println(string(ciphertext)) // exampleplaintext
```
