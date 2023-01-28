# desavx

Package desavx implements the Data Encryption Standard (DES) as described
in chapter 7.4 of Handbook of Applied Cryptography. DES proceeds in 16
rounds, processing 64-bit plaintext blocks into 64-bit ciphertext blocks
using a 56-bit key. This implementation utilises x86 AVX extensions to
work on multiple blocks of plaintext simultaneously. It can be used as
follows.

```go
// The length of the key must be 8 bytes, though 8 of its bits are
// discarded
key, _ := hex.DecodeString("deadbeefdeadbeef")
mode := desavx.NewDESECBEncrypter(key)

// The length of plaintext must be a multiple of 8 (the block size),
// and will otherwise require padding
plaintext := []byte("exampleplaintext")

ciphertext := make([]byte, len(plaintext))
mode.CryptBlocks(ciphertext, plaintext)
```
