package desavx_test

import (
	"encoding/hex"
	"fmt"

	"github.com/andjam/desavx"
)

func Example() {
	// The length of plaintext must be a multiple of 8
	plaintext := []byte("exampleplaintext")
	ciphertext := make([]byte, len(plaintext))

	// DES keys must be 8 bytes
	key, _ := hex.DecodeString("deadbeefdeadc0de")
	desavx.NewDESECBEncrypter(key).CryptBlocks(ciphertext, plaintext)  // Encrypt
	desavx.NewDESECBDecrypter(key).CryptBlocks(ciphertext, ciphertext) // Decrypt

	// DES3 keys must be 24 bytes
	key, _ = hex.DecodeString("deadbeefdeadc0defeedbabef00dbabebaadf00dbaaaaaad")
	desavx.NewDES3ECBEncrypter(key).CryptBlocks(ciphertext, ciphertext) // Encrypt
	desavx.NewDES3ECBDecrypter(key).CryptBlocks(ciphertext, ciphertext) // Decrypt

	fmt.Println(string(ciphertext)) // Output: exampleplaintext
}
