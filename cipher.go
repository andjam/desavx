//go:build amd64
// +build amd64

package desavx

// desECBCrypt encrypts or decrypts bytes from src to dst using DES in
// electronic code book mode. It proceeds in 16 rounds using the keys in the
// subkeys array, and continues to process blocks until it reaches the end
// of src or dst. Only blocks up to a multiple of 8 are processed, any
// additional data in src is ignored.
func desECBCrypt(subkeys *[rounds]qw, dst []byte, src []byte)
