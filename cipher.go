//go:build amd64
// +build amd64

package desavx

// desECBCrypt (encrypts or decrypts) bytes from src to dst using DES in
// electronic coodebook mode. It continues to process blocks until it reaches
// the end of src or dst. Only blocks up to a multiple of 8 are processed, any
// additional data in src is ignored.
func desECBCrypt(subkeys *[rounds]qw, dst []byte, src []byte)

// desTripleECBCrypt triple encrypts (or decrypts) bytes from src to dst using
// DES in electronic coodebook mode. It continues to process blocks until it
// reaches the end of src or dst. Only blocks up to a multiple of 8 are
// processed, any additional data in src is ignored.
func desTripleECBCrypt(subkeysTriple *[3][rounds]qw, dst, src []byte)
