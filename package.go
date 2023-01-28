//go:build amd64
// +build amd64

// Package desavx implements the Data Encryption Standard (DES) as described
// in chapter 7.4 of Handbook of Applied Cryptography. DES proceeds in 16
// rounds, processing 64-bit plaintext blocks into 64-bit ciphertext blocks
// using a 56-bit key. This implementation utilises x86 AVX extensions to
// work on multiple blocks of plaintext simultaneously. It can be used as
// follows.
//
//   // The length of the key must be 8 bytes, though 8 of its bits are
//   // discarded
//   key, _ := hex.DecodeString("deadbeefdeadbeef")
//   mode := desavx.NewDESECBEncrypter(key)
//
//   // The length of plaintext must be a multiple of 8 (the block size),
//   // and will otherwise require padding
//   plaintext := []byte("exampleplaintext")
//
//   ciphertext := make([]byte, len(plaintext))
//   mode.CryptBlocks(ciphertext, plaintext)
package desavx

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/cpu"
)

const (
	rounds = 16 // The number of feistel rounds used by DES
)

type (
	dw uint32 // A doubleword
	qw uint64 // A quadword
)

const (
	dwSize = int(unsafe.Sizeof(dw(0)))
	qwSize = int(unsafe.Sizeof(qw(0)))
)

var (
	ErrAVXSupport = errors.New("desavx: CPU requires AVX support")
	ErrKeySize    = errors.New("desavx: invalid key size")
	ErrInputSize  = errors.New("desavx: invalid input size")
	ErrInternal   = errors.New("desavx: something unexpected happened")
)

func init() {
	if !cpu.X86.HasAVX {
		panic(ErrAVXSupport)
	}
}

// desECB is a cipher.BlockMode compatible type which encrypts or decrypts
// plaintext bytes using DES in electronic code book mode.
type desECB struct {
	subkeys [rounds]qw
}

func (e desECB) BlockSize() int {
	return qwSize
}

// CryptBlocks encrypts or decrypts plaintext bytes from src to dst. It
// proceeds in 16 rounds using the 16 48-bit subkeys (stored in the lower 48
// bits of each 64 bit item) in the subkeys array. The first item is the
// subkey used in the first round, the second item is the subkey used in the
// the second round and so on.
//
// The length of src must be a multiple of 8 (the block size) and no greater
// than the length dst or CryptBlocks will panic. Additional care must to
// taken to ensure src and dst do not overlap.
func (e desECB) CryptBlocks(dst, src []byte) {
	if len(src)%qwSize != 0 {
		panic(ErrInputSize)
	}
	if len(dst) < len(src) {
		panic(ErrInputSize)
	}
	desECBCrypt(&e.subkeys, dst, src)
}

// Apply the left rotation of 1 or 2 to the 28-bit value stored in the lower
// 28 bits of x, for round i, in accordance with the schedule defined in
// HoAC 7.83.
func rotation(x qw, i int) qw {
	switch i {
	case 1, 2, 9, 16:
		return x<<37>>36 | x>>27
	case 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15:
		return x<<38>>36 | x>>26
	}
	panic(ErrInternal)
}

// Begin the key schedule described in HoAC 7.83. Compute the initial 28-bit
// C and D values (stored in the lower 28 bits of c and d) which will be
// iterated on successively in calls to ksNext, and used to generate the
// subkeys for each round.
func ksStart(key qw) (c, d qw) {
	t := pc1(key)
	c = t >> 28
	d = t << 36 >> 36
	return
}

// Continue the key schedule described in HoAC 7.83. Compute the 28-bit C
// and D values (stored in the lower 28 bits of c and d), and subkey for
// round i, from the C and D values from the previous round.
func ksNext(cprev, dprev qw, i int) (c, d, subkey qw) {
	c = rotation(cprev, i)
	d = rotation(dprev, i)
	subkey = pc2(c<<28 | d)
	return
}

// NewDESECBEncrypter returns a cipher.BlockMode which encrypts messages
// using DES in electronic code book mode. The key should be 8 bytes long,
// however, its effective size is only 56 bits as the least significant bit
// from each byte is ignored.
func NewDESECBEncrypter(key []byte) cipher.BlockMode {
	if len(key) != 8 {
		panic(ErrKeySize)
	}
	keyUint64 := binary.LittleEndian.Uint64(key)

	var (
		c, d = ksStart(qw(keyUint64))

		mode   desECB
		subkey qw
	)
	for i := 0; i < rounds; i++ {
		c, d, subkey = ksNext(c, d, i+1)
		mode.subkeys[i] = subkey
	}
	return mode
}

// NewDESECBDecrypter returns a cipher.BlockMode which decrypts messages
// using DES in electronic code book mode. The key should be 8 bytes long,
// however, its effective size is only 56 bits as the least significant bit
// from each byte is ignored.
func NewDESECBDecrypter(key []byte) cipher.BlockMode {
	if len(key) != 8 {
		panic(ErrKeySize)
	}
	keyUint64 := binary.LittleEndian.Uint64(key)

	var (
		c, d = ksStart(qw(keyUint64))

		mode   desECB
		subkey qw
	)
	for i := 0; i < rounds; i++ {
		c, d, subkey = ksNext(c, d, i+1)
		mode.subkeys[rounds-1-i] = subkey
	}
	return mode
}
