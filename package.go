//go:build amd64
// +build amd64

// Package desavx implements the Data Encryption Standard (DES) as described in
// chapter 7.4 of Handbook of Applied Cryptography. DES proceeds in 16 rounds,
// processing 64-bit plaintext blocks into 64-bit ciphertext blocks using a
// 56-bit key. This implementation utilises x86 AVX extensions to work on
// multiple blocks of plaintext simultaneously. It can be used as follows.
//
//  // The length of plaintext must be a multiple of 8
//  plaintext := []byte("exampleplaintext")
//  ciphertext := make([]byte, len(plaintext))
//
//  // DES keys must be 8 bytes
//  key, _ := hex.DecodeString("deadbeefdeadc0de")
//  desavx.NewDESECBEncrypter(key).CryptBlocks(ciphertext, plaintext) // Encrypt
//  desavx.NewDESECBDecrypter(key).CryptBlocks(ciphertext, ciphertext) // Decrypt
//
//  // DES3 keys must be 24 bytes
//  key, _ = hex.DecodeString("deadbeefdeadc0defeedbabef00dbabebaadf00dbaaaaaad")
//  desavx.NewDES3ECBEncrypter(key).CryptBlocks(ciphertext, ciphertext) // Encrypt
//  desavx.NewDES3ECBDecrypter(key).CryptBlocks(ciphertext, ciphertext) // Decrypt
//
//  fmt.Println(string(ciphertext)) // exampleplaintext
package desavx

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/cpu"
)

type (
	v32 uint32
	v64 uint64
)

const (
	rounds = 16

	v32Size = int(unsafe.Sizeof(v32(0)))
	v64Size = int(unsafe.Sizeof(v64(0)))
)

var (
	ErrAVXSupport = errors.New("desavx: AVX support required")
	ErrKeySize    = errors.New("desavx: invalid key size")
	ErrInputSize  = errors.New("desavx: invalid input size")
	ErrInternal   = errors.New("desavx: something unexpected happened")
)

func init() {
	if !cpu.X86.HasAVX {
		panic(ErrAVXSupport)
	}
}

// desECB is a cipher.BlockMode compatible type which encrypts (or decrypts)
// plaintext bytes using DES in electronic coodebook mode. The 16 48-bit DES
// subkeys are stored in the lower 48 bits of the 16 v64 items in the subkeys
// array.
type desECB struct {
	subkeys [rounds]v64
}

func (_ desECB) BlockSize() int {
	return v64Size
}

// CryptBlocks encrypts (or decrypts) plaintext bytes from src to dst. It
// proceeds in 16 rounds using subkey[i] in round i.
//
// The length of src must be a multiple of 8 (the block size) and no greater
// than the length dst or CryptBlocks will panic. Additional care must to taken
// to ensure src and dst do not overlap.
func (de desECB) CryptBlocks(dst, src []byte) {
	if len(src)%v64Size != 0 {
		panic(ErrInputSize)
	}
	if len(dst) < len(src) {
		panic(ErrInputSize)
	}
	desECBCrypt(&de.subkeys, dst, src)
}

// desTripleECB is a cipher.BlockMode compatible type which triple encrypts (or
// decrypts) plaintext bytes using DES in electronic coodebook mode. The 16
// 48-bit DES subkeys used for stage i are stored in the lower 48 bits of each
// v64 item of the subkeys<i> array.
type desTripleECB struct {
	subkeys1,
	subkeys2,
	subkeys3 [rounds]v64
}

func (_ desTripleECB) BlockSize() int {
	return v64Size
}

// CryptBlocks encrypts (or decrypts) plaintext bytes from src to dst. It
// applies three stages of DES consecutively using the 16 subkeys in subkeys<i>
// in stage i.
//
// The length of src must be a multiple of 8 (the block size) and no greater
// than the length dst or CryptBlocks will panic. Additional care must to taken
// to ensure src and dst do not overlap.
func (dte desTripleECB) CryptBlocks(dst, src []byte) {
	if len(src)%v64Size != 0 {
		panic(ErrInputSize)
	}
	if len(dst) < len(src) {
		panic(ErrInputSize)
	}
	desTripleECBCrypt(&[3][rounds]v64{
		dte.subkeys1,
		dte.subkeys2,
		dte.subkeys3}, dst, src)
}

// Apply the left rotation of 1 or 2 to the 28-bit value stored in the lower 28
// bits of x, for round i, in accordance with the schedule defined in HoAC 7.83.
func rotation(x v64, i int) v64 {
	switch i {
	case 1, 2, 9, 16:
		return x<<37>>36 | x>>27
	case 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15:
		return x<<38>>36 | x>>26
	}
	panic(ErrInternal)
}

// Begin the key schedule described in HoAC 7.83. Compute the initial 28-bit C
// and D values (stored in the lower 28 bits of c and d) which will be iterated
// on successively in calls to ksNext, and used to generate the subkeys for each
// round.
func ksStart(key v64) (c, d v64) {
	t := pc1(key)
	c = t >> 28
	d = t << 36 >> 36
	return
}

// Continue the key schedule described in HoAC 7.83. Compute the 28-bit C and D
// values (stored in the lower 28 bits of c and d), and subkey for round i, from
// the C and D values from the previous round.
func ksNext(cprev, dprev v64, i int) (c, d, subkey v64) {
	c = rotation(cprev, i)
	d = rotation(dprev, i)
	subkey = pc2(c<<28 | d)
	return
}

// NewDESECBEncrypter returns a cipher.BlockMode which encrypts messages using
// DES in electronic coodebook mode. The key should be 8 bytes long, its
// effective size however, is only 56 bits as the least significant bit from
// each byte is ignored.
func NewDESECBEncrypter(key []byte) cipher.BlockMode {
	if len(key) != v64Size {
		panic(ErrKeySize)
	}
	keyUint64 := binary.LittleEndian.Uint64(key)

	var (
		c, d = ksStart(v64(keyUint64))

		mode   desECB
		subkey v64
	)
	for i := 0; i < rounds; i++ {
		c, d, subkey = ksNext(c, d, i+1)
		mode.subkeys[i] = subkey
	}
	return mode
}

// NewDESECBDecrypter returns a cipher.BlockMode which decrypts messages using
// DES in electronic coodebook mode. The key should be 8 bytes long, however,
// its effective size is only 56 bits as the least significant bit from each
// byte is ignored.
func NewDESECBDecrypter(key []byte) cipher.BlockMode {
	if len(key) != v64Size {
		panic(ErrKeySize)
	}
	keyUint64 := binary.LittleEndian.Uint64(key)

	var (
		c, d = ksStart(v64(keyUint64))

		mode   desECB
		subkey v64
	)
	for i := 0; i < rounds; i++ {
		c, d, subkey = ksNext(c, d, i+1)
		mode.subkeys[rounds-1-i] = subkey
	}
	return mode
}

// NewDES3ECBEncrypter returns a cipher.BlockMode which encrypts messages using
// DES3 in electronic coodebook mode. The key should be 24 bytes long, its
// effective size however, is only 168 bits as the least significant bit from
// each byte is ignored.
func NewDES3ECBEncrypter(key []byte) cipher.BlockMode {
	if len(key) != v64Size*3 {
		panic(ErrKeySize)
	}
	key1Uint64 := binary.LittleEndian.Uint64(key[:8])
	key2Uint64 := binary.LittleEndian.Uint64(key[8:16])
	key3Uint64 := binary.LittleEndian.Uint64(key[16:])

	var (
		c1, d1 = ksStart(v64(key1Uint64))
		c2, d2 = ksStart(v64(key2Uint64))
		c3, d3 = ksStart(v64(key3Uint64))

		mode   desTripleECB
		subkey v64
	)
	for i := 0; i < rounds; i++ {
		c1, d1, subkey = ksNext(c1, d1, i+1)
		mode.subkeys1[i] = subkey
		c2, d2, subkey = ksNext(c2, d2, i+1)
		mode.subkeys2[rounds-1-i] = subkey
		c3, d3, subkey = ksNext(c3, d3, i+1)
		mode.subkeys3[i] = subkey
	}
	return mode
}

// NewDES3ECBDecrypter returns a cipher.BlockMode which decrypts messages using
// DES3 in electronic coodebook mode. The key should be 24 bytes long, its its
// effective size however, is only 168 bits as the least significant bit from
// each byte is ignored.
func NewDES3ECBDecrypter(key []byte) cipher.BlockMode {
	if len(key) != v64Size*3 {
		panic(ErrKeySize)
	}
	key1Uint64 := binary.LittleEndian.Uint64(key[:8])
	key2Uint64 := binary.LittleEndian.Uint64(key[8:16])
	key3Uint64 := binary.LittleEndian.Uint64(key[16:])

	var (
		c1, d1 = ksStart(v64(key1Uint64))
		c2, d2 = ksStart(v64(key2Uint64))
		c3, d3 = ksStart(v64(key3Uint64))

		mode   desTripleECB
		subkey v64
	)
	for i := 0; i < rounds; i++ {
		c1, d1, subkey = ksNext(c1, d1, i+1)
		mode.subkeys3[rounds-1-i] = subkey
		c2, d2, subkey = ksNext(c2, d2, i+1)
		mode.subkeys2[i] = subkey
		c3, d3, subkey = ksNext(c3, d3, i+1)
		mode.subkeys1[rounds-1-i] = subkey
	}
	return mode
}
