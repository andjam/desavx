package des

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

type (
	cryptTests struct {
		key     []byte
		in, out []byte
	}
)

func testCryptBlocks(
	modeFactory func([]byte) cipher.BlockMode,
	tests cryptTests,
) func(*testing.T) {
	return func(t *testing.T) {
		out := make([]byte, len(tests.out))
		modeFactory(tests.key).CryptBlocks(out, tests.in)

		if !bytes.Equal(out[:], tests.out[:]) {
			t.FailNow()
		}
	}
}

var (
	testExample = cryptTests{
		key: []byte{
			0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1,
		},
		in: []byte{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		},
		out: []byte{
			0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05,
		},
	}

	// NIST Special Publication 800-17 Appendix A
	// Sample outputs
	testsSample = cryptTests{
		key: []byte{
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		},
		in: []byte{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		out: []byte{
			0x95, 0xf8, 0xa5, 0xe5, 0xdd, 0x31, 0xd9, 0x00,
			0x95, 0xf8, 0xa5, 0xe5, 0xdd, 0x31, 0xd9, 0x00,
			0x95, 0xf8, 0xa5, 0xe5, 0xdd, 0x31, 0xd9, 0x00,
			0x95, 0xf8, 0xa5, 0xe5, 0xdd, 0x31, 0xd9, 0x00,
		},
	}

	// NIST Special Publication 800-17 Appendix B
	// Known answer tests table 1
	testsTable1 = cryptTests{
		key: []byte{
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		in: []byte{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		out: []byte{
			0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00,
			0xDD, 0x7F, 0x12, 0x1C, 0xA5, 0x01, 0x56, 0x19,
			0x2E, 0x86, 0x53, 0x10, 0x4F, 0x38, 0x34, 0xEA,
			0x4B, 0xD3, 0x88, 0xFF, 0x6C, 0xD8, 0x1D, 0x4F,
			0x20, 0xB9, 0xE7, 0x67, 0xB2, 0xFB, 0x14, 0x56,
			0x55, 0x57, 0x93, 0x80, 0xD7, 0x71, 0x38, 0xEF,
			0x6C, 0xC5, 0xDE, 0xFA, 0xAF, 0x04, 0x51, 0x2F,
			0x0D, 0x9F, 0x27, 0x9B, 0xA5, 0xD8, 0x72, 0x60,
			0xD9, 0x03, 0x1B, 0x02, 0x71, 0xBD, 0x5A, 0x0A,
			0x42, 0x42, 0x50, 0xB3, 0x7C, 0x3D, 0xD9, 0x51,
			0xB8, 0x06, 0x1B, 0x7E, 0xCD, 0x9A, 0x21, 0xE5,
			0xF1, 0x5D, 0x0F, 0x28, 0x6B, 0x65, 0xBD, 0x28,
			0xAD, 0xD0, 0xCC, 0x8D, 0x6E, 0x5D, 0xEB, 0xA1,
			0xE6, 0xD5, 0xF8, 0x27, 0x52, 0xAD, 0x63, 0xD1,
			0xEC, 0xBF, 0xE3, 0xBD, 0x3F, 0x59, 0x1A, 0x5E,
			0xF3, 0x56, 0x83, 0x43, 0x79, 0xD1, 0x65, 0xCD,
			0x2B, 0x9F, 0x98, 0x2F, 0x20, 0x03, 0x7F, 0xA9,
			0x88, 0x9D, 0xE0, 0x68, 0xA1, 0x6F, 0x0B, 0xE6,
			0xE1, 0x9E, 0x27, 0x5D, 0x84, 0x6A, 0x12, 0x98,
			0x32, 0x9A, 0x8E, 0xD5, 0x23, 0xD7, 0x1A, 0xEC,
			0xE7, 0xFC, 0xE2, 0x25, 0x57, 0xD2, 0x3C, 0x97,
			0x12, 0xA9, 0xF5, 0x81, 0x7F, 0xF2, 0xD6, 0x5D,
			0xA4, 0x84, 0xC3, 0xAD, 0x38, 0xDC, 0x9C, 0x19,
			0xFB, 0xE0, 0x0A, 0x8A, 0x1E, 0xF8, 0xAD, 0x72,
			0x75, 0x0D, 0x07, 0x94, 0x07, 0x52, 0x13, 0x63,
			0x64, 0xFE, 0xED, 0x9C, 0x72, 0x4C, 0x2F, 0xAF,
			0xF0, 0x2B, 0x26, 0x3B, 0x32, 0x8E, 0x2B, 0x60,
			0x9D, 0x64, 0x55, 0x5A, 0x9A, 0x10, 0xB8, 0x52,
			0xD1, 0x06, 0xFF, 0x0B, 0xED, 0x52, 0x55, 0xD7,
			0xE1, 0x65, 0x2C, 0x6B, 0x13, 0x8C, 0x64, 0xA5,
			0xE4, 0x28, 0x58, 0x11, 0x86, 0xEC, 0x8F, 0x46,
			0xAE, 0xB5, 0xF5, 0xED, 0xE2, 0x2D, 0x1A, 0x36,
			0xE9, 0x43, 0xD7, 0x56, 0x8A, 0xEC, 0x0C, 0x5C,
			0xDF, 0x98, 0xC8, 0x27, 0x6F, 0x54, 0xB0, 0x4B,
			0xB1, 0x60, 0xE4, 0x68, 0x0F, 0x6C, 0x69, 0x6F,
			0xFA, 0x07, 0x52, 0xB0, 0x7D, 0x9C, 0x4A, 0xB8,
			0xCA, 0x3A, 0x2B, 0x03, 0x6D, 0xBC, 0x85, 0x02,
			0x5E, 0x09, 0x05, 0x51, 0x7B, 0xB5, 0x9B, 0xCF,
			0x81, 0x4E, 0xEB, 0x3B, 0x91, 0xD9, 0x07, 0x26,
			0x4D, 0x49, 0xDB, 0x15, 0x32, 0x91, 0x9C, 0x9F,
			0x25, 0xEB, 0x5F, 0xC3, 0xF8, 0xCF, 0x06, 0x21,
			0xAB, 0x6A, 0x20, 0xC0, 0x62, 0x0D, 0x1C, 0x6F,
			0x79, 0xE9, 0x0D, 0xBC, 0x98, 0xF9, 0x2C, 0xCA,
			0x86, 0x6E, 0xCE, 0xDD, 0x80, 0x72, 0xBB, 0x0E,
			0x8B, 0x54, 0x53, 0x6F, 0x2F, 0x3E, 0x64, 0xA8,
			0xEA, 0x51, 0xD3, 0x97, 0x55, 0x95, 0xB8, 0x6B,
			0xCA, 0xFF, 0xC6, 0xAC, 0x45, 0x42, 0xDE, 0x31,
			0x8D, 0xD4, 0x5A, 0x2D, 0xDF, 0x90, 0x79, 0x6C,
			0x10, 0x29, 0xD5, 0x5E, 0x88, 0x0E, 0xC2, 0xD0,
			0x5D, 0x86, 0xCB, 0x23, 0x63, 0x9D, 0xBE, 0xA9,
			0x1D, 0x1C, 0xA8, 0x53, 0xAE, 0x7C, 0x0C, 0x5F,
			0xCE, 0x33, 0x23, 0x29, 0x24, 0x8F, 0x32, 0x28,
			0x84, 0x05, 0xD1, 0xAB, 0xE2, 0x4F, 0xB9, 0x42,
			0xE6, 0x43, 0xD7, 0x80, 0x90, 0xCA, 0x42, 0x07,
			0x48, 0x22, 0x1B, 0x99, 0x37, 0x74, 0x8A, 0x23,
			0xDD, 0x7C, 0x0B, 0xBD, 0x61, 0xFA, 0xFD, 0x54,
			0x2F, 0xBC, 0x29, 0x1A, 0x57, 0x0D, 0xB5, 0xC4,
			0xE0, 0x7C, 0x30, 0xD7, 0xE4, 0xE2, 0x6E, 0x12,
			0x09, 0x53, 0xE2, 0x25, 0x8E, 0x8E, 0x90, 0xA1,
			0x5B, 0x71, 0x1B, 0xC4, 0xCE, 0xEB, 0xF2, 0xEE,
			0xCC, 0x08, 0x3F, 0x1E, 0x6D, 0x9E, 0x85, 0xF6,
			0xD2, 0xFD, 0x88, 0x67, 0xD5, 0x0D, 0x2D, 0xFE,
			0x06, 0xE7, 0xEA, 0x22, 0xCE, 0x92, 0x70, 0x8F,
			0x16, 0x6B, 0x40, 0xB4, 0x4A, 0xBA, 0x4B, 0xD6},
	}
)

func TestDESCryptBlocks(t *testing.T) {
	t.Run("example", testCryptBlocks(
		NewDESECBEncrypter, testExample))
	t.Run("sample outputs", testCryptBlocks(
		NewDESECBEncrypter, testsSample))
	t.Run("known answer tests table 1", testCryptBlocks(
		NewDESECBEncrypter, testsTable1))
}

func TestDES3CryptBlocks(t *testing.T) {
	t.Run("example", testCryptBlocks(
		NewDES3ECBEncrypter,
		cryptTests{
			key: append(testExample.key,
				append(testExample.key,
					testExample.key...)...),
			in:  testExample.in,
			out: testExample.out}))
	t.Run("sample outputs", testCryptBlocks(
		NewDES3ECBEncrypter,
		cryptTests{
			key: append(testsSample.key,
				append(testsSample.key,
					testsSample.key...)...),
			in:  testsSample.in,
			out: testsSample.out}))
	t.Run("known answer tests table 1", testCryptBlocks(
		NewDES3ECBEncrypter,
		cryptTests{
			key: append(testsTable1.key,
				append(testsTable1.key,
					testsTable1.key...)...),
			in:  testsTable1.in,
			out: testsTable1.out}))
}
