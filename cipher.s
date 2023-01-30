//go:build amd64
// +build amd64

#include "textflag.h"
#include "go_asm.h"

TEXT feistel(SB),NOSPLIT,$48
#define subkeysptr AX // *[rounds]v64
#define in         X0 // [2]v64
#define out        X0 // [2]v64

	MOVQ    SI, (SP)
	VMOVDQU X8, 16(SP)
	VMOVDQU X9, 32(SP)
#define left  X8
#define right X9
	VPSRLQ $const_v32Size*8, in, left
	VPSLLQ $const_v32Size*8, in, right
	VPSRLQ $const_v32Size*8, right, right

	LEAQ const_rounds*const_v64Size(subkeysptr), R15
	MOVQ subkeysptr, SI

loopstart:
	MOVQ    (SI), AX
	VMOVDQU right, out
	CALL    fVec2(SB)
	VPXOR   left, out, out
	VMOVDQU right, left
	VMOVDQU out, right

	ADDQ $const_v64Size, SI
	CMPQ SI, R15
	JNE  loopstart

	VPSLLQ $const_v32Size*8, right, right
	VPXOR  right, left, out

#undef left
#undef right
	MOVQ (SP), SI
	VMOVDQU 16(SP), X8
	VMOVDQU 32(SP), X9

#undef subkeysptr
#undef in
#undef out
	RET

TEXT ·desECBCrypt(SB),NOSPLIT,$56
	MOVQ R8, (SP)
	MOVQ DI, 8(SP)
	MOVQ R12, 16(SP)
	MOVQ SI, 24(SP)
	MOVQ R13, 32(SP)
#define subkeysptr R8  // *[rounds]v64
#define dstptr     DI  // []byte
#define dstlen     R12 // int
#define srcptr     SI  // []byte
#define srclen     R13 // int
	MOVQ main·subkeys(FP), subkeysptr
	MOVQ ·dst_base+8(FP), dstptr
	MOVQ ·dst_len+16(FP), dstlen
	MOVQ ·src_base+32(FP), srcptr
	MOVQ ·src_len+40(FP), srclen

	MOVQ R9, 40(SP)
	MOVQ R11, 48(SP)
#define dstnxt R9
#define srcnxtptr R11
	ADDQ dstptr, dstlen
	ADDQ srcptr, srclen

crypttwo:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*2, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptone
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*2, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptone

	VMOVDQU (srcptr), X0
	CALL    ipVec2(SB)
	MOVQ    subkeysptr, AX
	CALL    feistel(SB)
	CALL    ipInverseVec2(SB)
	VMOVDQU X0, (dstptr)

	MOVQ dstnxt, dstptr
	MOVQ srcnxtptr, srcptr
	JMP crypttwo

cryptone:
	MOVQ dstptr, dstnxt
	XORQ R14, R14
	ADDQ $const_v64Size, R14
	CMPQ R14, dstlen
	JG   cryptoneend
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptoneend
	
	MOVQ (srcptr), X0
	CALL ipVec2(SB)
	MOVQ subkeysptr, AX
	CALL feistel(SB)
	CALL ipInverseVec2(SB)
	MOVQ X0, (dstptr)

cryptoneend:

#undef dstnxt
#undef srcnxtptr
	MOVQ 40(SP), R9
	MOVQ 48(SP), R11

#undef subkeysptr
#undef dstptr
#undef dstlen
#undef srcptr
#undef srclen
	MOVQ R8, (SP)
	MOVQ DI, 8(SP)
	MOVQ R12, 16(SP)
	MOVQ SI, 24(SP)
	MOVQ R13, 32(SP)
	RET

TEXT ·desTripleECBCrypt(SB),NOSPLIT,$72
	MOVQ R8, (SP)
	MOVQ DI, 8(SP)
	MOVQ R12, 16(SP)
	MOVQ SI, 24(SP)
	MOVQ R13, 32(SP)
#define subkeysptr R8  // *[3][rounds]v64
#define dstptr     DI  // []byte
#define dstlen     R12 // int
#define srcptr     SI  // []byte
#define srclen     R13 // int
	MOVQ main·subkeysTriple(FP), subkeysptr
	MOVQ ·dst_base+8(FP), dstptr
	MOVQ ·dst_len+16(FP), dstlen
	MOVQ ·src_base+32(FP), srcptr
	MOVQ ·src_len+40(FP), srclen

	MOVQ R9, 40(SP)
	MOVQ R11, 48(SP)
#define dstnxt R9
#define srcnxtptr R11
	ADDQ dstptr, dstlen
	ADDQ srcptr, srclen

crypttwo:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*2, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptone
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*2, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptone

	VMOVDQU (srcptr), X0
	CALL    ipVec2(SB)
	MOVQ    subkeysptr, AX
	CALL    feistel(SB)
	MOVQ    subkeysptr, AX
	ADDQ    $const_rounds*const_v64Size, AX
	CALL    feistel(SB)
	MOVQ    subkeysptr, AX
	ADDQ    $const_rounds*const_v64Size*2, AX
	CALL    feistel(SB)
	CALL    ipInverseVec2(SB)
	VMOVDQU X0, (dstptr)

	MOVQ dstnxt, dstptr
	MOVQ srcnxtptr, srcptr
	JMP crypttwo

cryptone:
	MOVQ dstptr, dstnxt
	XORQ R14, R14
	ADDQ $const_v64Size, R14
	CMPQ R14, dstlen
	JG   cryptoneend
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptoneend
	
	MOVQ (srcptr), X0
	CALL ipVec2(SB)
	MOVQ subkeysptr, AX
	CALL feistel(SB)
	MOVQ subkeysptr, AX
	ADDQ $const_rounds*const_v64Size, AX
	CALL feistel(SB)
	MOVQ subkeysptr, AX
	ADDQ $const_rounds*const_v64Size*2, AX
	CALL feistel(SB)
	CALL ipInverseVec2(SB)
	MOVQ X0, (dstptr)

cryptoneend:

#undef dstnxt
#undef srcnxtptr
	MOVQ 40(SP), R9
	MOVQ 48(SP), R11

#undef subkeysptr
#undef dstptr
#undef dstlen
#undef srcptr
#undef srclen
	MOVQ R8, (SP)
	MOVQ DI, 8(SP)
	MOVQ R12, 16(SP)
	MOVQ SI, 24(SP)
	MOVQ R13, 32(SP)
	RET
