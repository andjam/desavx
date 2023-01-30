//go:build amd64
// +build amd64

#include "textflag.h"
#include "go_asm.h"

TEXT f(SB),NOSPLIT,$8
	MOVQ R8, (SP)
#define subkey R8
#define in     X0
#define out    X0
	MOVQ AX, subkey
	CALL eVec2(SB)

	MOVQ         subkey, X1
	VPBROADCASTQ X1, X1
	VPXOR        X0, X1, X0
	CALL         substitutionVec2(SB)
	CALL         pVec2(SB)
#undef subkey
#undef in
#undef out
	MOVQ (SP), R8
	RET

TEXT feistel(SB),NOSPLIT,$56
	MOVQ    SI, (SP)
	MOVQ    R8, 8(SP)
	MOVQ    R9, 16(SP)
	VMOVDQU X8, 24(SP)
	VMOVDQU X9, 40(SP)
#define subkeysptr R8
#define in         X0
#define out        X0
	MOVQ   AX, subkeysptr
	VPSRLQ $const_v32Size*8, in, X8
	VPSLLQ $const_v32Size*8, in, X9
	VPSRLQ $const_v32Size*8, X9, X9

	MOVQ   $0, SI

loopstart:
	MOVQ    (subkeysptr)(SI*8), R9
	MOVQ    R9, AX
	VMOVDQU X9, X0
	CALL    f(SB)

	VPXOR   X8, X0, X0
	VMOVDQU X9, X8
	VMOVDQU X0, X9

	INCQ SI
	CMPQ SI, $const_rounds
	JNE  loopstart

	VPSLLQ $const_v32Size*8, X9, X9
	VPXOR  X9, X8, out
#undef subkeysptr
#undef in
#undef out
	MOVQ    (SP), SI
	MOVQ    8(SP), R8
	MOVQ    16(SP), R9
	VMOVDQU 24(SP), X8
	VMOVDQU 40(SP), X9
	RET

TEXT ·desECBCrypt(SB),NOSPLIT,$56
	MOVQ R8, (SP)
	MOVQ DI, 8(SP)
	MOVQ R12, 16(SP)
	MOVQ SI, 24(SP)
	MOVQ R13, 32(SP)
#define subkeysptr R8
#define dstptr     DI
#define dstlen     R12
#define srcptr     SI
#define srclen     R13
	MOVQ R9, 40(SP)
	MOVQ R11, 48(SP)
#define dstnxt R9
#define srcnxtptr R11
	MOVQ main·subkeys(FP), subkeysptr
	MOVQ ·dst_base+8(FP), dstptr
	MOVQ ·dst_len+16(FP), dstlen
	MOVQ ·src_base+32(FP), srcptr
	MOVQ ·src_len+40(FP), srclen

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
#define subkeysptr R8
#define dstptr     DI
#define dstlen     R12
#define srcptr     SI
#define srclen     R13
	MOVQ R9, 40(SP)
	MOVQ R11, 48(SP)
#define dstnxt R9
#define srcnxtptr R11
	MOVQ main·subkeysTriple(FP), subkeysptr
	MOVQ ·dst_base+8(FP), dstptr
	MOVQ ·dst_len+16(FP), dstlen
	MOVQ ·src_base+32(FP), srcptr
	MOVQ ·src_len+40(FP), srclen

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
