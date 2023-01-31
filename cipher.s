//go:build amd64
// +build amd64

#include "textflag.h"
#include "go_asm.h"

TEXT feistel(SB),NOSPLIT,$80
#define subkeysptr AX // *[rounds]v64
#define in         Y0 // [4]v64
#define out        Y0 // [4]v64

	MOVQ    SI, (SP)
	MOVQ    R8, 8(SP)
	VMOVDQU Y8, 16(SP)
	VMOVDQU Y9, 48(SP)
#define left  Y8
#define right Y9
	VPSRLQ $const_v32Size*8, in, left
	VPSLLQ $const_v32Size*8, in, right
	VPSRLQ $const_v32Size*8, right, right

	LEAQ const_rounds*const_v64Size(subkeysptr), R8
	MOVQ subkeysptr, SI

	MOVQ         $0x8000000000000000, DX
	MOVQ         DX, X6
	VPBROADCASTQ X6, Y6

loopstart:
	MOVQ    (SI), AX
	VMOVDQU right, out
	CALL    fVec4(SB)
	VPXOR   left, out, out
	VMOVDQU right, left
	VMOVDQU out, right

	ADDQ $const_v64Size, SI
	CMPQ SI, R8
	JNE  loopstart

	VPSLLQ $const_v32Size*8, right, right
	VPXOR  right, left, out

#undef left
#undef right
	MOVQ    (SP), SI
	MOVQ    8(SP), R8
	VMOVDQU 16(SP), Y8
	VMOVDQU 48(SP), Y9

#undef subkeysptr
#undef in
#undef out
	RET

TEXT ·desECBCrypt(SB),NOSPLIT,$56
	MOVQ R8, (SP)
	MOVQ DI, 8(SP)
	MOVQ SI, 16(SP)
	MOVQ R12, 24(SP)
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

cryptfour:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*4, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptthree
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*4, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptthree

	VMOVDQU (srcptr), Y0
	CALL    ipVec4(SB)
	MOVQ    subkeysptr, AX
	CALL    feistel(SB)
	CALL    ipInverseVec4(SB)
	VMOVDQU Y0, (dstptr)

	MOVQ dstnxt, dstptr
	MOVQ srcnxtptr, srcptr
	JMP  cryptfour

cryptthree:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*3, dstnxt
	CMPQ dstnxt, dstlen
	JG   crypttwo
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*3, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   crypttwo
	
	VPXOR        Y0, Y0, Y0
	PINSRQ       $0, const_v64Size*2(srcptr), X0
	VINSERTI128  $1, X0, Y0, Y0
	PINSRQ       $1, const_v64Size(srcptr), X0
	PINSRQ       $0, (srcptr), X0
	CALL         ipVec4(SB)
	MOVQ         subkeysptr, AX
	CALL         feistel(SB)
	CALL         ipInverseVec4(SB)
	PEXTRQ       $0, X0, (dstptr)
	PEXTRQ       $1, X0, const_v64Size(dstptr)
	VEXTRACTI128 $1, Y0, X0
	PEXTRQ       $0, X0, const_v64Size*2(dstptr)
	JMP          cryptend

crypttwo:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*2, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptone
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*2, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptone
	
	PINSRQ $0, (srcptr), X0
	PINSRQ $1, const_v64Size(srcptr), X0
	CALL   ipVec4(SB)
	MOVQ   subkeysptr, AX
	CALL   feistel(SB)
	CALL   ipInverseVec4(SB)
	PEXTRQ $0, X0, (dstptr)
	PEXTRQ $1, X0, const_v64Size(dstptr)
	JMP    cryptend

cryptone:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptend
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptend
	
	MOVQ (srcptr), X0
	CALL ipVec4(SB)
	MOVQ subkeysptr, AX
	CALL feistel(SB)
	CALL ipInverseVec4(SB)
	MOVQ X0, (dstptr)

cryptend:

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
	MOVQ SI, 16(SP)
	MOVQ R12, 24(SP)
	MOVQ R13, 32(SP)
	RET

TEXT ·desTripleECBCrypt(SB),NOSPLIT,$72
	MOVQ R8, (SP)
	MOVQ DI, 8(SP)
	MOVQ SI, 16(SP)
	MOVQ R12, 24(SP)
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

cryptfour:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*4, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptthree
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*4, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptthree

	VMOVDQU (srcptr), Y0
	CALL    ipVec4(SB)
	MOVQ    subkeysptr, AX
	CALL    feistel(SB)
	MOVQ    subkeysptr, AX
	ADDQ    $const_rounds*const_v64Size, AX
	CALL    feistel(SB)
	MOVQ    subkeysptr, AX
	ADDQ    $const_rounds*const_v64Size*2, AX
	CALL    feistel(SB)
	CALL    ipInverseVec4(SB)
	VMOVDQU Y0, (dstptr)

	MOVQ dstnxt, dstptr
	MOVQ srcnxtptr, srcptr
	JMP  cryptfour

cryptthree:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*3, dstnxt
	CMPQ dstnxt, dstlen
	JG   crypttwo
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*3, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   crypttwo
	
	VPXOR        Y0, Y0, Y0
	PINSRQ       $0, const_v64Size*2(srcptr), X0
	VINSERTI128  $1, X0, Y0, Y0
	PINSRQ       $1, const_v64Size(srcptr), X0
	PINSRQ       $0, (srcptr), X0
	CALL         ipVec4(SB)
	MOVQ         subkeysptr, AX
	CALL         feistel(SB)
	MOVQ         subkeysptr, AX
	ADDQ         $const_rounds*const_v64Size, AX
	CALL         feistel(SB)
	MOVQ         subkeysptr, AX
	ADDQ         $const_rounds*const_v64Size*2, AX
	CALL         feistel(SB)
	CALL         ipInverseVec4(SB)
	PEXTRQ       $0, X0, (dstptr)
	PEXTRQ       $1, X0, const_v64Size(dstptr)
	VEXTRACTI128 $1, Y0, X0
	PEXTRQ       $0, X0, const_v64Size*2(dstptr)
	JMP          cryptend

crypttwo:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size*2, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptone
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size*2, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptone
	
	PINSRQ $0, (srcptr), X0
	PINSRQ $1, const_v64Size(srcptr), X0
	CALL   ipVec4(SB)
	MOVQ   subkeysptr, AX
	CALL   feistel(SB)
	MOVQ   subkeysptr, AX
	ADDQ   $const_rounds*const_v64Size, AX
	CALL   feistel(SB)
	MOVQ   subkeysptr, AX
	ADDQ   $const_rounds*const_v64Size*2, AX
	CALL   feistel(SB)
	CALL   ipInverseVec4(SB)
	PEXTRQ $0, X0, (dstptr)
	PEXTRQ $1, X0, const_v64Size(dstptr)
	JMP    cryptend

cryptone:
	MOVQ dstptr, dstnxt
	ADDQ $const_v64Size, dstnxt
	CMPQ dstnxt, dstlen
	JG   cryptend
	MOVQ srcptr, srcnxtptr
	ADDQ $const_v64Size, srcnxtptr
	CMPQ srcnxtptr, srclen
	JG   cryptend
	
	MOVQ (srcptr), X0
	CALL ipVec4(SB)
	MOVQ subkeysptr, AX
	CALL feistel(SB)
	MOVQ subkeysptr, AX
	ADDQ $const_rounds*const_v64Size, AX
	CALL feistel(SB)
	MOVQ subkeysptr, AX
	ADDQ $const_rounds*const_v64Size*2, AX
	CALL feistel(SB)
	CALL ipInverseVec4(SB)
	MOVQ X0, (dstptr)

cryptend:

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
	MOVQ SI, 16(SP)
	MOVQ R12, 24(SP)
	MOVQ R13, 32(SP)
	RET
