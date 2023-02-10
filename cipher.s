//go:build amd64
// +build amd64

#include "textflag.h"
#include "go_asm.h"

TEXT feistel(SB),NOSPLIT,$80
	MOVQ    SI, (SP)
	MOVQ    R8, 8(SP)
	VMOVDQU Y8, 16(SP)
	VMOVDQU Y9, 48(SP)
#define subkeysptr AX // *[rounds]v64
#define in         Y0 // [4]v64
#define out        Y0 // [4]v64

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

#undef subkeysptr
#undef in
#undef out
	MOVQ    (SP), SI
	MOVQ    8(SP), R8
	VMOVDQU 16(SP), Y8
	VMOVDQU 48(SP), Y9
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

loopstart:
	MOVQ    srcptr, srcnxtptr
	ADDQ    $const_v64Size*4, srcnxtptr
	CMPQ    srcnxtptr, srclen
	JG      loadthree
	VMOVDQU (srcptr), Y0

	CALL ipVec4(SB)
	MOVQ subkeysptr, AX
	CALL feistel(SB)
	CALL ipInverseVec4(SB)

	MOVQ    dstptr, dstnxt
	ADDQ    $const_v64Size*4, dstnxt
	CMPQ    dstnxt, dstlen
	JG      loadthree
	VMOVDQU Y0, (dstptr)

	MOVQ dstnxt, dstptr
	MOVQ srcnxtptr, srcptr
	JMP  loopstart

loadthree:
	MOVQ        srcptr, srcnxtptr
	ADDQ        $const_v64Size*3, srcnxtptr
	CMPQ        srcnxtptr, srclen
	JG          loadtwo
	PINSRQ      $0, const_v64Size*2(srcptr), X0
	VINSERTI128 $1, X0, Y0, Y0
loadtwo:
	MOVQ        srcptr, srcnxtptr
	ADDQ        $const_v64Size*2, srcnxtptr
	CMPQ        srcnxtptr, srclen
	JG          loadone
	PINSRQ      $1, const_v64Size(srcptr), X0
loadone:
	MOVQ        srcptr, srcnxtptr
	ADDQ        $const_v64Size, srcnxtptr
	CMPQ        srcnxtptr, srclen
	JG          end
	PINSRQ      $0, (srcptr), X0

	CALL ipVec4(SB)
	MOVQ subkeysptr, AX
	CALL feistel(SB)
	CALL ipInverseVec4(SB)

extractthree:
	MOVQ         dstptr, dstnxt
	ADDQ         $const_v64Size*3, dstnxt
	CMPQ         dstnxt, dstlen
	JG           extracttwo
	VEXTRACTI128 $1, Y0, X1
	PEXTRQ       $0, X1, const_v64Size*2(dstptr)
extracttwo:
	MOVQ         dstptr, dstnxt
	ADDQ         $const_v64Size*2, dstnxt
	CMPQ         dstnxt, dstlen
	JG           extractone
	PEXTRQ       $1, X0, const_v64Size(dstptr)
extractone:
	MOVQ         dstptr, dstnxt
	ADDQ         $const_v64Size, dstnxt
	CMPQ         dstnxt, dstlen
	PEXTRQ       $0, X0, (dstptr)

end:

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

loopstart:
	MOVQ    dstptr, dstnxt
	ADDQ    $const_v64Size*4, dstnxt
	CMPQ    dstnxt, dstlen
	JG      loadthree
	VMOVDQU (srcptr), Y0

	CALL ipVec4(SB)
	LEAQ (subkeysptr), AX
	CALL feistel(SB)
	LEAQ const_rounds*const_v64Size(subkeysptr), AX
	CALL feistel(SB)
	LEAQ const_rounds*const_v64Size*2(subkeysptr), AX
	CALL feistel(SB)
	CALL ipInverseVec4(SB)

	MOVQ    srcptr, srcnxtptr
	ADDQ    $const_v64Size*4, srcnxtptr
	CMPQ    srcnxtptr, srclen
	JG      loadthree
	VMOVDQU Y0, (dstptr)

	MOVQ dstnxt, dstptr
	MOVQ srcnxtptr, srcptr
	JMP  loopstart

loadthree:
	MOVQ        srcptr, srcnxtptr
	ADDQ        $const_v64Size*3, srcnxtptr
	CMPQ        srcnxtptr, srclen
	JG          loadtwo
	PINSRQ      $0, const_v64Size*2(srcptr), X0
	VINSERTI128 $1, X0, Y0, Y0
loadtwo:
	MOVQ        srcptr, srcnxtptr
	ADDQ        $const_v64Size*2, srcnxtptr
	CMPQ        srcnxtptr, srclen
	JG          loadone
	PINSRQ      $1, const_v64Size(srcptr), X0
loadone:
	MOVQ        srcptr, srcnxtptr
	ADDQ        $const_v64Size, srcnxtptr
	CMPQ        srcnxtptr, srclen
	JG          end
	PINSRQ      $0, (srcptr), X0

	CALL ipVec4(SB)
	LEAQ (subkeysptr), AX
	CALL feistel(SB)
	LEAQ const_rounds*const_v64Size(subkeysptr), AX
	CALL feistel(SB)
	LEAQ const_rounds*const_v64Size*2(subkeysptr), AX
	CALL feistel(SB)
	CALL ipInverseVec4(SB)

extractthree:
	MOVQ         dstptr, dstnxt
	ADDQ         $const_v64Size*3, dstnxt
	CMPQ         dstnxt, dstlen
	JG           extracttwo
	VEXTRACTI128 $1, Y0, X1
	PEXTRQ       $0, X1, const_v64Size*2(dstptr)
extracttwo:
	MOVQ         dstptr, dstnxt
	ADDQ         $const_v64Size*2, dstnxt
	CMPQ         dstnxt, dstlen
	JG           extractone
	PEXTRQ       $1, X0, const_v64Size(dstptr)
extractone:
	MOVQ         dstptr, dstnxt
	ADDQ         $const_v64Size, dstnxt
	CMPQ         dstnxt, dstlen
	PEXTRQ       $0, X0, (dstptr)

end:

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
