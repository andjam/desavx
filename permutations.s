//go:build amd64
// +build amd64

#include "textflag.h"
#include "go_asm.h"

TEXT bitGroupSwapVec2(SB),NOSPLIT|NOFRAME,$0
#define mask  AX
#define shift BX
	MOVQ   shift, X1
	VPSRLQ X1, X0, X2
	VPXOR  X0, X2, X2

	MOVQ         mask, X3
	VPBROADCASTQ X3, X3

	VPAND  X2, X3, X2
	VPSLLQ X1, X2, X3
	VPXOR  X2, X3, X2
	VPXOR  X2, X0, X0
#undef mask
#undef shift
	RET

TEXT bitGroupLeftShiftVec2(SB),NOSPLIT|NOFRAME,$0
#define mask  AX
#define shift BX
	MOVQ         mask, X5
	VPBROADCASTQ X5, X5
	VPAND        X0, X5, X5
	MOVQ         shift, X2
	VPSLLQ       X2, X5, X5
	VPXOR        X1, X5, X1
#undef mask
#undef shift
	RET

TEXT bitGroupLeftRotateVec2(SB),NOSPLIT|NOFRAME,$0
#define mask  AX
#define shift BX
#define wrap  CX
	MOVQ         mask, X4
	VPBROADCASTQ X4, X4
	VPAND        X0, X4, X4

	MOVQ   shift, X2
	VPSLLQ X2, X4, X2
	VPXOR  X1, X2, X1
	MOVQ   $const_v64Size*8, R14
	SUBQ   wrap, R14
	MOVQ   R14, X3
	VPSLLQ X3, X1, X1
	VPSRLQ X3, X1, X1

	SUBQ   shift, wrap
	MOVQ   wrap, X2
	VPSRLQ X2, X4, X4

	VPXOR  X1, X4, X1
#undef mask
#undef shift
#undef wrap
	RET

TEXT ·ip(SB),NOSPLIT,$16
	MOVQ ·in(FP), X0
	CALL ipVec2(SB)
	MOVQ X0, ·ret+8(FP)
	RET

TEXT ·ipVec2(SB),NOSPLIT,$32
	VMOVDQU ·in(FP), X0
	CALL    ipVec2(SB)
	VMOVDQU X0, ·ret+16(FP)
	RET

TEXT ipVec2(SB),NOSPLIT|NOFRAME,$0
	MOVQ $33, BX
	MOVQ $0x0000000055555555, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $12, BX
	MOVQ $0x0000f0f00000f0f0, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $6, BX
	MOVQ $0x00cc00cc00cc00cc, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $5, BX
	MOVQ $0x0202020202020202, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $4, BX
	MOVQ $0x0909090909090909, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $1, BX
	MOVQ $0x4949494949494949, AX
	CALL bitGroupSwapVec2(SB)
	RET

TEXT ·ipInverse(SB),NOSPLIT,$16
	MOVQ ·in(FP), X0
	CALL ipInverseVec2(SB)
	MOVQ X0, ·ret+8(FP)
	RET

TEXT ·ipInverseVec2(SB),NOSPLIT,$32
	VMOVDQU ·in(FP), X0
	CALL ipInverseVec2(SB)
	VMOVDQU X0, ·ret+16(FP)
	RET

TEXT ipInverseVec2(SB),NOSPLIT|NOFRAME,$0
	MOVQ $1, BX
	MOVQ $0x4949494949494949, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $4, BX
	MOVQ $0x0909090909090909, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $5, BX
	MOVQ $0x0202020202020202, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $6, BX
	MOVQ $0x00cc00cc00cc00cc, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $12, BX
	MOVQ $0x0000f0f00000f0f0, AX
	CALL bitGroupSwapVec2(SB)

	MOVQ $33, BX
	MOVQ $0x0000000055555555, AX
	CALL bitGroupSwapVec2(SB)
	RET

TEXT ·pc1(SB),NOSPLIT,$16
	MOVQ ·in(FP), X0
	CALL pc1Vec2(SB)
	MOVQ X0, ·ret+8(FP)
	RET

TEXT ·pc1Vec2(SB),NOSPLIT,$32
	VMOVDQU ·in(FP), X0
	CALL    pc1Vec2(SB)
	VMOVDQU X0, ·ret+16(FP)
	RET

TEXT pc1Vec2(SB),NOSPLIT|NOFRAME,$0
	VPXOR X1, X1, X1

	MOVQ $64, CX
	MOVQ $4, BX
	MOVQ $0x1000000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $0, BX
	MOVQ $0x0000000010000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ $1, BX
	MOVQ $0x0800000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $3, BX
	MOVQ $0x0000800000000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ $5, BX
	MOVQ $0x0010004000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $7, BX
	MOVQ $0x0000000020000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ$ 8, BX
	MOVQ $0x0000000000020408, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ$ 9, BX
	MOVQ $0x0000000000100000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 10, BX
	MOVQ $0x0408000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ$ 12, BX
	MOVQ $0x0000008000000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 14, BX
	MOVQ $0x0000100040000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ$ 16, BX
	MOVQ $0x0000000000200000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ$ 17, BX
	MOVQ $0x0000000000000204, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ$ 18, BX
	MOVQ $0x0000000000001000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 19, BX
	MOVQ $0x0204080000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ$ 21, BX
	MOVQ $0x0000000080000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 23, BX
	MOVQ $0x0000001000400000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ$ 25, BX
	MOVQ $0x0000000000002000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ$ 26, BX
	MOVQ $0x0000000000000002, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 27, BX
	MOVQ $0x2000000000000010, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 28, BX
	MOVQ $0x0002040800000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ$ 30, BX
	MOVQ $0x0000000000800000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ$ 32, BX
	MOVQ $0x0000000000004000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 34, BX
	MOVQ $0x4000000000000020, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 36, BX
	MOVQ $0x0020000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 37, BX
	MOVQ $0x0000020408000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ$ 39, BX
	MOVQ $0x0000000000008000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 41, BX
	MOVQ $0x8000000000000040, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 43, BX
	MOVQ $0x0040000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 45, BX
	MOVQ $0x0000200000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 46, BX
	MOVQ $0x0000000204080000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ$ 48, BX
	MOVQ $0x0000000000000080, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $56, CX
	MOVQ$ 50, BX
	MOVQ $0x0080000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 52, BX
	MOVQ $0x0000400000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ$ 54, BX
	MOVQ $0x0000002000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $56, CX
	MOVQ $55, BX
	MOVQ $0x0000000002040800, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ X1, X0
	RET

TEXT ·pc2(SB),NOSPLIT,$16
	MOVQ ·in(FP), X0
	CALL pc2Vec2(SB)
	MOVQ X0, ·ret+8(FP)
	RET

TEXT ·pc2Vec2(SB),NOSPLIT,$32
	VMOVDQU ·in(FP), X0
	CALL pc2Vec2(SB)
	VMOVDQU X0, ·ret+16(FP)
	RET

TEXT pc2Vec2(SB),NOSPLIT|NOFRAME,$0
	VPXOR X1, X1, X1

	MOVQ $0, BX
	MOVQ $0x0000200000010000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $1, BX
	MOVQ $0x0000000040080000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $2, BX
	MOVQ $0x0000000a00000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $3, BX
	MOVQ $0x0000000000000888, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $4, BX
	MOVQ $0x0000000000000100, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $5, BX
	MOVQ $0x0000040000000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $7, BX
	MOVQ $0x0000008000000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $8, BX
	MOVQ $0x0000000000008001, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $10, BX
	MOVQ $0x0000000000000220, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $12, BX
	MOVQ $0x0000000110000000, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $17, BX
	MOVQ $0x0000000000000002, AX
	CALL bitGroupLeftShiftVec2(SB)

	MOVQ $48, CX
	MOVQ $18, BX
	MOVQ $0x0040000000000010, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $22, BX
	MOVQ $0x0000000008000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $24, BX
	MOVQ $0x0000000001000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $27, BX
	MOVQ $0x0002000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $28, BX
	MOVQ $0x0010000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $30, BX
	MOVQ $0x0001080000100000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $33, BX
	MOVQ $0x0000000000400000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $36, BX
	MOVQ $0x00a4000000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $37, BX
	MOVQ $0x0000110000000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $38, BX
	MOVQ $0x0000401000804000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $39, BX
	MOVQ $0x0008000004000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $40, BX
	MOVQ $0x0000000000020000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $43, BX
	MOVQ $0x0000000000000400, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $44, BX
	MOVQ $0x0000000002000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $45, BX
	MOVQ $0x0000002000000040, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $46, BX
	MOVQ $0x0000020020000000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ $48, CX
	MOVQ $47, BX
	MOVQ $0x0000000000001000, AX
	CALL bitGroupLeftRotateVec2(SB)

	MOVQ X1, X0
	RET
