/*
 * instruction length decoder (written by kaitek, modified by mercurysquad)
 * voodoo xnu kernel
 *
 * based on code from AntiHookExec 1.00, Copyright (c) 2004 Chew Keong TAN
 * opcode tables based on documentation from http://www.sandpile.org/
 *
 *   todo:   * support for instruction set extensions newer than SSSE3
 *           * verify that VT instructions are correctly decoded
 * AnV - Added better opcode + SSE4.1 + SSE4.2 support
 */

#define VERBOSE FALSE
//#define VERBOSE TRUE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/vm_map.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include "insn_patcher.h"

#define OP_HAS_MODRM		(1 << 0)
#define OP_PREFIX		(1 << 1)
#define OP_REX			(1 << 2)
#define OP_TWOBYTE		(1 << 3)
#define OP_THREEBYTE_38		(1 << 4)
#define OP_THREEBYTE_3A		(1 << 5)
#define OP_HAS_IMM8		(1 << 6)
#define OP_HAS_IMM16		(1 << 7)
#define OP_HAS_IMM32		(1 << 8)
#define OP_HAS_IMM64		(1 << 9)
#define OP_CHECK_66		(1 << 10)
#define OP_CHECK_67		(1 << 11)
#define OP_CHECK_REX		(1 << 12)
#define OP_HAS_DISP8		(1 << 13)
#define OP_HAS_DISP16		(1 << 14)
#define OP_HAS_DISP32		(1 << 15)
#define OP_UNDEFINED		(1 << 16)
#define OP_IA32_ONLY		(1 << 17)
#define OP_NEEDS_PATCH		(1 << 18)
#define OP_SPECIAL		(1 << 19)

#define OP_GROUP(n)		((n & 0xff) << 24)
#define OP_GROUP_MASK		(0xff << 24)
#define OP_GROUP_EXTRACT(n)	((n >> 24) & 0xff)

#define OP_OPERANDS		(OP_HAS_MODRM|OP_HAS_IMM8|OP_HAS_IMM16|OP_HAS_IMM32|	\
				OP_HAS_IMM64|OP_CHECK_66|OP_CHECK_67|OP_CHECK_REX|	\
				OP_HAS_DISP8|OP_HAS_DISP16|OP_HAS_DISP32)

#define PREF_NONE		(1 << 0)	// used for SSE opcodes with no prefix
#define PREF_F0			(1 << 1)	// LOCK
#define PREF_F2			(1 << 2)	// REPNE (or SSE)
#define PREF_F3			(1 << 3)	// REP (or SSE)
#define PREF_2E			(1 << 4)	// CS segment
#define PREF_36			(1 << 5)	// SS segment
#define PREF_3E			(1 << 6)	// DS segment
#define PREF_26			(1 << 7)	// ES segment
#define PREF_64			(1 << 8)	// FS segment
#define PREF_65			(1 << 9)	// GS segment
#define PREF_66			(1 << 10)	// operand size (or SSE)
#define PREF_67			(1 << 11)	// address size
#define PREF_REX		(1 << 12)	// REX byte (default operand size)
#define PREF_REX_W		(1 << 13)	// REX byte (64-bit operand size)

#define PREF_SSE_ALL		(PREF_NONE|PREF_F3|PREF_66|PREF_F2)

#define min(x,y)	((x < y) ? (x) : (y))

uint32_t prefix_table[256] =
{
	[0xf0] = PREF_F0,	[0xf2] = PREF_F2,	[0xf3] = PREF_F3,	[0x2e] = PREF_2E,
	[0x36] = PREF_36,	[0x3e] = PREF_3E,	[0x26] = PREF_26,	[0x64] = PREF_64,
	[0x65] = PREF_65,	[0x66] = PREF_66,	[0x67] = PREF_67,

	[0x40 ... 0x47] = PREF_REX,	// operand size unchanged
	[0x48 ... 0x4f] = PREF_REX_W,	// 64-bit operand size
};

// note: some instructions (such as VT in groups 7 and 9), are distinguished not only by different
//       reg values but by different r/m values -- this can be safely ignored for the purposes of
//       length decoding.

enum {
	GRP_1 = 1,	GRP_2,		GRP_3A,		GRP_3B,
	GRP_4,		GRP_5,		GRP_6,		GRP_7,
	GRP_8,		GRP_9,		GRP_10,		GRP_11,
	GRP_12,		GRP_13,		GRP_14,		GRP_15,
	GRP_16,		GRP_17A,	GRP_17B,
#ifdef EXTENDED_PATCHER
	GRP_FISTTP
#endif
};

uint32_t group_table[][8] = // inherits from parent table
{
	[GRP_1] = { // group 1 (80..83)
		[0 ... 7] = OP_HAS_MODRM,		// ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
	},
	[GRP_2] = { // group 2 (C0..C1, D0..D3)
		[0 ... 7] = OP_HAS_MODRM,		// ROL, ROR, RCL, RCR, SHL, SHR, SAL, SAR
	},
	[GRP_3A] = { // group 3a (F6)
		[0 ... 1] = OP_HAS_MODRM|OP_HAS_IMM8,	// TEST Ib/Iz, TEST Ib/Iz
		[2 ... 7] = OP_HAS_MODRM		// NOT, NEG, {MUL,IMUL,DIV,IDIV} AL/rAX
	},
	[GRP_3B] = { // group 3b (F7)
		[0 ... 1] = OP_HAS_MODRM|OP_CHECK_66,	// TEST Ib/Iz, TEST Ib/Iz
		[2 ... 7] = OP_HAS_MODRM		// NOT, NEG, {MUL,IMUL,DIV,IDIV} AL/rAX
	},
	[GRP_4] = { // group 4 (FE)
		[0 ... 1] = OP_HAS_MODRM,		// {INC,DEC} Eb
		[2 ... 7] = OP_UNDEFINED
	},
	[GRP_5] = { // group 5 (FF)
		[0 ... 3] = OP_HAS_MODRM,		// {INC,DEC} Ev, CALL {Ev,Mp}
#ifdef EXTENDED_PATCHER
		[4 ... 5] = OP_HAS_MODRM|OP_SPECIAL,	// JMP {Ev,Mp}
#else
		[4 ... 5] = OP_HAS_MODRM,		// JMP {Ev,Mp}
#endif
		[6] = OP_HAS_MODRM,			// PUSH Ev
		[7] = OP_UNDEFINED
	},
	[GRP_6] = { // group 6 (0F 00)
		[0 ... 5] = OP_HAS_MODRM|OP_SPECIAL,	// {SLDT,STR,LLDT,LTR,VERR,VERW} {Mw,Rv}
		[6 ... 7] = OP_UNDEFINED
	},
	[GRP_7] = { // group 7 (0F 01)
		[0 ... 4] = OP_HAS_MODRM|OP_SPECIAL,	// {SGDT,SIDT,LGDT,LIDT} Ms, SMSW Mw
		[5] = OP_UNDEFINED,
		[6 ... 7] = OP_HAS_MODRM|OP_SPECIAL	// LMSW {Mw,Rv}, INVLPG M (also: SWAPGS/RDTSCP)
	},
	[GRP_8] = { // group 8 (0F BA)
		[0 ... 3] = OP_UNDEFINED,
		[4 ... 7] = OP_HAS_MODRM|OP_HAS_IMM8	// BT, BTS, BTR, BTC
	},
	[GRP_9] = { // group 9 (0F C7)
		[0] = OP_UNDEFINED,
		[1] = OP_HAS_MODRM,			// CMPXCHG Mq
		[2 ... 5] = OP_UNDEFINED,
		[6 ... 7] = OP_HAS_MODRM		// todo: VT instructions with prefixes
	},
	[GRP_10] = { // group 10 (8F)
		[0] = OP_HAS_MODRM,			// POP Ev
		[1 ... 7] = OP_HAS_MODRM
	},
	[GRP_11] = { // group 11 (0F B9)
		[0 ... 7] = 0				// UD2
	},
	[GRP_12] = { // group 12 (C6..C7)
		[0] = OP_HAS_MODRM,			// MOV
		[1 ... 7] = OP_HAS_MODRM
	},
	[GRP_13] = { // group 13 (0F 71)
		[0 ... 1] = OP_UNDEFINED,
		[2] = OP_HAS_MODRM|OP_HAS_IMM8,		// PSRLW {PRq,VRo},Ib
		[3] = OP_UNDEFINED,
		[4] = OP_HAS_MODRM|OP_HAS_IMM8,		// PSRAW {PRq,VRo},Ib
		[5] = OP_UNDEFINED,
		[6] = OP_HAS_MODRM|OP_HAS_IMM8,		// PSLLW {PRq,VRo},Ib
		[7] = OP_UNDEFINED
	},
	[GRP_14] = { // group 14 (0F 72)
		[0 ... 1] = OP_UNDEFINED,
		[2] = OP_HAS_MODRM|OP_HAS_IMM8,		// PSRLD {PRq,VRo},Ib
		[3] = OP_UNDEFINED,
		[4] = OP_HAS_MODRM|OP_HAS_IMM8,		// PSRAD {PRq,VRo},Ib
		[5] = OP_UNDEFINED,
		[6] = OP_HAS_MODRM|OP_HAS_IMM8,		// PSLLD {PRq,VRo},Ib
		[7] = OP_UNDEFINED
	},
	[GRP_15] = { // group 15 (0F 73)
		[0 ... 1] = OP_UNDEFINED,
		[2 ... 3] = OP_HAS_MODRM|OP_HAS_IMM8,	// PSRLQ {PRq,VRo},Ib / PSRLDQ VRo,Ib
		[4 ... 5] = OP_UNDEFINED,
		[6 ... 7] = OP_HAS_MODRM|OP_HAS_IMM8	// PSLLQ {PRq,VRo},Ib / PSLLDQ Vro,Ib
	},
	[GRP_16] = { // group 16 (0F AE) -- todo: test XRSTOR M and LFENCE (and CLFLUSH M and SFENCE)
		[0 ... 7] = OP_HAS_MODRM,		// FX{SAVE,RSTOR} M512 / {LD,ST}MXCSR Md /
							// X{SAVE,RSTOR} M or LFENCE / MFENCE / CLFLUSH M or SFENCE
	},
	[GRP_17A] = { // group 17a (0F 18)
		[0 ... 3] = OP_HAS_MODRM,		// PREFETCH{NTA,T0,T1,T2} M
		[4 ... 7] = OP_HAS_MODRM		// HINT_NOP Ev
	},
	[GRP_17B] = { // group 17b (0F 19..1F)
		[0 ... 7] = OP_HAS_MODRM		// HINT_NOP Ev
	},
#ifdef EXTENDED_PATCHER
	[GRP_FISTTP] = { // (DF, DB, DD)
		[0] = OP_HAS_MODRM,
		[1] = OP_HAS_MODRM|OP_NEEDS_PATCH,	// FISTTP
		[2 ... 7] = OP_HAS_MODRM
	}
#endif
};

uint32_t one_byte_table[256] =
{
	OP_HAS_MODRM|OP_SPECIAL,	// 00: ADD Eb,Gb
	OP_HAS_MODRM,			// 01: ADD Ev,Gv
	OP_HAS_MODRM,			// 02: ADD Gb,Eb
	OP_HAS_MODRM,			// 03: ADD Gv,Ev
	OP_HAS_IMM8,			// 04: ADD AL,Ib
	OP_CHECK_66,			// 05: ADD rAX,Iz
	OP_IA32_ONLY|OP_SPECIAL,	// 06: PUSH ES
	OP_IA32_ONLY|OP_SPECIAL,	// 07: POP ES

	OP_HAS_MODRM,			// 08: OR Eb,Gb
	OP_HAS_MODRM,			// 09: OR Ev,Gv
	OP_HAS_MODRM,			// 0A: OR Gb,Eb
	OP_HAS_MODRM,			// 0B: OR Gv,Ev
	OP_HAS_IMM8,			// 0C: OR AL,Ib
	OP_CHECK_66,			// 0D: OR rAX,Iz
	OP_IA32_ONLY|OP_SPECIAL,	// 0E: PUSH CS
	OP_TWOBYTE,			// 0F: 2-byte escape

	OP_HAS_MODRM,			// 10: ADC Eb,Gb
	OP_HAS_MODRM,			// 11: ADC Ev,Gv
	OP_HAS_MODRM,			// 12: ADC Gb,Eb
	OP_HAS_MODRM,			// 13: ADC Gv,Ev
	OP_HAS_IMM8,			// 14: ADC AL,Ib
	OP_CHECK_66,			// 15: ADC rAX,Iz
	OP_IA32_ONLY|OP_SPECIAL,	// 16: PUSH SS
	OP_IA32_ONLY|OP_SPECIAL,	// 17: POP SS

	OP_HAS_MODRM,			// 18: SBB Eb,Gb
	OP_HAS_MODRM,			// 19: SBB Ev,Gv
	OP_HAS_MODRM,			// 1A: SBB Gb,Eb
	OP_HAS_MODRM,			// 1B: SBB Gv,Ev
	OP_HAS_IMM8,			// 1C: SBB AL,Ib
	OP_CHECK_66,			// 1D: SBB rAX,Iz
	OP_IA32_ONLY|OP_SPECIAL,	// 1E: PUSH DS
	OP_IA32_ONLY|OP_SPECIAL,	// 1F: POP DS

	OP_HAS_MODRM,			// 20: AND Eb,Gb
	OP_HAS_MODRM,			// 21: AND Ev,Gv
	OP_HAS_MODRM,			// 22: AND Gb,Eb
	OP_HAS_MODRM,			// 23: AND Gv,Ev
	OP_HAS_IMM8,			// 24: AND AL,Ib
	OP_CHECK_66,			// 25: AND rAX,Iz
	OP_PREFIX,			// 26: ES prefix
	OP_IA32_ONLY|OP_SPECIAL,	// 27: DAA

	OP_HAS_MODRM,			// 28: SUB Eb,Gb
	OP_HAS_MODRM,			// 29: SUB Ev,Gv
	OP_HAS_MODRM,			// 2A: SUB Gb,Eb
	OP_HAS_MODRM,			// 2B: SUB Gv,Ev
	OP_HAS_IMM8,			// 2C: SUB AL,Ib
	OP_CHECK_66,			// 2D: SUB rAX,Iz
	OP_PREFIX,			// 2E: CS prefix (hint not taken for Jcc)
	OP_IA32_ONLY|OP_SPECIAL,	// 2F: DAS

	OP_HAS_MODRM,			// 30: XOR Eb,Gb
	OP_HAS_MODRM,			// 31: XOR Ev,Gv
	OP_HAS_MODRM,			// 32: XOR Gb,Eb
	OP_HAS_MODRM,			// 33: XOR Gv,Ev
	OP_HAS_IMM8,			// 34: XOR AL,Ib
	OP_CHECK_66,			// 35: XOR rAX,Iz
	OP_PREFIX,			// 36: SS prefix
	OP_IA32_ONLY|OP_SPECIAL,	// 37: AAA

	OP_HAS_MODRM,			// 38: CMP Eb,Gb
	OP_HAS_MODRM,			// 39: CMP Ev,Gv
	OP_HAS_MODRM,			// 3A: CMP Gb,Eb
	OP_HAS_MODRM,			// 3B: CMP Gv,Ev
	OP_HAS_IMM8,			// 3C: CMP AL,Ib
	OP_CHECK_66,			// 3D: CMP rAX,Iz
	OP_PREFIX,			// 3E: DS prefix (hint taken for Jcc)
	OP_IA32_ONLY|OP_SPECIAL,	// 3F: AAS

	/* note: the single-byte opcode forms of the INC/DEC instructions do not exist
	 * in the x86-64 instruction set, but rather are reassigned for use as the REX
	 * prefix. for the purposes of length decoding, we only need to check whether
	 * the fourth bit in the REX byte is set, which is the case for 48 to 4F. */

	OP_REX,				// 40: INC eAX
	OP_REX,				// 41: INC eCX
	OP_REX,				// 42: INC eDX
	OP_REX,				// 43: INC eBX
	OP_REX,				// 44: INC eSP
	OP_REX,				// 45: INC eBP
	OP_REX,				// 46: INC eSI
	OP_REX,				// 47: INC eDI

	OP_REX,				// 48: DEC eAX
	OP_REX,				// 49: DEC eCX
	OP_REX,				// 4A: DEC eDX
	OP_REX,				// 4B: DEC eBX
	OP_REX,				// 4C: DEC eSP
	OP_REX,				// 4D: DEC eBP
	OP_REX,				// 4E: DEC eSI
	OP_REX,				// 4F: DEC eDI

	0,				// 50: POP rAX
	0,				// 51: POP rCX
	0,				// 52: POP rDX
	0,				// 53: POP rBX
	0,				// 54: POP rSP
	0,				// 55: POP rBP
	0,				// 56: POP rSI
	0,				// 57: POP rDI

	0,				// 58: PUSH rAX
	0,				// 59: PUSH rCX
	0,				// 5A: PUSH rDX
	0,				// 5B: PUSH rBX
	0,				// 5C: PUSH rSP
	0,				// 5D: PUSH rBP
	0,				// 5E: PUSH rSI
	0,				// 5F: PUSH rDI

	OP_IA32_ONLY,			// 60: PUSH{A,AD}
	OP_IA32_ONLY,			// 61: POP{A,AD}
	OP_IA32_ONLY|OP_HAS_MODRM,	// 62: BOUND Gv,Ma
	OP_HAS_MODRM|OP_SPECIAL,	// 63: ARPL Ew,Gw (MOVSXD Gv,Ed for x86-64)
	OP_PREFIX,			// 64: FS prefix
	OP_PREFIX,			// 65: GS prefix (hint alt taken for Jcc)
	OP_PREFIX,			// 66: operand size prefix
	OP_PREFIX,			// 67: address size prefix

	OP_CHECK_66,			// 68: PUSH Iz
	OP_HAS_MODRM|OP_CHECK_66,	// 69: IMUL Gv,Ev,Iz
	OP_HAS_IMM8,			// 6A: PUSH Ib
	OP_HAS_MODRM|OP_HAS_IMM8,	// 6B: IMUL Gv,Ev,Ib
	0,				// 6C: IN{S,SB} Yb,DX
	0,				// 6D: IN{SW,SD} Yz,DX
	0,				// 6E: OUT{S,SB} DX,Xb
	0,				// 6F: OUT{S,SW,SD} DX,Xz

	OP_HAS_IMM8,			// 70: JO Jb
	OP_HAS_IMM8,			// 71: JNO Jb
	OP_HAS_IMM8,			// 72: J{B,NAE,C} Jb
	OP_HAS_IMM8,			// 73: J{NB,AE,NC} Jb
	OP_HAS_IMM8,			// 74: J{Z,E} Jb
	OP_HAS_IMM8,			// 75: J{NZ,NE} Jb
	OP_HAS_IMM8,			// 76: J{BE,NA} Jb
	OP_HAS_IMM8,			// 77: J{NBE,A} Jb

	OP_HAS_IMM8,			// 78: JS Jb
	OP_HAS_IMM8,			// 79: JNS Jb
	OP_HAS_IMM8,			// 7A: J{P,PE} Jb
	OP_HAS_IMM8,			// 7B: J{NP,PO} Jb
	OP_HAS_IMM8,			// 7C: J{L,NGE} Jb
	OP_HAS_IMM8,			// 7D: J{NL,GE} Jb
	OP_HAS_IMM8,			// 7E: J{LE,NG} Jb
	OP_HAS_IMM8,			// 7F: J{NLE,G} Jb

	OP_GROUP(GRP_1)|OP_HAS_IMM8,	// 80: group 1 (Eb,Ib)
	OP_GROUP(GRP_1)|OP_CHECK_66,	// 81: group 1 (Ev,Iz)
	OP_IA32_ONLY|OP_GROUP(GRP_1)|OP_HAS_IMM8, // 82: group 1 (Eb,Ib) [alias]
	OP_GROUP(GRP_1)|OP_HAS_IMM8,	// 83: group 1 (Ev,Ib)
	OP_HAS_MODRM,			// 84: TEST Eb,Gb
	OP_HAS_MODRM,			// 85: TEST Ev,Gv
	OP_HAS_MODRM,			// 86: XCHG Eb,Gb
	OP_HAS_MODRM,			// 87: XCHG Ev,Gv

	OP_HAS_MODRM,			// 88: MOV Eb,Gb
	OP_HAS_MODRM,			// 89: MOV Ev,Gv
	OP_HAS_MODRM,			// 8A: MOV Gb,Eb
	OP_HAS_MODRM,			// 8B: MOV Gv,Ev
	OP_HAS_MODRM,			// 8C: MOV {Mw,Rv},Sw
	OP_HAS_MODRM,			// 8D: LEA Gv,M
	OP_HAS_MODRM,			// 8E: MOV Sw,{Mw,Rv}
	OP_GROUP(GRP_10),		// 8F: group 10

	OP_SPECIAL,			// 90: NOP / PAUSE (with F3 prefix)
	0,				// 91: XCHG rCX,rAX
	0,				// 92: XCHG rDX,rAX
	0,				// 93: XCHG rBX,rAX
	0,				// 94: XCHG rSP,rAX
	0,				// 95: XCHG rBP,rAX
	0,				// 96: XCHG rSI,rAX
	0,				// 97: XCHG rDI,rAX

	0,				// 98: C{BW,WDE}
	0,				// 99: C{WD,DQ}
	OP_IA32_ONLY|OP_CHECK_66|OP_HAS_IMM16, // 9A: CALL Ap
	0,				// 9B: {,F}WAIT
	0,				// 9C: PUSH{F,FD} Fv
	0,				// 9D: POP{F,FD} Fv
	0,				// 9E: SAHF
	0,				// 9F: LAHF

	OP_CHECK_67,			// A0: MOV AL,Ob
	OP_CHECK_67,			// A1: MOV rAX,Ov
	OP_CHECK_67,			// A2: MOV Ob,AL
	OP_CHECK_67,			// A3: MOV Ov,rAX
	0,				// A4: MOV{S,SB} Yb,Xb
	0,				// A5: MOV{S,SW,SD} Yv,Xv
	0,				// A6: CMP{S,SB} Yb,Xb
	0,				// A7: CMP{S,SW,SD} Yv,Xv

	OP_HAS_IMM8,			// A8: TEST AL,Ib
	OP_CHECK_66,			// A9: TEST rAX,Iz
	0,				// AA: STO{S,SB} Yb,AL
	0,				// AB: STO{S,SW,SD} Yv,rAX
	0,				// AC: LOD{S,SB} AL,Xb
	0,				// AD: LOD{S,SW,SD} rAX,Xv
	0,				// AE: SCA{S,SB} Yb,AL
	0,				// AF: SCA{S,SW,SD} Yv,rAX

	OP_HAS_IMM8,			// B0: MOV AL,Ib
	OP_HAS_IMM8,			// B1: MOV CL,Ib
	OP_HAS_IMM8,			// B2: MOV DL,Ib
	OP_HAS_IMM8,			// B3: MOV BL,Ib
	OP_HAS_IMM8,			// B4: MOV AH,Ib
	OP_HAS_IMM8,			// B5: MOV CH,Ib
	OP_HAS_IMM8,			// B6: MOV DH,Ib
	OP_HAS_IMM8,			// B7: MOV BH,Ib

	OP_CHECK_66|OP_CHECK_REX,	// B8: MOV rAX,Iv
	OP_CHECK_66|OP_CHECK_REX,	// B9: MOV rCX,Iv
	OP_CHECK_66|OP_CHECK_REX,	// BA: MOV rDX,Iv
	OP_CHECK_66|OP_CHECK_REX,	// BB: MOV rBX,Iv
	OP_CHECK_66|OP_CHECK_REX,	// BC: MOV rSP,Iv
	OP_CHECK_66|OP_CHECK_REX,	// BD: MOV rBP,Iv
	OP_CHECK_66|OP_CHECK_REX,	// BE: MOV rSI,Iv
	OP_CHECK_66|OP_CHECK_REX,	// BF: MOV rDI,Iv

	OP_GROUP(GRP_2)|OP_HAS_IMM8,	// C0: group 2 (Eb,Ib)
	OP_GROUP(GRP_2)|OP_HAS_IMM8,	// C1: group 2 (Ev,Ib)
	OP_HAS_IMM16,			// C2: RETN Iw
	0,				// C3: RETN
	OP_IA32_ONLY|OP_HAS_MODRM|OP_SPECIAL, // C4: LES Gz,Mp
	OP_IA32_ONLY|OP_HAS_MODRM|OP_SPECIAL, // C5: LDS Gz,Mp
	OP_GROUP(GRP_12)|OP_HAS_IMM8,	// C6: group 12 (Eb,Ib)
	OP_GROUP(GRP_12)|OP_CHECK_66,	// C7: group 12 (Ev,Iz)

	OP_HAS_IMM16|OP_HAS_IMM8,	// C8: ENTER Iw,Ib
	0,				// C9: LEAVE
	OP_HAS_IMM16,			// CA: RETF Iw
	0,				// CB: RETF
	0,				// CC: INT3
	OP_HAS_IMM8,			// CD: INT Ib
	OP_IA32_ONLY,			// CE: INTO
	OP_SPECIAL,			// CF: IRET

	OP_GROUP(GRP_2),		// D0: group 2 (Eb,1)
	OP_GROUP(GRP_2),		// D1: group 2 (Ev,1)
	OP_GROUP(GRP_2),		// D2: group 2 (Eb,CL)
	OP_GROUP(GRP_2),		// D3: group 2 (Ev,CL)
	OP_IA32_ONLY|OP_HAS_IMM8|OP_SPECIAL, // D4: AAM Ib
	OP_IA32_ONLY|OP_HAS_IMM8|OP_SPECIAL, // D5: AAD Ib
	OP_IA32_ONLY,			// D6: SALC
	0,				// D7: XLAT{,B}

#ifdef EXTENDED_PATCHER
	OP_HAS_MODRM,			// D8: ESC to coprocessor
	OP_HAS_MODRM,			// D9: ESC to coprocessor
	OP_HAS_MODRM,			// DA: ESC to coprocessor
	OP_GROUP(GRP_FISTTP),		// DB: ESC to coprocessor
	OP_HAS_MODRM,			// DC: ESC to coprocessor
	OP_GROUP(GRP_FISTTP),		// DD: ESC to coprocessor
	OP_HAS_MODRM,			// DE: ESC to coprocessor
	OP_GROUP(GRP_FISTTP),		// DF: ESC to coprocessor
#else
	OP_HAS_MODRM,			// D8: ESC to coprocessor
	OP_HAS_MODRM,			// D9: ESC to coprocessor
	OP_HAS_MODRM,			// DA: ESC to coprocessor
	OP_HAS_MODRM,			// DB: ESC to coprocessor
	OP_HAS_MODRM,			// DC: ESC to coprocessor
	OP_HAS_MODRM,			// DD: ESC to coprocessor
	OP_HAS_MODRM,			// DE: ESC to coprocessor
	OP_HAS_MODRM,			// DF: ESC to coprocessor
#endif

	OP_HAS_IMM8,			// E0: LOOP{NE,NZ} Jb
	OP_HAS_IMM8,			// E1: LOOP{E,Z} Jb
	OP_HAS_IMM8,			// E2: LOOP Jb
	OP_HAS_IMM8,			// E3: J{CXZ,ECX} Jb
	OP_HAS_IMM8,			// E4: IN AL,Ib
	OP_HAS_IMM8,			// E5: IN eAX,Ib
	OP_HAS_IMM8,			// E6: OUT Ib,AL
	OP_HAS_IMM8,			// E7: OUT Ib,eAX

	OP_CHECK_66,			// E8: CALL Jz
	OP_CHECK_66,			// E9: JMP Jz
#ifdef EXTENDED_PATCHER
	OP_IA32_ONLY|OP_CHECK_66|OP_HAS_IMM16|OP_SPECIAL, // EA: JMP Ap
#else
	OP_IA32_ONLY|OP_CHECK_66|OP_HAS_IMM16, // EA: JMP Ap
#endif
	OP_HAS_IMM8,			// EB: JMP Jb
	0,				// EC: IN AL,DX
	0,				// ED: IN eAX,DX
	0,				// EE: OUT DX,AL
	0,				// EF: OUT DX,eAX

	OP_PREFIX,			// F0: LOCK
	0,				// F1: INT1
	OP_PREFIX,			// F2: REPNE
	OP_PREFIX,			// F3: REP{,E}
	0,				// F4: HLT
	0,				// F5: CMC
	OP_GROUP(GRP_3A),		// F6: group 3 (Eb)
	OP_GROUP(GRP_3B),		// F7: group 3 (Ev)

	0,				// F8: CLC
	0,				// F9: STC
	0,				// FA: CLI
	0,				// FB: STI
	0,				// FC: CLD
	0,				// FD: STD
	OP_GROUP(GRP_4),		// FE: group 4
	OP_GROUP(GRP_5)			// FF: group 5
};

typedef struct {
	uint32_t flags;
	uint32_t prefixes;
} ext_opcode_t;

ext_opcode_t two_byte_table[256] = {
	{ OP_GROUP(GRP_6),		0 },				// 00: group 6
	{ OP_GROUP(GRP_7),		0 },				// 01: group 7
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 02: LAR Gv,Ew
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 03: LSL Gv,Ew
	{ OP_UNDEFINED,			0 },				// 04
	{ 0,				0 },					// 05: SYSCALL
	{ OP_SPECIAL,			0 },				// 06: CLTS
	{ OP_SPECIAL,			0 },				// 07: SYSRET

	{ OP_SPECIAL,			0 },				// 08: INVD
	{ OP_SPECIAL,			0 },				// 09: WBINVD
	{ OP_UNDEFINED,			0 },				// 0A
	{ 0,				0 },				// 0B: UD2
	{ OP_UNDEFINED,			0 },				// 0C
	{ OP_HAS_MODRM,			0 },	 			// 0D: PREFETCHx M
	{ 0,				0 },				// 0E: FEMMS
	{ OP_UNDEFINED,			0 },				// 0F (3DNow!)

	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 10: MOV{UP,S}S V{o,d},W{o,d} / MOV{UP,S}D V{o,q},W{o,q} 
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 11: MOV{UP,S}S W{o,d},V{o,d} / MOV{UP,S}D W{o,q},V{o,q} 
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 12: MOV{L,HL}PS Vq,{M,VR}q / MOVSLDUP Vo,Wo / MOVLPD Vq,Mq / MOVDDUP Vo,Wq
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 13: MOVLP{S,D} Mq,Vq
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 14: UNPCKLP{S,D} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 15: UNPCKHP{S,D} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_F3|PREF_66 },	// 16: MOV{H,LH}PS Vq,{M,VR}q / MOVSHDUP Vo,Wo / MOVHPD Vq,Mq
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 17: MOVHP{S,D} Mq,Vq

	{ OP_GROUP(GRP_17A),		0 },				// 18: group 17 (PREFETCH{NTA,T0,T1,T2} and HINT_NOP)
	{ OP_GROUP(GRP_17B),		0 },				// 19: group 17 (HINT_NOP)
	{ OP_GROUP(GRP_17B),		0 },				// 1A: group 17 (HINT_NOP)
	{ OP_GROUP(GRP_17B),		0 },				// 1B: group 17 (HINT_NOP)
	{ OP_GROUP(GRP_17B),		0 },				// 1C: group 17 (HINT_NOP)
	{ OP_GROUP(GRP_17B),		0 },				// 1D: group 17 (HINT_NOP)
	{ OP_GROUP(GRP_17B),		0 },				// 1E: group 17 (HINT_NOP)
	{ OP_GROUP(GRP_17B),		0 },				// 1F: group 17 (HINT_NOP)

	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 20: MOV Rd,Cd
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 21: MOV Rd,Dd
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 22: MOV Cd,Rd
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 23: MOV Dd,Rd
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 24: MOV Rd,Td
	{ OP_UNDEFINED,			0 },				// 25
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// 26: MOV Td,Rd
	{ OP_UNDEFINED,			0 },				// 27

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 28: MOVAP{S,D} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 29: MOVAP{S,D} Wo,Vo
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 2A: CVTPI2PS Vq,{M,P}q / CVTSI2SS Vd,Ed / CVTPI2PD Vo,{M,P}q / CVTSI2SD Vq,Ed
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 2B: MOVNTP{S,D} Mo,Vo
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 2C: CVTT{PS2PI,SS2SI} {Pq,Gd},W{q,d} / CVTT{PD2PI,SD2SI} {Pq,Gd},W{o,q}
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 2D: CVT{PS2PI,SS2SI} {Pq,Gd},W{q,d} / CVT{PD2PI,SD2SI} {Pq,Gd},W{o,q}
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 2E: UCOMIS{S,D} V{d,q},W{d,q}
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 2F: COMIS{S,D} V{d,q},W{d,q}

	{ OP_SPECIAL,			0 },				// 30: WRMSR
	{ 0,				0 },				// 31: RDTSC
	{ OP_SPECIAL,			0 },				// 32: RDMSR
	{ 0,				0 },				// 33: RDPMC
	{ OP_NEEDS_PATCH,		0 },				// 34: SYSENTER
	{ OP_SPECIAL,			0 },				// 35: SYSEXIT
	{ OP_UNDEFINED,			0 },				// 36
	{ OP_UNDEFINED,			0 },				// 37

	{ OP_THREEBYTE_38,		0 },				// 38: three-byte opcode
	{ OP_UNDEFINED,			0 },				// 39
	{ OP_THREEBYTE_3A,		0 },				// 3A: three-byte opcode
	{ OP_UNDEFINED,			0 },				// 3B
	{ OP_UNDEFINED,			0 },				// 3C
	{ OP_UNDEFINED,			0 },				// 3D
	{ OP_UNDEFINED,			0 },				// 3E
	{ OP_UNDEFINED,			0 },				// 3F

	{ OP_HAS_MODRM,			0 },	 			// 40: CMOVO Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 41: CMOVNO Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 42: CMOV{B,C,NAE} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 43: CMOV{AE,NB,NC} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 44: CMOV{E,Z} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 45: CMOV{NE,NZ} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 46: CMOV{BE,NA} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 47: CMOV{A,NBE} Gv,Ev

	{ OP_HAS_MODRM,			0 },	 			// 48: CMOVS Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 49: CMOVNS Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 4A: CMOV{P,PE} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 4B: CMOV{NP,PO} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 4C: CMOV{L,NGE} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 4D: CMOV{NL,GE} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 4E: CMOV{LE,NG} Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// 4F: CMOV{NLE,G} Gv,Ev

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 50: MOVMSKP{S,D} Gd,VRo
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 51: SQRT{P,S}S V{o,d},W{o,d} / SQRT{P,S}D V{o,q},W{o,q}
	{ OP_HAS_MODRM,			PREF_NONE|PREF_F3 },		// 52: RSQRT{P,S}S V{o,d},W{o,d}
	{ OP_HAS_MODRM,			PREF_NONE|PREF_F3 },		// 53: RCP{P,S}S V{o,d},W{o,d}
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 54: ANDP{S,D} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 55: ANDNP{S,D} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 56: ORP{S,D} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 57: XORP{S,D} Vo,Wo

	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 58: ADD{P,S}S V{o,d},W{o,d} / ADD{P,S}D V{o,q},W{o,q}
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 59: MUL{P,S}S V{o,d},W{o,d} / MUL{P,S}D V{o,q},W{o,q}
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 5A: CVTPS2PD Vo,Wq / CVTSS2SD Vq,Wd / CVTPD2PS Vo,Wo / CVTSD2SS Vd,Wq
	{ OP_HAS_MODRM,			PREF_NONE|PREF_F3|PREF_66 },	// 5B: CVT{DQ2PS,TPS2DQ,PS2DQ} Vo,Wo
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 5C: SUB{P,S}S V{o,d},W{o,d} / SUB{P,S}D V{o,q},W{o,q}
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 5D: MIN{P,S}S V{o,d},W{o,d} / MIN{P,S}D V{o,q},W{o,q}
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 5E: DIV{P,S}S V{o,d},W{o,d} / DIV{P,S}D V{o,q},W{o,q}
	{ OP_HAS_MODRM,			PREF_SSE_ALL },			// 5F: MAX{P,S}S V{o,d},W{o,d} / MAX{P,S}D V{o,q},W{o,q}

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 60: PUNPCKLBW Pq,Qd / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 61: PUNPCKLWD Pq,Qd / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 62: PUNPCKLDQ Pq,Qd / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 63: PACKSSWB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 64: PCMPGTB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 65: PCMPGTW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 66: PCMPGTD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 67: PACKUSWB Pq,Qq / Vo,Wo

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 68: PUNPCKHBW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 69: PUNPCKHWD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 6A: PUNPCKHDQ Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 6B: PACKSSDW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_66 },			// 6C: PUNPCKLQDQ Vo,Wq
	{ OP_HAS_MODRM,			PREF_66 },			// 6D: PUNPCKHQDQ Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 6E: MOVD Pq,Ed / Vo,Ed
	{ OP_HAS_MODRM,			PREF_NONE|PREF_F3|PREF_66 },	// 6F: MOVQ Pq,Qq / MOV{DQU,DQA} Vo,Wo

	{ OP_HAS_MODRM|OP_HAS_IMM8,	PREF_SSE_ALL },			// 70: PSHUFW Pq,Qq,Ib / PSHUF{HW,D,LW} Vo,Wo,Ib
	{ OP_GROUP(GRP_13),		PREF_NONE|PREF_66 },		// 71: group 13 (PSHIMW) PS{RL,RA,LL}W {PRq,VRo},Ib
	{ OP_GROUP(GRP_14),		PREF_NONE|PREF_66 },		// 72: group 14 (PSHIMD) PS{RL,RA,LL}D {PRq,VRo},Ib
	{ OP_GROUP(GRP_15),		PREF_NONE|PREF_66 },		// 73: group 15 (PSHIMQ) PS{RL,LL}Q {PRq,VRo},Ib / PSRLDQ VRo,Ib
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 74: PCMPEQB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 75: PCMPEQW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 76: PCMPEQD Pq,Qq / Vo,Wo
	{ 0,				PREF_NONE },			// 77: EMMS

	{ OP_HAS_MODRM,			0 },	 			// 78: VMREAD E{d,q},G{d,q}
	{ OP_HAS_MODRM,			0 },	 			// 79: VMWRITE E{d,q},G{d,q}
	{ OP_UNDEFINED,			0 },	 			// 7A
	{ OP_UNDEFINED,			0 },	 			// 7B
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66|PREF_F2 },		// 7C: HADDP{D,S} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66|PREF_F2 },	 	// 7D: HSUBP{D,S} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_F3|PREF_66 },	// 7E: MOVD Ed,Pd / MOVQ V{o,q},{M,V}q / MOVD Ed,Vd
	{ OP_HAS_MODRM,			PREF_NONE|PREF_F3|PREF_66 },	// 7F: MOVQ Qq,Pq / MOV{DQU,DQA} Wo,Vo

	{ OP_CHECK_66,			0 },	 			// 80: JO Jv
	{ OP_CHECK_66,			0 },	 			// 81: JNO Jv
	{ OP_CHECK_66,			0 },	 			// 82: J{B,C,NAE} Jv
	{ OP_CHECK_66,			0 },	 			// 83: J{AE,NB,NC} Jv
	{ OP_CHECK_66,			0 },	 			// 84: J{E,Z} Jv
	{ OP_CHECK_66,			0 },	 			// 85: J{NE,NZ} Jv
	{ OP_CHECK_66,			0 },	 			// 86: J{BE,NA} Jv
	{ OP_CHECK_66,			0 },	 			// 87: J{A,NBE} Jv

	{ OP_CHECK_66,			0 },	 			// 88: JS Jv
	{ OP_CHECK_66,			0 },	 			// 89: JNS Jv
	{ OP_CHECK_66,			0 },	 			// 8A: J{P,PE} Jv
	{ OP_CHECK_66,			0 },	 			// 8B: J{NP,PO} Jv
	{ OP_CHECK_66,			0 },	 			// 8C: J{L,NGE} Jv
	{ OP_CHECK_66,			0 },	 			// 8D: J{NL,GE} Jv
	{ OP_CHECK_66,			0 },	 			// 8E: J{LE,NG} Jv
	{ OP_CHECK_66,			0 },	 			// 8F: J{NLE,G} Jv

	{ OP_HAS_MODRM,			0 },	 			// 90: SETO Eb
	{ OP_HAS_MODRM,			0 },	 			// 91: SETNO Eb
	{ OP_HAS_MODRM,			0 },	 			// 92: SET{B,C,NAE} Eb
	{ OP_HAS_MODRM,			0 },	 			// 93: SET{AE,NB,NC} Eb
	{ OP_HAS_MODRM,			0 },	 			// 94: SET{E,Z} Eb
	{ OP_HAS_MODRM,			0 },	 			// 95: SET{NE,NZ} Eb
	{ OP_HAS_MODRM,			0 },	 			// 96: SET{BE,NA} Eb
	{ OP_HAS_MODRM,			0 },	 			// 97: SET{A,NBE} Eb

	{ OP_HAS_MODRM,			0 },	 			// 98: SETS Eb
	{ OP_HAS_MODRM,			0 },	 			// 99: SETNS Eb
	{ OP_HAS_MODRM,			0 },	 			// 9A: SET{P,PE} Eb
	{ OP_HAS_MODRM,			0 },	 			// 9B: SET{NP,PO} Eb
	{ OP_HAS_MODRM,			0 },	 			// 9C: SET{L,NGE} Eb
	{ OP_HAS_MODRM,			0 },	 			// 9D: SET{NL,GE} Eb
	{ OP_HAS_MODRM,			0 },	 			// 9E: SET{LE,NG} Eb
	{ OP_HAS_MODRM,			0 },	 			// 9F: SET{NLE,G} Eb

	{ OP_SPECIAL, 			0 },				// A0: PUSH FS
	{ OP_SPECIAL, 			0 },				// A1: POP FS
	{ OP_NEEDS_PATCH,	 	0 },				// A2: CPUID
	{ OP_HAS_MODRM,			0 },	 			// A3: BT Ev,Gv
	{ OP_HAS_MODRM|OP_HAS_IMM8,	0 },	 			// A4: SHLD Ev,Gv,Ib
	{ OP_HAS_MODRM,			0 },	 			// A5: SHLD Ev,Gv,CL
	{ OP_UNDEFINED,			0 },	 			// A6
	{ OP_UNDEFINED,			0 },	 			// A7

	{ OP_SPECIAL, 			0 },				// A8: PUSH GS
	{ OP_SPECIAL, 			0 },				// A9: POP GS
	{ OP_SPECIAL,			0 },				// AA: RSM
	{ OP_HAS_MODRM,			0 },	 			// AB: BTS Ev,Gv
	{ OP_HAS_MODRM|OP_HAS_IMM8,	0 },	 			// AC: SHRD Ev,Gv,Ib
	{ OP_HAS_MODRM,			0 },	 			// AD: SHRD Ev,Gv,CL
	{ OP_GROUP(GRP_16),		0 },	 			// AE: group 16
	{ OP_HAS_MODRM,			0 },	 			// AF: IMUL Gv,Ev

	{ OP_HAS_MODRM,			0 },	 			// B0: CMPXCHG Eb,Gb
	{ OP_HAS_MODRM,			0 },	 			// B1: CMPXCHG Ev,Gv
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// B2: LSS Gz,Mp
	{ OP_HAS_MODRM,			0 },	 			// B3: BTR Ev,Gv
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// B4: LFS Gz,Mp
	{ OP_HAS_MODRM|OP_SPECIAL,	0 },	 			// B5: LGS Gz,Mp
	{ OP_HAS_MODRM,			0 },	 			// B6: MOVZX Gv,Eb
	{ OP_HAS_MODRM,			0 },	 			// B7: MOVZX Gv,Ew

	{ OP_HAS_MODRM,			PREF_F3 },			// B8: POPCNT Pq,Qq

	{ OP_GROUP(GRP_11),		0 }, 				// B9: group 11
	{ OP_GROUP(GRP_8),		0 },				// BA: group 8
	{ OP_HAS_MODRM,			0 },	 			// BB: BTC Ev,Gv
	{ OP_HAS_MODRM,			0 },	 			// BC: BSF Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// BD: BSR Gv,Ev
	{ OP_HAS_MODRM,			0 },	 			// BE: MOVSX Gv,Eb
	{ OP_HAS_MODRM,			0 },	 			// BF: MOVSX Gv,Ew

	{ OP_HAS_MODRM,			0 },	 			// C0: XADD Eb,Gb
	{ OP_HAS_MODRM,			0 },	 			// C1: XADD Ev,Gv
	{ OP_HAS_MODRM|OP_HAS_IMM8,	PREF_SSE_ALL },			// C2: CMPPS Vps, Wps, Ib
	{ OP_HAS_MODRM,			PREF_NONE },			// C3: MOVNTI Md,Gd
	{ OP_HAS_MODRM|OP_HAS_IMM8,	PREF_NONE|PREF_66 },		// C4: PINSRW {Pq,Vo},Mw,Ib / {Pq,Vo},G[wd],Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8,	PREF_NONE|PREF_66 },		// C5: PEXTRW Gd,PRq,Ib / Gd,VRo,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8,	PREF_NONE|PREF_66 },		// C6: SHUFP{S,D} Vo,Wo,Ib
	{ OP_GROUP(GRP_9),		0 },				// C7: group 9

	{ 0,				0 },							// C8: BSWAP EAX
	{ 0,				0 },							// C9: BSWAP ECX
	{ 0,				0 },							// CA: BSWAP EDX
	{ 0,				0 },							// CB: BSWAP EBX
	{ 0,				0 },							// CC: BSWAP ESP
	{ 0,				0 },							// CD: BSWAP EBP
	{ 0,				0 },							// CE: BSWAP ESI
	{ 0,				0 },							// CF: BSWAP EDI

	{ OP_HAS_MODRM,			PREF_66|PREF_F2 },			// D0: ADDSUBP{D,S} Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D1: PSRLW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D2: PSRLD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D3: PSRLQ Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D4: PADDQ Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D5: PMULLW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_F3|PREF_66|PREF_F2 },	// D6: MOVQ2DQ Vo,PRq / MOVQ {M,V}q,Vq / MOVDQ2Q Pq,VRq
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D7: PMOVMSKB Gd,PRq / Gd,VRo

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D8: PSUBUSB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// D9: PSUBUSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// DA: PMINUB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// DB: PAND Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// DC: PADDUSB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// DD: PADDUSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// DE: PMAXUB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// DF: PANDN Pq,Qq / Vo,Wo

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E0: PAVGB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E1: PSRAW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E2: PSRAD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E3: PAVGW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E4: PMULHUW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E5: PMULHW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_F3|PREF_66|PREF_F2 },	// E6: CVTDQ2PD Vo,Wq / CVTTPD2DQ Vo,Wo / CVTPD2DQ Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E7: MOVNTQ Mq,Pq / Mo,Vo

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E8: PSUBSB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// E9: PSUBSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// EA: PMINSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// EB: POR Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// EC: PADDSB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// ED: PADDSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// EE: PMAXSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// EF: PXOR Pq,Qq / Vo,Wo

#ifdef EXTENDED_PATCHER
	{ OP_HAS_MODRM|OP_NEEDS_PATCH,	PREF_F2 },			// F0: LDDQU Vo,Mo
#else
	{ OP_HAS_MODRM,			PREF_F2 },					// F0: LDDQU Vo,Mo
#endif

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F1: PSLLW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F2: PSLLD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F3: PSLLQ Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F4: PMULUDQ Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F5: PMADDWD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F6: PSADBW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F7: MASKMOVQ Ppi,Qpi / MASKMOVDQU Vo,VRo

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F8: PSUBB Pq,Qq / Vo,Vw
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// F9: PSUBW Pq,Qq / Vo,Vw
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// FA: PSUBD Pq,Qq / Vo,Vw
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// FB: PSUBQ Pq,Qq / Vo,Vw
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// FC: PADDB Pq,Qq / Vo,Vw
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// FD: PADDW Pq,Qq / Vo,Vw
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// FE: PADDD Pq,Qq / Vo,Vw

	{ OP_UNDEFINED,			0 }				// FF
};

ext_opcode_t three_byte_38_table[256] =
{
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 00: PSHUFB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 01: PHADDW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 02: PHADDD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 03: PHADDSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 04: PMADDUBSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 05: PHSUBW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 06: PHSUBD Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 07: PHSUBSW Pq,Qq / Vo,Wo

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 08: PSIGNB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 09: PSIGNW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 0A: PSIGND Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 0B: PMULHRSW Pq,Qq / Vo,Wo

	[0x0c ... 0x0f] = { OP_UNDEFINED, 0 },				// 0C to 0f: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM,			PREF_66 },					// 10: PBLENDVB Pq,Qq,Rq

	[0x11 ... 0x13] = { OP_UNDEFINED, 0 },				// 11 to 13: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM,			PREF_66 },					// 14: BLENDVPS Pq,Qq,Rq
	{ OP_HAS_MODRM,			PREF_66 },					// 15: BLENDVPD Pq,Qq,Rq

	{ OP_UNDEFINED, 0 },								// 16: undefined and non-SSSE3 opcode

	{ OP_HAS_MODRM,			PREF_66 },					// 17: PTEST Pq,Qq

	[0x18 ... 0x1b] = { OP_UNDEFINED, 0 },				// 18 to 1B: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 1C: PABSB Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 1D: PABSW Pq,Qq / Vo,Wo
	{ OP_HAS_MODRM,			PREF_NONE|PREF_66 },		// 1E: PABSD Pq,Qq / Vo,Wo

	{ OP_UNDEFINED, 0 },								// 1F: undefined and non-SSSE3 opcode

	{ OP_HAS_MODRM,			PREF_66 },					// 20: PMOVSXBW Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 21: PMOVSXBD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 22: PMOVSXBQ Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 23: PMOVSXWD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 24: PMOVSXWQ Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 25: PMOVSXDQ Pq,Qq

	[0x26 ... 0x27] = { OP_UNDEFINED, 0 },				// 26 to 27: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM,			PREF_66 },					// 28: PMULDQ Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 29: PCMPEQQ Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 2A: MOVNTDQA Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 2B: PACKUSDW Pq,Qq

	[0x2c ... 0x2f] = { OP_UNDEFINED, 0 },				// 2C to 2F: undefined and non-SSSE3 opcodes
	
	{ OP_HAS_MODRM,			PREF_66 },					// 30: PMOVZXBW Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 31: PMOVZXBD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 32: PMOVZXBQ Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 33: PMOVZXWD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 34: PMOVZXWQ Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 35: PMOVZXDQ Pq,Qq

	{ OP_UNDEFINED, 0 },									// 36: undefined and non-SSSE3 opcode

	{ OP_HAS_MODRM,			PREF_66 },					// 37: PCMPGTQ Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 38: PMINSB Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 39: PMINSD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 3A: PMINUW Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 3B: PMINUD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 3C: PMAXSB Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 3D: PMAXSD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 3E: PMAXUW Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 3F: PMAXUD Pq,Qq	
	{ OP_HAS_MODRM,			PREF_66 },					// 40: PMULLD Pq,Qq
	{ OP_HAS_MODRM,			PREF_66 },					// 41: PHMINPOSUW Pq,Qq

	[0x42 ... 0xef] = { OP_UNDEFINED, 0 },				// 42 to EF: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM,			PREF_F2 },					// F0: CRC32 Vo,Qq
	{ OP_HAS_MODRM,			PREF_F2 },					// F1: CRC32 Vo,Qq

	[0xf2 ... 0xff] = { OP_UNDEFINED, 0 }				// F2 to FF: undefined and non-SSSE3 opcodes
};

ext_opcode_t three_byte_3a_table[256]  =
{
	[0x00 ... 0x07] = { OP_UNDEFINED, 0 },				// 00 to 07: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 08: ROUNDPS Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 09: ROUNDPD Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 0A: ROUNDSS Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 0B: ROUNDSD Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 0C: BLENDPS Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 0D: BLENDPD Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 0E: PBLENDW Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8,	PREF_NONE|PREF_66 },	// 0F: PALIGNR Pq,Qq,Ib / Vo,Wo,Ib

	[0x10 ... 0x13] = { OP_UNDEFINED, 0 },				// 10 to 13: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 14: PEXTRB Vo,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 15: PEXTRW Vo,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 16: PEXTRD Vo,Qq,Ib / PEXTRQ Vo,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 17: EXTRACTPS Pq,Qq,Ib

	[0x18 ... 0x19] = { OP_UNDEFINED, 0 },				// 18 to 19: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 20: PINSRB Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 21: INSERTPS Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 22: PINSRD Pq,Qq,Ib / PINSRQ Pq,Wo,Ib

	[0x23 ... 0x3f] = { OP_UNDEFINED, 0 },				// 23 to 3F: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 40: DPPS Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 41: DPPD Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 42: MPSADBW Pq,Qq,Ib

	[0x43 ... 0x5f] = { OP_UNDEFINED, 0 },				// 43 to 5F: undefined and non-SSSE3 opcodes

	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 60: PCMPESTRM Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 61: PCMPESTRI Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 62: PCMPISTRM Pq,Qq,Ib
	{ OP_HAS_MODRM|OP_HAS_IMM8, PREF_66 },				// 63: PCMPISTRI Pq,Qq,Ib

	[0x64 ... 0xff] = { OP_UNDEFINED, 0 }				// 64 to FF: undefined and non-SSSE3 opcodes
};

/* get_insn_length: calculates the length of a single instruction
 *
 * arguments:  insn: (in) pointer to instruction
 *             is_64bit: (in) specifies whether instruction set is x86-64
 *             status: (out) returns STATUS_* flags (see disasm.h)
 * returns:    number of bytes in instruction
 *             INSN_INVALID if invalid
 *             INSN_UNSUPPORTED if unsupported
 */

int32_t get_insn_length(uint8_t *insn, boolean_t is_64bit, uint8_t *status)
{
	uint32_t flag = 0; // instruction information
	uint32_t prefix = 0; // all prefixes preceding opcode
	uint8_t *eip = insn; // current location in instruction
	uint8_t opcode; // last byte of opcode

	do {
		flag &= ~(OP_PREFIX|OP_REX);
		opcode = *eip++;
		flag |= one_byte_table[opcode];
		if (!is_64bit)
			flag &= ~OP_REX;
		if (flag & (OP_PREFIX|OP_REX))
			prefix |= prefix_table[opcode];
	} while (flag & (OP_PREFIX|OP_REX));

	if (flag & OP_TWOBYTE) {
		ext_opcode_t *info;
		opcode = *eip++;
		info = &two_byte_table[opcode];
		flag |= info->flags;
		if (flag & (OP_THREEBYTE_38|OP_THREEBYTE_3A)) {
			ext_opcode_t *table;
			if (flag & OP_THREEBYTE_38)
				table = three_byte_38_table;
			else if (flag & OP_THREEBYTE_3A)
				table = three_byte_3a_table;
			else // shut up optimizer (never reached)
				return INSN_INVALID;
			opcode = *eip++;
			info = &table[opcode];
			flag |= info->flags;
		}
		if (!(prefix & ~(PREF_REX|PREF_REX_W)))
			prefix |= PREF_NONE;
		if (info->prefixes && !(info->prefixes & prefix))
			flag |= OP_UNDEFINED;
	}

	if (flag & OP_GROUP_MASK) {
		uint8_t reg = (*eip & 0x38) >> 3;
		flag |= group_table[OP_GROUP_EXTRACT(flag)][reg];
	}

	if ((flag & OP_UNDEFINED) || (is_64bit && (flag & OP_IA32_ONLY)))
		return INSN_INVALID;

	if (flag & OP_SPECIAL) {
		/* detect certain instructions that are invalid unless in ring 0, unlikely to be used
		 * in 32-bit user code, or archaic (ie. bcd instructions). */
		if (flag & (OP_THREEBYTE_38|OP_THREEBYTE_3A))
			return INSN_UNSUPPORTED;
		else if (flag & OP_TWOBYTE) {
			switch (opcode) {
			case 0x00: // {SLDT,STR,LLDT,LTR,VERR,VERW} {Mw,Rv}
			case 0x01: // {SGDT,SIDT,LGDT,LIDT} Ms, SMSW Mw, LMSW {Mw,Rv}
				   // INVLPG M (also: SWAPGS/RDTSCP)
			case 0x02: // LAR Gv,Ew
			case 0x03: // LSL Gv,Ew
			case 0x06: // CLTS
			case 0x07: // SYSRET
			case 0x08: // INVD
			case 0x09: // WBINVD
			case 0x20: // MOV Rd,Cd
			case 0x21: // MOV Rd,Dd
			case 0x22: // MOV Cd,Rd
			case 0x23: // MOV Dd,Rd
			case 0x24: // MOV Rd,Td
			case 0x26: // MOV Td,Rd
			case 0x30: // WRMSR
			case 0x32: // RDMSR
			case 0x35: // SYSEXIT
			case 0xa0: // PUSH FS
			case 0xa1: // POP FS
			case 0xa8: // PUSH GS
			case 0xa9: // POP GS
			case 0xaa: // RSM
			case 0xb2: // LSS Gz,Mp
			case 0xb4: // LFS Gz,Mp
			case 0xb5: // LGS Gz,Mp
				break;
			default:
				return INSN_UNSUPPORTED;
			}
		} else {
			switch (opcode) {
			case 0x06: // PUSH ES
			case 0x07: // POP ES
			case 0x0e: // PUSH CS
			case 0x16: // PUSH SS
			case 0x17: // POP SS
			case 0x1e: // PUSH DS
			case 0x1f: // POP DS
			case 0x27: // DAA
			case 0x2f: // DAS
			case 0x37: // AAA
			case 0x3f: // AAS
			case 0xc4: // LES Gz,Mp
			case 0xc5: // LDS Gz,Mp
			case 0xcf: // IRET
			case 0xd4: // AAM Ib
			case 0xd5: // AAD Ib
			case 0x63: // ARPL Ew,Gw (MOVSXD Gv,Ed for x86-64)
				break;
			case 0x00: // ADD Eb,Gb
				/* a two-byte null instruction almost certainly means we're decoding garbade
				 * or that we have reached padding. */
				if (*eip == 0x00) { // ADD [eax],al
					*status |= STATUS_PADDING;
					return 1;
				}
				break;
			case 0x90: // NOP / PAUSE
				if (!(prefix & PREF_F3)) { // make sure not PAUSE
					*status |= STATUS_PADDING;
					return 1;
				}
				break;
#ifdef EXTENDED_PATCHER
			case 0xff: // JMP Ev (FF/4) / JMP Mp (FF/5)
			case 0xea: // JMP Ap
				/* an absolute unconditional jump is often followed by garbage, so we inform
				 * the calling function that what follows is probably invalid. */
				*status |= STATUS_REST;
				break;
#endif
			default:
				return INSN_UNSUPPORTED;
			}
		}
	}

	if (flag & OP_NEEDS_PATCH)
		*status |= STATUS_NEEDS_PATCH;

	if (!(flag & OP_OPERANDS))
		return (uint32_t) (eip - insn);

	if (is_64bit && (flag & OP_CHECK_REX)) {
		if (prefix & PREF_REX_W)
			flag |= OP_HAS_IMM64;
		else if (prefix & PREF_66)
			flag |= OP_HAS_IMM16;
		else
			flag |= OP_HAS_IMM32;
	} else if (flag & OP_CHECK_66) {
		if (prefix & PREF_66)
			flag |= OP_HAS_IMM16;
		else
			flag |= OP_HAS_IMM32;
	} else if (flag & OP_CHECK_67) {
		if (is_64bit) {
			if (prefix & PREF_67)
				flag |= OP_HAS_IMM32;
			else
				flag |= OP_HAS_IMM64;
		} else {
			if (prefix & PREF_67)
				flag |= OP_HAS_IMM16;
			else
				flag |= OP_HAS_IMM32;
		}
	}

	if (flag & OP_HAS_MODRM) {
		uint32_t modrm = *eip++;
		uint32_t mod = modrm >> 6;
		uint32_t rm = modrm & 0x7;

		if (prefix & PREF_67) {
			if (mod == 1)
				flag |= OP_HAS_DISP8;
			else if (mod == 2)
				flag |= OP_HAS_DISP16;
			else if (mod == 0 && rm == 6)
				flag |= OP_HAS_DISP16;
		} else {
			if (mod == 1)
				flag |= OP_HAS_DISP8;
			else if (mod == 2)
				flag |= OP_HAS_DISP32;
			else if (mod == 0 && rm == 5)
				flag |= OP_HAS_DISP32;
			if (mod < 3 && rm == 4) {
				uint32_t sib_base = *eip++ & 0x7;
				if (mod == 0 && sib_base == 5)
					flag |= OP_HAS_DISP32;
			}
		}
	}

	if (flag & OP_HAS_IMM8)
		eip++;
	if (flag & OP_HAS_IMM16)
		eip += 2;
	if (flag & OP_HAS_IMM32)
		eip += 4;
	if (flag & OP_HAS_IMM64)
		eip += 8;
	if (flag & OP_HAS_DISP8)
		eip++;
	if (flag & OP_HAS_DISP16)
		eip += 2;
	if (flag & OP_HAS_DISP32)
		eip += 4;

	return (uint32_t) (eip - insn);
}

/* old sysenter_trap:
 *  +0	5a		popl %edx		[returned by check_sysenter_trap]
 *  +1	89e1		movl %esp,%ecx
 *  +3	0f34		sysenter		[arg for check_sysenter_trap]
 *  +5	0f1f00		nopl (%eax)
 * new sysenter_trap:
 *  +0	59		popl %ecx
 *  +1	cdfc		int $0xfc
 *  +3	51		pushl %ecx
 *  +4	c3		ret
 *  +5	0f1f00		nopl (%eax)
 */

uint8_t *check_sysenter_trap(uint8_t *insn)
{
	uint32_t peek_back, peek_ahead;
	if (*(uint16_t *) insn != 0x340f)
		return (uint8_t *) -1;
	peek_back = *(uint32_t *) (insn - 4);
	if ((peek_back & 0xffffff00) != 0xe1895a00)
		return (uint8_t *) -1;
	peek_ahead = *(uint32_t *) (insn + 2);
	if ((peek_ahead & 0x00ffffff) != 0x00001f0f)
		return (uint8_t *) -1;
	return (insn - 3);
}

const uint8_t new_sysenter_trap[8] = { 0x59, 0xcd, 0xfc, 0x51, 0xc3, 0x0f, 0x1f, 0x00 };

void patch_sysenter_trap(uint8_t *begin)
{
	*(uint32_t *) begin = *(const uint32_t *) new_sysenter_trap;
	*(uint32_t *) (begin + 4) = *(const uint32_t *) (new_sysenter_trap + 4);
}

boolean_t patch_insn(uint8_t *insn, boolean_t verbose, boolean_t is_64bit)
{
#ifdef EXTENDED_PATCHER
	uint32_t opcode = *(uint32_t *) insn;

	if (((insn[0] & 0xf0) == 0xd0) &&
			(((insn[1] >> 3) & 7) == 1)) {
		switch (insn[0]) {
			case 0xdf: /* word */
			case 0xdb: /* dword */
				insn[1] |= (3 << 3);
				break;
			case 0xdd: /* qword */
				insn[0] = 0xdf;
				insn[1] |= (7 << 3);
				break;
			default:
				return FALSE;
		}
		if (verbose)
			printf("(patching fisttp to fistp)\n");
		return TRUE;
	}

	if ((opcode & 0x00ffffff) == LDDQU) {
		if (verbose)
			printf("(patching lddqu to movdqu)\n");
		opcode &= 0xff000000; /* clear opcode, leave operand */
		opcode |= 0x006f0ff3; /* patch with movdqu */
		*(uint32_t *) insn = opcode;
		return TRUE;
	}
#endif

	if (*(uint16_t *) insn == CPUID) {
		if (verbose)
			printf("(patching cpuid to int 0xfb)\n");
		*(uint16_t *) insn = 0xfbcd; /* int 0xfb */
		return TRUE;
	}

	if (!is_64bit && (*(uint16_t *) insn == SYSENTER)) {
		uint8_t *begin = check_sysenter_trap(insn);
		if (begin == (uint8_t *) -1)
			return FALSE;
		if (verbose)
			printf("(patching sysenter_trap)\n");
		patch_sysenter_trap(begin);
		return TRUE;
	}

	return FALSE;
}

uint32_t scan_text_section(uint8_t *start, uint64_t size, uint64_t text_addr,
		boolean_t should_patch, boolean_t abi_is_64, boolean_t verbose,
		uint32_t *num_patches_out)
{
	int32_t res;
	uint8_t *insn, *end, *last_bad;
	uint32_t num_bad, num_patches;

	insn = start;
	end = start + size;
	last_bad = NULL;
	num_bad = 0;
	num_patches = 0;

	if (verbose) {
		uint64_t addr = text_addr;
		for (res = 0; insn < end; insn += res, addr += res) {
			uint8_t status = 0;
			res = get_insn_length(insn, abi_is_64, &status);
			if (res == INSN_INVALID) {
				printf("%08llx: (bad)\n", addr);
				res = 1;
				last_bad = insn;
				num_bad++;
			} else if (res == INSN_UNSUPPORTED) {
				printf("%08llx: (unsupported)\n", addr);
				res = 1;
				last_bad = insn;
				num_bad++;
			} else if (status) {
				if (status & STATUS_PADDING) {
					uint32_t n;
					for (n = 1; (insn + n) < end; n++)
						if (insn[n] != insn[0])
							break;
					printf("%08llx: (%d bytes padding)\n", addr, n);
					res = n;
					continue;
				}
#ifdef EXTENDED_PATCHER
				if (status & STATUS_REST) {
					last_bad = insn;
					printf("%08llx: (will rest)\n", addr);
				}
#endif
				if (!(status & STATUS_NEEDS_PATCH))
					continue;
				printf("%08llx: ", addr);
				if (!should_patch || ((insn - last_bad) <= REST_SIZE)) {
					printf("(skipped patch)\n");
					continue;
				}
				if (!patch_insn(insn, verbose, abi_is_64))
					printf("(unrecognized patch)\n");
				else
					num_patches++;
			}
		}
	} else {
		for (res = 0; insn < end; insn += res) {
			uint8_t status = 0;
			res = get_insn_length(insn, abi_is_64, &status);
			if (res <= 0) { /* INSN_INVALID or INSN_UNSUPPORTED */
				res = 1;
				last_bad = insn;
				num_bad++;
			} else {
#ifdef EXTENDED_PATCHER
				if (status & (STATUS_REST|STATUS_PADDING)) {
					if (status & STATUS_PADDING) {
						uint32_t n;
						for (n = 1; (insn + n) < end; n++)
							if (insn[n] != insn[0])
								break;
						res = n;
						continue;
					} else
						last_bad = insn;
				}
#else
				if (status & STATUS_PADDING) {
					uint32_t n;
					for (n = 1; (insn + n) < end; n++)
						if (insn[n] != insn[0])
							break;
					res = n;
					continue;
				}
#endif
				if ((status & STATUS_NEEDS_PATCH) && should_patch &&
						((insn - last_bad) > REST_SIZE) &&
						patch_insn(insn, verbose, abi_is_64))
					num_patches++;
			}
		}
	}

	*num_patches_out = num_patches;

	return num_bad;
}

/* segment loading routines (for patching). */

#define DEFINE_GETSEG(x)									\
\
struct segment_command##x *getsegforpatch##x(struct mach_header##x *header,		\
const char *seg_name)								\
{												\
struct segment_command##x *sgp;								\
uint32_t i;										\
\
sgp = (struct segment_command##x *) ((char *) header + sizeof (struct mach_header##x));	\
for (i = 0; i < header->ncmds; i++) {							\
if (sgp->cmd == LC_SEGMENT##x && !strncmp(sgp->segname, seg_name,		\
sizeof (sgp->segname)))						\
return sgp;								\
sgp = (struct segment_command##x *) ((char *) sgp + sgp->cmdsize);		\
}											\
\
return NULL;										\
}

DEFINE_GETSEG()
DEFINE_GETSEG(_64)

#define DEFINE_GETSECT(x)									\
\
struct section##x *getsectforpatch##x(struct mach_header##x *header,			\
const char *segname, const char *sectname)					\
{												\
struct segment_command##x *sgp;								\
struct section##x *sp;									\
uint32_t i;										\
\
sgp = getsegforpatch##x(header, segname);					\
if (!sgp)										\
return NULL;									\
\
sp = (struct section##x *) ((char *) sgp + sizeof (struct segment_command##x));		\
for (i = 0; i < sgp->nsects; i++){							\
if (!strncmp(sp->sectname, sectname, sizeof (sp->sectname)) &&			\
!strncmp(sp->segname, segname, sizeof (sp->segname)))		\
return sp;								\
sp = (struct section##x *) ((char *) sp + sizeof (struct section##x));		\
}											\
\
return NULL;										\
}

DEFINE_GETSECT()
DEFINE_GETSECT(_64)

/* note: the map_addr and map_size arguments are used only for error checking. */

kern_return_t patch_text_segment(uint8_t *addr, __unused mach_vm_offset_t map_addr,
		mach_vm_size_t map_size, boolean_t abi_is_64, boolean_t seg_is_64,
		boolean_t verbose, boolean_t *bypass, uint32_t *num_patches_out,
		uint32_t *num_bad_out)
{
	uint64_t text_addr, text_size;
	uint32_t text_offset;
	uint8_t *text_data;
	uint64_t tmp_size;
	uint32_t num_patches, num_bad;

	*bypass = FALSE;

	if (seg_is_64) {
		struct section_64 *text_sect;
		text_sect = getsectforpatch_64((struct mach_header_64 *) addr, "__TEXT", "__text");
		if (!text_sect) {
			if (verbose)
				printf("getsectforpatch_64 failed (text segment appears "
						"to contain garbage, bypassing patcher)\n");
			*bypass = TRUE;
			return KERN_FAILURE;
		}
		text_addr = text_sect->addr;
		text_size = text_sect->size;
		text_offset = text_sect->offset;
	} else {
		struct section *text_sect;
		text_sect = getsectforpatch((struct mach_header *) addr, "__TEXT", "__text");
		if (!text_sect) {
			if (verbose)
				printf("getsectforpatch failed (text segment appears "
						"to contain garbage, bypassing patcher)\n");
			*bypass = TRUE;
			return KERN_FAILURE;
		}
		text_addr = (uint64_t) text_sect->addr;
		text_size = (uint64_t) text_sect->size;
		text_offset = text_sect->offset;
	}

	tmp_size = (uint64_t) text_offset + text_size;
#ifdef FIXME
	/* xxx: this check only makes sense if map_addr is guaranteed to be vmaddr */
	if ((text_addr - map_addr) > map_size) {
		printf("text section address not within mapped range\n");
		return KERN_FAILURE;
	} else
#endif
	if (tmp_size > map_size) {
		printf("text section offset and size greater than mapping size\n");
		return KERN_FAILURE;
	} else if ((tmp_size + 16) > map_size) {
		/* take care not to access anything beyond the mapped range if the text
		 * section ends within 16 bytes (maximum instruction length is 15 bytes)
		 * of the end */
		text_size -= 16 - (map_size - tmp_size);
	}

	text_data = (uint8_t *) addr + text_offset;

	if (verbose) {
		uint32_t n;
		for (n = 0; n < 16; n++)
			printf("%02x ", text_data[n]);
		printf("\n");
	}

	/* before attempting to patch anything, scan through some of the section and verify
	 * that what we are attempting to patch is not total garbage. */
	num_bad = scan_text_section(text_data, min(text_size, PRESCAN_SIZE), text_addr, FALSE,
			abi_is_64, verbose, &num_patches);
	if (verbose)
		printf("prescan found %d bad instructions\n", num_bad);
	if (num_bad >= PRESCAN_MAX_BAD) {
		if (verbose)
			printf("text section appears to contain garbage, bypassing patcher\n");
		*bypass = TRUE;
		return KERN_FAILURE;
	}

	/* now that we have decided the text section contains valid code, scan through the
	 * whole section and perform the actual patching. */
	num_bad = scan_text_section(text_data, text_size, text_addr, TRUE, abi_is_64, verbose,
			&num_patches);
	if (verbose)
		printf("complete scan found %d bad instructions\n", num_bad);

	*num_patches_out = num_patches;
	*num_bad_out = num_bad;

	return KERN_SUCCESS;
}

kern_return_t remove_code_signature_32(uint8_t *data)
{
	struct mach_header *mh_32 = (struct mach_header *)data;
	struct load_command *tmplc = (struct load_command *)(data + sizeof(struct mach_header));
	uint32_t curlc = 0;
	uint32_t totlc = mh_32->ncmds;
	uint32_t curoff = sizeof(struct mach_header);
	struct linkedit_data_command *cryptsiglc = (struct linkedit_data_command *)0;
    struct linkedit_data_command *cryptsigdrs = (struct linkedit_data_command *)0;
	uint8_t *cryptsigdata = (uint8_t *)0;
    uint8_t *cryptdrsdata = (uint8_t *)0;
	uint32_t cryptsigdatasize = 0;
	uint32_t zeroeddata = 0;

	/* Get code signature load command + divide */
	while (curlc < totlc)
	{
		if (tmplc->cmd == LC_CODE_SIGNATURE)
		{
			cryptsiglc = (struct linkedit_data_command *)(data + curoff);
		}

        if (tmplc->cmd == LC_DYLIB_CODE_SIGN_DRS)
        {
            cryptsigdrs = (struct linkedit_data_command *)(data + curoff);
        }

		curoff += tmplc->cmdsize;
		tmplc = (struct load_command *)(data + curoff);
		++curlc;
	}

	/* Safety check */
	if ((cryptsiglc == 0) && (cryptsigdrs == 0))
	{
		printf("No code signature found, skipping patch\n");
		return KERN_FAILURE;
	}

    if (cryptsiglc)
    {
        cryptsigdata = (uint8_t *)(data + cryptsiglc->dataoff);

        zeroeddata = 0;

        /* Zero code signature... */
        while (zeroeddata < cryptsiglc->datasize)
        {
            *cryptsigdata = 0;
            ++zeroeddata;
            ++cryptsigdata;
        }

        /* Reduce the number of load commands + load command size */
        mh_32->ncmds -= 1;
        mh_32->sizeofcmds -= cryptsiglc->cmdsize;

    	/* Zero out load command of LC_CODE_SIGNATURE */
        cryptsiglc->cmd = 0;
        cryptsiglc->cmdsize = 0;
        cryptsiglc->dataoff = 0;
        cryptsiglc->datasize = 0;

        printf("Code signature (SIG) removed succesfully (32bit)\n");
    }

    if (cryptsigdrs)
    {
        cryptdrsdata = (uint8_t *)(data + cryptsigdrs->dataoff);

        zeroeddata = 0;

        /* Zero code signature... */
        while (zeroeddata < cryptsigdrs->datasize)
        {
            *cryptdrsdata = 0;
            ++zeroeddata;
            ++cryptdrsdata;
        }

        /* Reduce the number of load commands + load command size */
        mh_32->ncmds -= 1;
        mh_32->sizeofcmds -= cryptsigdrs->cmdsize;
        
        /* Zero out load command of LC_CODE_SIGNATURE */
        cryptsigdrs->cmd = 0;
        cryptsigdrs->cmdsize = 0;
        cryptsigdrs->dataoff = 0;
        cryptsigdrs->datasize = 0;

    	printf("Code signature (DRS) removed succesfully (32bit)\n");
    }

	return KERN_SUCCESS;
}

kern_return_t remove_code_signature_64(uint8_t *data)
{
	struct mach_header_64 *mh_64 = (struct mach_header_64 *)data;
	struct load_command *tmplc = (struct load_command *)(data + sizeof(struct mach_header_64));
	uint32_t curlc = 0;
	uint32_t totlc = mh_64->ncmds;
	uint32_t curoff = sizeof(struct mach_header_64);
	struct linkedit_data_command *cryptsiglc = (struct linkedit_data_command *)0;
    struct linkedit_data_command *cryptsigdrs = (struct linkedit_data_command *)0;
	uint8_t *cryptsigdata = (uint8_t *)0;
    uint8_t *cryptdrsdata = (uint8_t *)0;
	uint32_t cryptsigdatasize = 0;
	uint32_t zeroeddata = 0;
	
       /* Get code signature load command + divide */
        while (curlc < totlc)
        {
                if (tmplc->cmd == LC_CODE_SIGNATURE)
                {
                        cryptsiglc = (struct linkedit_data_command *)(data + curoff);
                }

            if (tmplc->cmd == LC_DYLIB_CODE_SIGN_DRS)
            {
                cryptsigdrs = (struct linkedit_data_command *)(data + curoff);
            }
            

                curoff += tmplc->cmdsize;
                tmplc = (struct load_command *)(data + curoff);
                ++curlc;
        }

	/* Safety check */
	if ((cryptsiglc == 0) && (cryptsigdrs == 0))
	{
		printf("No code signature found, skipping patch\n");
		return KERN_FAILURE;
	}

    if (cryptsiglc)
    {
        cryptsigdata = (uint8_t *)(data + cryptsiglc->dataoff);
	
        /* Zero code signature... */
        while (zeroeddata < cryptsiglc->datasize)
        {
            *cryptsigdata = 0;
            ++zeroeddata;
            ++cryptsigdata;
        }
	
        /* Reduce the number of load commands + load command size */
        mh_64->ncmds -= 1;
        mh_64->sizeofcmds -= cryptsiglc->cmdsize;
	
        /* Zero out load command of LC_CODE_SIGNATURE */
        cryptsiglc->cmd = 0;
        cryptsiglc->cmdsize = 0;
        cryptsiglc->dataoff = 0;
        cryptsiglc->datasize = 0;
	
        printf("Code signature (SIG) removed succesfully (64bit)\n");
    }

    if (cryptsigdrs)
    {
        cryptdrsdata = (uint8_t *)(data + cryptsigdrs->dataoff);
        
        zeroeddata = 0;
        
        /* Zero code signature... */
        while (zeroeddata < cryptsigdrs->datasize)
        {
            *cryptdrsdata = 0;
            ++zeroeddata;
            ++cryptdrsdata;
        }
        
        /* Reduce the number of load commands + load command size */
        mh_64->ncmds -= 1;
        mh_64->sizeofcmds -= cryptsigdrs->cmdsize;
        
        /* Zero out load command of LC_CODE_SIGNATURE */
        cryptsigdrs->cmd = 0;
        cryptsigdrs->cmdsize = 0;
        cryptsigdrs->dataoff = 0;
        cryptsigdrs->datasize = 0;
        
    	printf("Code signature (DRS) removed succesfully (64bit)\n");
    }
    
	return KERN_SUCCESS;
}

void Usage(char *name)
{
	printf("AnV Mach-O AMD Instruction Patcher V1.03\n");
	printf("Usage: %s <infile> <outfile>\n", name);
#ifdef EXTENDED_PATCHER
	printf("Patcher: Extended\n");
#else
	printf("Patcher: Standard\n");
#endif
	printf("Code signature stripping code also included\n");
	printf("Copyright (C) 2010 AnV Software\n");
	printf("Patching routines made by Voodoo team and extended by AnV Software\n");
}

int main(int argc, char **argv)
{
	FILE *f;
	uint8_t *buffer;
	uint8_t *archbuffer;
	struct fat_header *univbin;
	struct fat_arch *archbin;
	int filesize = 0;
	uint32_t current_bin = 0;
	uint32_t total_bins = 0;
	uint32_t total_patches = 0;
	boolean_t bypass = FALSE;
	uint32_t num_patches = 0;
	uint32_t num_bad = 0;

	if (argc != 3)
	{
		Usage(argv[0]);

		return(1);
	}

	f = fopen(argv[1], "rb");

	if (!f)
	{
		printf("ERROR: Opening input file failed\n");

		return(-2);
	}

	fseek(f,0,SEEK_END);
	filesize = ftell(f);
	fseek(f,0,SEEK_SET);

	buffer = (uint8_t *)malloc(filesize);

	fread((char *)buffer,filesize,1,f);

	fclose(f);

	if ((buffer[0] == 0xCE) && (buffer[1] == 0xFA) && (buffer[2] == 0xED) && (buffer[3] == 0xFE)) // Mach-O 32bit
	{
#ifndef CODESIGSTRIP
		patch_text_segment(buffer, 0, filesize, FALSE, FALSE, VERBOSE, &bypass, &num_patches, &num_bad);
		total_patches = num_patches;
#else
		total_patches = 1;
#endif
		remove_code_signature_32(buffer);
	} else if ((buffer[0] == 0xCF) && (buffer[1] == 0xFA) && (buffer[2] == 0xED) && (buffer[3] == 0xFE)) { // Mach-O 64bit
#ifndef CODESIGSTRIP
		patch_text_segment(buffer, 0, filesize, TRUE, TRUE, VERBOSE, &bypass, &num_patches, &num_bad);
		total_patches = num_patches;
#else
		total_patches = 1;
#endif
		remove_code_signature_64(buffer);
	} else if ((buffer[0] == 0xCA) && (buffer[1] == 0xFE) && (buffer[2] == 0xBA) && (buffer[3] == 0xBE)) { // Universal Binary
		total_bins = buffer[7] + (buffer[6] << 8) + (buffer[5] << 16) + (buffer[4] << 24);

		printf ("Patching universal binary (%d architectures)\n", total_bins);

		archbin = (struct fat_arch *)(buffer + 8);
	
		while (current_bin != total_bins)
		{
			if (OSSwapInt32(archbin->cputype) == CPU_TYPE_X86_64)
			{
				printf("Patching X86_64 part (processor %u, architecture %d)\n", OSSwapInt32(archbin->cputype), current_bin);

				archbuffer = buffer + OSSwapInt32(archbin->offset);
#ifndef CODESIGSTRIP
				patch_text_segment(archbuffer, 0, OSSwapInt32(archbin->size), TRUE, TRUE, VERBOSE, &bypass, &num_patches, &num_bad);
				total_patches += num_patches;
#else
				total_patches = 1;
#endif
				remove_code_signature_64(archbuffer);

				printf("Patch report (%d): %u instructions patched, %u bad instructions, patches bypassed: %s\n", current_bin+1, num_patches, num_bad, bypass == TRUE ? "YES" : "NO");
			} else if (OSSwapInt32(archbin->cputype) == CPU_TYPE_I386) {
				printf("Patching I386 part (processor %u, architecture %d)\n", OSSwapInt32(archbin->cputype), current_bin);
				
				archbuffer = buffer + OSSwapInt32(archbin->offset);
#ifndef CODESIGSTRIP
				patch_text_segment(archbuffer, 0, OSSwapInt32(archbin->size), FALSE, FALSE, VERBOSE, &bypass, &num_patches, &num_bad);
				total_patches += num_patches;
#else
				total_patches = 1;
#endif

				remove_code_signature_32(archbuffer);

				printf("Patch report (%d): %u instructions patched, %u bad instructions, patches bypassed: %s\n", current_bin+1, num_patches, num_bad, bypass == TRUE ? "YES" : "NO");
			} else {
				printf("Skipping non-Intel architecture (%d)\n", current_bin);
			}

			++current_bin;
			++archbin;
		}
	}
	else {
		printf("ERROR: Unsupported or no Mach-O file\n");

		return(-1);
	}

	if (total_patches <= 0)
	{
		printf("No patches found, not generating output file");
	} else {
		f = fopen(argv[2], "wb");

        if (!f)
        {
                printf("ERROR: Opening output file failed\n");

                return(-3);
        }

		fwrite((char *)buffer,filesize,1,f);

		fclose(f);
	}

	if (!((buffer[0] == 0xCA) && (buffer[1] == 0xFE) && (buffer[2] == 0xBA) && (buffer[3] == 0xBE)))
		printf("Patch report: %u instructions patched, %u bad instructions, patches bypassed: %s\n", num_patches, num_bad, bypass == TRUE ? "YES" : "NO");

	return(0);
}

