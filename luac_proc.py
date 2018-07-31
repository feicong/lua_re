# ----------------------------------------------------------------------
# Lua 5.2 bytecode processor module
# Copyright (c) 2018 fei_cong@hotmail.com
# ALL RIGHTS RESERVED.

import sys
from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
import ida_frame
from ida_funcs import *
from ida_lines import *
from ida_problems import *
import ida_offset
from ida_segment import *
from ida_name import *
from ida_netnode import *
import idautils
import idc

# extract bitfield occupying bits high..low from val (inclusive, start from 0)
def GET_BITS(val, low, high):
  return (val>>low) & ((1<<(high-low+1)) - 1)

# extract one bit
def BIT(val, bit):
  return (val>>bit) & 1

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m

# check if operand is register reg
def is_reg(op, reg):
    return op.type == o_reg and op.reg == reg

# check if operand is immediate value val
def is_imm(op, val):
    return op.type == o_imm and op.value == val

SIZE_C	=	9
SIZE_B	=	9
SIZE_Bx	=	(SIZE_C + SIZE_B)
SIZE_A	=	8
SIZE_Ax	=	(SIZE_C + SIZE_B + SIZE_A)

BITRK = (1 << (SIZE_B - 1))
def ISK(x):
    return (x & BITRK)

def INDEXK(r):
    return ((r) & ~BITRK)

def CC(r):
    if ISK(r):
        return 'K'
    else:
        return 'R'

def CV(r):
    if ISK(r):
        return INDEXK(r)
    else:
        return r

PLFM_LUAC = 99

# ----------------------------------------------------------------------
class lua_processor_t(processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = PLFM_LUAC

    # Processor features
    flag = PR_SEGS | PR_DEFSEG32 | PR_USE64 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_TYPEINFO

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['Luac']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['Lua Byte code']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    # codestart = ['\x60\x00']  # 60 00 xx xx: MOVqw         SP, SP-delta

    # Array of 'return' instruction opcodes (optional)
    # retcodes = ['\x04\x00']   # 04 00: RET

    # You should define 2 virtual segment registers for CS and DS.
    # Let's call them rVcs and rVds.

    # icode of the first instruction
    instruc_start = 0

    #
    #      Size of long double (tbyte) for this processor
    #      (meaningful only if ash.a_tbyte != NULL)
    #
    tbyte_size = 0

    segstarts = {}
    segends = {}

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP)
        # you may define and use your own bits
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "Lua bytecode assembler",

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string)
        'a_sizeof_fmt': "size %s",
    } # Assembler


    # ----------------------------------------------------------------------
    def dt_to_width(self, dt):
        """Returns OOFW_xxx flag given a dt_xxx"""
        if   dt == dt_byte:  return OOFW_8
        elif dt == dt_word:  return OOFW_16
        elif dt == dt_dword: return OOFW_32
        elif dt == dt_qword: return OOFW_64


    # ----------------------------------------------------------------------
    # Instruction decoding
    # R(x) - register
    # Kst(x) - constant (in constant table)
    # RK(x) == if ISK(x) then Kst(INDEXK(x)) else R(x)
    # ----------------------------------------------------------------------
    def decode_MOVE(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_MOVE,/*	A B	R(A) := R(B)					*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        return True

    def decode_LOADK(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_LOADK,/*	A Bx	R(A) := Kst(Bx)					*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_displ
        insn.Op2.reg = bx
        insn.Op2.dtype = dt_dword

        return True

    def cmt_LOADK(self, insn):
        return "hello LOADK"

    def decode_LOADKX(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_LOADKX,/*	A 	R(A) := Kst(extra arg)				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        return True

    def decode_LOADBOOL(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_LOADBOOL,/*	A B C	R(A) := (Bool)B; if (C) pc++			*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = b
        insn.Op2.dtype = dt_dword

        insn.Op3.type = o_imm
        insn.Op3.value = b
        insn.Op3.dtype = dt_dword

        return True

    def decode_LOADNIL(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_LOADNIL,/*	A B	R(A), R(A+1), ..., R(A+B) := nil		*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = b
        insn.Op2.dtype = dt_dword

        return True

    def decode_GETUPVAL(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_GETUPVAL,/*	A B	R(A) := UpValue[B]				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_displ
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword
        insn.Op2.specval = 1

        return True

    def decode_GETTABUP(self, insn, a, b, c, ax, bx, sbx):
        """
        A B C	R(A) := UpValue[B][RK(C)]
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_displ
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword
        insn.Op2.specval = 1

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_GETTABLE(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_GETTABLE,/*	A B C	R(A) := R(B)[RK(C)]				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_SETTABUP(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_SETTABUP,/*	A B C	UpValue[A][RK(B)] := RK(C)			*/
        """
        insn.Op1.type = o_displ
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword
        insn.Op1.specval = 1

        if (ISK(b)):
            insn.Op2.type = o_displ
            insn.Op2.reg = CV(b)
        else:
            insn.Op2.type = o_reg
            insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_SETUPVAL(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_SETUPVAL,/*	A B	UpValue[B] := R(A)				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_displ
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword
        insn.Op2.specval = 1

        return True

    def decode_SETTABLE(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_SETTABLE,/*	A B C	R(A)[RK(B)] := RK(C)				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        if (ISK(b)):
            insn.Op2.type = o_displ
            insn.Op2.reg = CV(b)
        else:
            insn.Op2.type = o_reg
            insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_NEWTABLE(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_NEWTABLE,/*	A B C	R(A) := {} (size = B,C)				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = b
        insn.Op2.dtype = dt_dword

        insn.Op3.type = o_imm
        insn.Op3.value = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_SELF(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_SELF,/*	A B C	R(A+1) := R(B); R(A) := R(B)[RK(C)]		*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a + 1
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_MATH(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_ADD,/*	A B C	R(A) := RK(B) + RK(C)				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        if (ISK(b)):
            insn.Op2.type = o_displ
            insn.Op2.reg = CV(b)
        else:
            insn.Op2.type = o_reg
            insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_UNM(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_UNM,/*	A B	R(A) := -R(B)					*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        return True

    def decode_NOT(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_NOT,/*	A B	R(A) := not R(B)				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        return True

    def decode_LEN(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_LEN,/*	A B	R(A) := length of R(B)				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        return True

    def decode_CONCAT(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_CONCAT,/*	A B C	R(A) := R(B).. ... ..R(C)			*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        insn.Op3.type = o_reg
        insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_JMP(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_JMP,/*	A sBx	pc+=sBx; if (A) close all upvalues >= R(A - 1)	*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = sbx
        insn.Op2.dtype = dt_dword

        return True

    def decode_EQ(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_EQ,/*	A B C	if ((RK(B) == RK(C)) ~= A) then pc++		*/
        """
        insn.Op1.type = o_imm
        insn.Op1.value = a
        insn.Op1.dtype = dt_dword

        if (ISK(b)):
            insn.Op2.type = o_displ
            insn.Op2.reg = CV(b)
        else:
            insn.Op2.type = o_reg
            insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_LT(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_LT,/*	A B C	if ((RK(B) <  RK(C)) ~= A) then pc++		*/
        """
        insn.Op1.type = o_imm
        insn.Op1.value = a
        insn.Op1.dtype = dt_dword

        if (ISK(b)):
            insn.Op2.type = o_displ
            insn.Op2.reg = CV(b)
        else:
            insn.Op2.type = o_reg
            insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_LE(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_LE,/*	A B C	if ((RK(B) <= RK(C)) ~= A) then pc++		*/
        """
        insn.Op1.type = o_imm
        insn.Op1.value = a
        insn.Op1.dtype = dt_dword

        if (ISK(b)):
            insn.Op2.type = o_displ
            insn.Op2.reg = CV(b)
        else:
            insn.Op2.type = o_reg
            insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        if (ISK(c)):
            insn.Op3.type = o_displ
            insn.Op3.reg = CV(c)
        else:
            insn.Op3.type = o_reg
            insn.Op3.reg = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_TEST(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_TEST,/*	A C	if not (R(A) <=> C) then pc++			*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = c
        insn.Op2.dtype = dt_dword

        return True

    def decode_TESTSET(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_TESTSET,/*	A B C	if (R(B) <=> C) then R(A) := R(B) else pc++	*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_reg
        insn.Op2.reg = b
        insn.Op2.dtype = dt_dword

        insn.Op3.type = o_imm
        insn.Op3.value = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_CALL(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_CALL,/*	A B C	R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
        OP_TAILCALL,/*	A B C	return R(A)(R(A+1), ... ,R(A+B-1))		*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = b
        insn.Op2.dtype = dt_dword

        insn.Op3.type = o_imm
        insn.Op3.value = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_RETURN(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_RETURN,/*	A B	return R(A), ... ,R(A+B-2)	(see note)	*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = b
        insn.Op2.dtype = dt_dword

        return True

    def decode_FORLOOP(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_FORLOOP,/*	A sBx	R(A)+=R(A+2);
			if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = sbx
        insn.Op2.dtype = dt_dword

        return True

    def decode_FORPREP(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_FORPREP,/*	A sBx	R(A)-=R(A+2); pc+=sBx				*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = sbx
        insn.Op2.dtype = dt_dword

        return True

    def decode_TFORCALL(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_TFORCALL,/*	A C	R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));	*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = c
        insn.Op2.dtype = dt_dword

        return True

    def decode_TFORLOOP(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_TFORLOOP,/*	A sBx	if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = sbx
        insn.Op2.dtype = dt_dword

        return True

    def decode_SETLIST(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_SETLIST,/*	A B C	R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B	*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = b
        insn.Op2.dtype = dt_dword

        insn.Op3.type = o_imm
        insn.Op3.value = c
        insn.Op3.dtype = dt_dword

        return True

    def decode_CLOSURE(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_CLOSURE,/*	A Bx	R(A) := closure(KPROTO[Bx])			*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = bx
        insn.Op2.dtype = dt_dword

        return True

    def decode_VARARG(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_VARARG,/*	A B	R(A), R(A+1), ..., R(A+B-2) = vararg		*/
        """
        insn.Op1.type = o_reg
        insn.Op1.reg = a
        insn.Op1.dtype = dt_dword

        insn.Op2.type = o_imm
        insn.Op2.value = b
        insn.Op2.dtype = dt_dword

        return True

    def decode_EXTRAARG(self, insn, a, b, c, ax, bx, sbx):
        """
        OP_EXTRAARG/*	Ax	extra (larger) argument for previous opcode	*/
        """
        insn.Op1.type = o_imm
        insn.Op1.value = ax
        insn.Op1.dtype = dt_dword

        return True


    # ----------------------------------------------------------------------
    # Processor module callbacks
    #
    # ----------------------------------------------------------------------
    def notify_get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        for EBC it's 8 bytes of the actual return address
        plus 8 bytes of the saved frame address
        """
        return 16

    def notify_may_be_func(self, insn, state):
        """
        can a function start here?
        the instruction is in 'cmd'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        print("notify_may_be_func called. ea:%x, state:%d" % (insn.ea, state))
        if self.check_is_segstart(insn.ea):
            return 100
        else:
            return 10

    def notify_add_func(self, func_ea):
        """
        The kernel has added a function.
        @param func_ea: function start EA
        @return: Nothing
        """
        print("notify_add_func called. func_ea:%x" % func_ea)

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        print("notify_get_autocmt called:%x ea:%x" % insn.ea)
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt'](insn)

    # ----------------------------------------------------------------------
    def notify_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return op.type in [o_imm, o_displ, o_mem]

    # ----------------------------------------------------------------------
    def notify_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        #print("notify_is_align_insn called\n")
        return 0

    # ----------------------------------------------------------------------
    def notify_newfile(self, filename):
        print("notify_newfile called\n")
        self.init_seginfo()

    # ----------------------------------------------------------------------
    def notify_oldfile(self, filename):
        pass

    # ----------------------------------------------------------------------
    def notify_out_header(self, ctx):
        """function to produce start of disassembled text"""
        ctx.out_line("; Lua 52, unit size: %d bits" % (self.PTRSZ*8))
        ctx.flush_outbuf(0)

    def init_seginfo(self):
        #print("seg len:%d\n" % len(list(idautils.Segments())))
        for seg in idautils.Segments():
            segname = idc.SegName(seg)
            if segname.startswith('func_'):
                self.segstarts[idc.SegStart(seg)] = segname
                self.segends[idc.SegEnd(seg)] = segname
                #print("segname:%s\n" % segname)
                #print("add_func() called ret:%d" % add_func(idc.SegStart(seg), idc.SegEnd(seg)))

    def check_is_segstart(self, ea):
        return ea in self.segstarts

    def check_is_segend(self, ea):
        return ea in self.segends

    # ----------------------------------------------------------------------
    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        print("notify_emu called. ea:%x" % insn.ea)
        # for k in self.segstarts.keys():
        #    print(self.segstarts[k])

        return 1


    def notify_setup_til(self):
        """Setup default type libraries (called after loading a new file into the database)
        The processor module may load tils, setup memory model and perform other actions required to set up the type system
        @return: None
        """
        print("notify_setup_til called.")

    # ----------------------------------------------------------------------
    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        #print("notify_out_operand called. op:%x" % op.type)
        optype = op.type
        fl     = op.specval
        def_arg = is_defarg(get_flags(ctx.insn.ea), op.n)

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif optype == o_imm:
            # for immediate loads, use the transfer width (type of first operand)
            if op.n == 1:
                width = self.dt_to_width(ctx.insn.Op1.dtype)
            else:
                width = OOFW_32 if self.PTRSZ == 4 else OOFW_64
            ctx.out_value(op, OOFW_IMM | width)

        elif optype in [o_near, o_mem]:
            r = ctx.out_name_expr(op, op.addr, idc.BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)

        elif optype == o_displ:
            is_upval = fl
            if is_upval:
                ctx.out_register(self.upvalue_names[op.reg])    #Upvalues
            else:
                ctx.out_register(self.constant_names[op.reg])   #Constants

            #if op.addr != 0 or def_arg:
            #    ctx.out_value(op, OOF_ADDR | (OOFW_32 if self.PTRSZ == 4 else OOFW_64) | signed | OOFS_NEEDSIGN)

        else:
            return False

        return True

    # ----------------------------------------------------------------------
    # Generate the instruction mnemonics
    def out_mnem(self, ctx):
        # Init output buffer
        #print("out_mnem called.\n")
        ctx.out_mnem(12)

    # ----------------------------------------------------------------------
    # Generate text representation of an instruction in 'ctx.insn' structure.
    # This function shouldn't change the database, flags or anything else.
    # All these actions should be performed only by u_emu() function.
    def notify_out_insn(self, ctx):
        print("notify_out_insn called.\n")
        ctx.out_mnemonic()

        ctx.out_one_operand(0)
        for i in xrange(1, 3):
            op = ctx.insn[i]

            if op.type == o_void:
                break

            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()  # generate comment at the next call to MakeLine()
        ctx.flush_outbuf()

    def notify_set_func_start(self, func_start_ea, new_ea):
        """
        Function chunk start address will be changed
        args:
          func_start_ea, end_ea
        Returns: 1-ok,<=0-do not change
        """
        print("notify_set_func_start called, func_start_ea:%x, new_ea:%x" % (func_start_ea, new_ea))
        return 1

    def notify_set_func_end(self, func_start_ea, func_end_ea):
        """
        Function chunk end address will be changed
        args:
          func_start_ea, func_end_ea
        Returns: 1-ok,<=0-do not change
        """
        print("notify_set_func_end called, func_start_ea:%x, func_end_ea:%x" % (func_start_ea, func_end_ea))
        return 1

    # ----------------------------------------------------------------------
    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        """
        # take opcode byte
        b = insn.get_next_dword()

        # the 6bit opcode
        opcode = b & 0x3F
        arg_a = GET_BITS(b, 6, 13)
        arg_b = GET_BITS(b, 23, 31)
        arg_c = GET_BITS(b, 14, 22)
        arg_ax = GET_BITS(b, 6, 31)
        arg_bx = GET_BITS(b, 14, 31)
        arg_sbx = GET_BITS(b, 14, 31) - 131071

        print("opcode:%x, a:%x, b:%x, c:%x, ax:%x, bx:%x, sbx:%d" % (opcode, arg_a, arg_b, arg_c, arg_ax, arg_bx, arg_sbx))

        # opcode supported?
        try:
            ins = self.itable[opcode]
            # set default itype
            insn.itype = getattr(self, 'itype_' + ins.name)
        except:
            return 4

        # call the decoder
        return insn.size if ins.d(insn, arg_a, arg_b, arg_c, arg_ax, arg_bx, arg_sbx) else 0

    # ----------------------------------------------------------------------
    def init_instructions(self):
        class idef:
            """
            Internal class that describes an instruction by:
            - instruction name
            - instruction decoding routine
            - canonical flags used by IDA
            """
            def __init__(self, name, d, cf, cmt = None):
                self.name = name
                self.d = d
                self.cf  = cf
                self.cmt = cmt

        #
        # Instructions table (w/ pointer to decoder)
        #
        self.itable = {
            0x00: idef(name='MOVE', d=self.decode_MOVE, cf=CF_USE1 | CF_USE2, cmt=''),
            0x01: idef(name='LOADK', d=self.decode_LOADK, cf=CF_USE1 | CF_USE2, cmt=self.cmt_LOADK),
            0x02: idef(name='LOADKX', d=self.decode_LOADKX, cf=CF_USE1 | CF_USE2, cmt=''),
            0x03: idef(name='LOADBOOL', d=self.decode_LOADBOOL, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x04: idef(name='LOADNIL', d=self.decode_LOADNIL, cf=CF_USE1 | CF_USE2, cmt=''),
            0x05: idef(name='GETUPVAL', d=self.decode_GETUPVAL, cf=CF_USE1 | CF_USE2, cmt=''),

            0x06: idef(name='GETTABUP', d=self.decode_GETTABUP, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x07: idef(name='GETTABLE', d=self.decode_GETTABLE, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x08: idef(name='SETTABUP', d=self.decode_SETTABUP, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x09: idef(name='SETUPVAL', d=self.decode_SETUPVAL, cf=CF_USE1 | CF_USE2, cmt=''),
            0x0A: idef(name='SETTABLE', d=self.decode_SETTABLE, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x0B: idef(name='NEWTABLE', d=self.decode_NEWTABLE, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x0C: idef(name='SELF', d=self.decode_SELF, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x0D: idef(name='ADD', d=self.decode_MATH, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x0E: idef(name='SUB', d=self.decode_MATH, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x0F: idef(name='MUL', d=self.decode_MATH, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x10: idef(name='DIV', d=self.decode_MATH, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x11: idef(name='MOD', d=self.decode_MATH, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x12: idef(name='POW', d=self.decode_MATH, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x13: idef(name='UNM', d=self.decode_UNM, cf=CF_USE1 | CF_USE2, cmt=''),
            0x14: idef(name='NOT', d=self.decode_NOT, cf=CF_USE1 | CF_USE2, cmt=''),
            0x15: idef(name='LEN', d=self.decode_LEN, cf=CF_USE1 | CF_USE2, cmt=''),

            0x16: idef(name='CONCAT', d=self.decode_CONCAT, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x17: idef(name='JMP', d=self.decode_JMP, cf=CF_USE1 | CF_USE2, cmt=''),
            0x18: idef(name='EQ', d=self.decode_EQ, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x19: idef(name='LT', d=self.decode_LT, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x1A: idef(name='LE', d=self.decode_LE, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x1B: idef(name='TEST', d=self.decode_TEST, cf=CF_USE1 | CF_USE2, cmt=''),
            0x1C: idef(name='TESTSET', d=self.decode_TESTSET, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x1D: idef(name='CALL', d=self.decode_CALL, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x1E: idef(name='TAILCALL', d=self.decode_CALL, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),
            0x1F: idef(name='RETURN', d=self.decode_RETURN, cf=CF_USE1 | CF_USE2, cmt=''),

            0x20: idef(name='FORLOOP', d=self.decode_FORLOOP, cf=CF_USE1 | CF_USE2, cmt=''),

            0x21: idef(name='FORPREP', d=self.decode_FORPREP, cf=CF_USE1 | CF_USE2, cmt=''),

            0x22: idef(name='TFORCALL', d=self.decode_TFORCALL, cf=CF_USE1 | CF_USE2, cmt=''),
            0x23: idef(name='TFORLOOP', d=self.decode_TFORLOOP, cf=CF_USE1 | CF_USE2, cmt=''),

            0x24: idef(name='SETLIST', d=self.decode_SETLIST, cf=CF_USE1 | CF_USE2 | CF_USE3, cmt=''),

            0x25: idef(name='CLOSURE', d=self.decode_CLOSURE, cf=CF_USE1 | CF_USE2, cmt=''),

            0x26: idef(name='VARARG', d=self.decode_VARARG, cf=CF_USE1 | CF_USE2, cmt=''),

            0x27: idef(name='EXTRAARG', d=self.decode_EXTRAARG, cf=CF_USE1, cmt=''),
        }

        # Now create an instruction table compatible with IDA processor module requirements
        Instructions = []
        i = 0
        for x in self.itable.values():
            d = dict(name=x.name, feature=x.cf)
            if x.cmt != None:
                d['cmt'] = x.cmt
            Instructions.append(d)
            setattr(self, 'itype_' + x.name, i)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(Instructions) + 1

        # Array of instructions
        self.instruc = Instructions

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_RETURN

    # ----------------------------------------------------------------------
    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        # Registers definition
        self.reg_names = [
            # General purpose registers
            # #define MAXSTACK	250
            # >>> for i in xrange(250):
            # ...     print("\"R%d\"," % i)
            "R0",
            "R1",
            "R2",
            "R3",
            "R4",
            "R5",
            "R6",
            "R7",
            "R8",
            "R9",
            "R10",
            "R11",
            "R12",
            "R13",
            "R14",
            "R15",
            "R16",
            "R17",
            "R18",
            "R19",
            "R20",
            "R21",
            "R22",
            "R23",
            "R24",
            "R25",
            "R26",
            "R27",
            "R28",
            "R29",
            "R30",
            "R31",
            "R32",
            "R33",
            "R34",
            "R35",
            "R36",
            "R37",
            "R38",
            "R39",
            "R40",
            "R41",
            "R42",
            "R43",
            "R44",
            "R45",
            "R46",
            "R47",
            "R48",
            "R49",
            "R50",
            "R51",
            "R52",
            "R53",
            "R54",
            "R55",
            "R56",
            "R57",
            "R58",
            "R59",
            "R60",
            "R61",
            "R62",
            "R63",
            "R64",
            "R65",
            "R66",
            "R67",
            "R68",
            "R69",
            "R70",
            "R71",
            "R72",
            "R73",
            "R74",
            "R75",
            "R76",
            "R77",
            "R78",
            "R79",
            "R80",
            "R81",
            "R82",
            "R83",
            "R84",
            "R85",
            "R86",
            "R87",
            "R88",
            "R89",
            "R90",
            "R91",
            "R92",
            "R93",
            "R94",
            "R95",
            "R96",
            "R97",
            "R98",
            "R99",
            "R100",
            "R101",
            "R102",
            "R103",
            "R104",
            "R105",
            "R106",
            "R107",
            "R108",
            "R109",
            "R110",
            "R111",
            "R112",
            "R113",
            "R114",
            "R115",
            "R116",
            "R117",
            "R118",
            "R119",
            "R120",
            "R121",
            "R122",
            "R123",
            "R124",
            "R125",
            "R126",
            "R127",
            "R128",
            "R129",
            "R130",
            "R131",
            "R132",
            "R133",
            "R134",
            "R135",
            "R136",
            "R137",
            "R138",
            "R139",
            "R140",
            "R141",
            "R142",
            "R143",
            "R144",
            "R145",
            "R146",
            "R147",
            "R148",
            "R149",
            "R150",
            "R151",
            "R152",
            "R153",
            "R154",
            "R155",
            "R156",
            "R157",
            "R158",
            "R159",
            "R160",
            "R161",
            "R162",
            "R163",
            "R164",
            "R165",
            "R166",
            "R167",
            "R168",
            "R169",
            "R170",
            "R171",
            "R172",
            "R173",
            "R174",
            "R175",
            "R176",
            "R177",
            "R178",
            "R179",
            "R180",
            "R181",
            "R182",
            "R183",
            "R184",
            "R185",
            "R186",
            "R187",
            "R188",
            "R189",
            "R190",
            "R191",
            "R192",
            "R193",
            "R194",
            "R195",
            "R196",
            "R197",
            "R198",
            "R199",
            "R200",
            "R201",
            "R202",
            "R203",
            "R204",
            "R205",
            "R206",
            "R207",
            "R208",
            "R209",
            "R210",
            "R211",
            "R212",
            "R213",
            "R214",
            "R215",
            "R216",
            "R217",
            "R218",
            "R219",
            "R220",
            "R221",
            "R222",
            "R223",
            "R224",
            "R225",
            "R226",
            "R227",
            "R228",
            "R229",
            "R230",
            "R231",
            "R232",
            "R233",
            "R234",
            "R235",
            "R236",
            "R237",
            "R238",
            "R239",
            "R240",
            "R241",
            "R242",
            "R243",
            "R244",
            "R245",
            "R246",
            "R247",
            "R248",
            "R249",
            # Fake segment registers
            "CS",
            "DS"
        ]

        # Constants definition
        self.constant_names = [
            # #define MAXSTACK	250
            # >>> for i in xrange(250):
            # ...     print("\"K%d\"," % i)
            "K0",
            "K1",
            "K2",
            "K3",
            "K4",
            "K5",
            "K6",
            "K7",
            "K8",
            "K9",
            "K10",
            "K11",
            "K12",
            "K13",
            "K14",
            "K15",
            "K16",
            "K17",
            "K18",
            "K19",
            "K20",
            "K21",
            "K22",
            "K23",
            "K24",
            "K25",
            "K26",
            "K27",
            "K28",
            "K29",
            "K30",
            "K31",
            "K32",
            "K33",
            "K34",
            "K35",
            "K36",
            "K37",
            "K38",
            "K39",
            "K40",
            "K41",
            "K42",
            "K43",
            "K44",
            "K45",
            "K46",
            "K47",
            "K48",
            "K49",
            "K50",
            "K51",
            "K52",
            "K53",
            "K54",
            "K55",
            "K56",
            "K57",
            "K58",
            "K59",
            "K60",
            "K61",
            "K62",
            "K63",
            "K64",
            "K65",
            "K66",
            "K67",
            "K68",
            "K69",
            "K70",
            "K71",
            "K72",
            "K73",
            "K74",
            "K75",
            "K76",
            "K77",
            "K78",
            "K79",
            "K80",
            "K81",
            "K82",
            "K83",
            "K84",
            "K85",
            "K86",
            "K87",
            "K88",
            "K89",
            "K90",
            "K91",
            "K92",
            "K93",
            "K94",
            "K95",
            "K96",
            "K97",
            "K98",
            "K99",
            "K100",
            "K101",
            "K102",
            "K103",
            "K104",
            "K105",
            "K106",
            "K107",
            "K108",
            "K109",
            "K110",
            "K111",
            "K112",
            "K113",
            "K114",
            "K115",
            "K116",
            "K117",
            "K118",
            "K119",
            "K120",
            "K121",
            "K122",
            "K123",
            "K124",
            "K125",
            "K126",
            "K127",
            "K128",
            "K129",
            "K130",
            "K131",
            "K132",
            "K133",
            "K134",
            "K135",
            "K136",
            "K137",
            "K138",
            "K139",
            "K140",
            "K141",
            "K142",
            "K143",
            "K144",
            "K145",
            "K146",
            "K147",
            "K148",
            "K149",
            "K150",
            "K151",
            "K152",
            "K153",
            "K154",
            "K155",
            "K156",
            "K157",
            "K158",
            "K159",
            "K160",
            "K161",
            "K162",
            "K163",
            "K164",
            "K165",
            "K166",
            "K167",
            "K168",
            "K169",
            "K170",
            "K171",
            "K172",
            "K173",
            "K174",
            "K175",
            "K176",
            "K177",
            "K178",
            "K179",
            "K180",
            "K181",
            "K182",
            "K183",
            "K184",
            "K185",
            "K186",
            "K187",
            "K188",
            "K189",
            "K190",
            "K191",
            "K192",
            "K193",
            "K194",
            "K195",
            "K196",
            "K197",
            "K198",
            "K199",
            "K200",
            "K201",
            "K202",
            "K203",
            "K204",
            "K205",
            "K206",
            "K207",
            "K208",
            "K209",
            "K210",
            "K211",
            "K212",
            "K213",
            "K214",
            "K215",
            "K216",
            "K217",
            "K218",
            "K219",
            "K220",
            "K221",
            "K222",
            "K223",
            "K224",
            "K225",
            "K226",
            "K227",
            "K228",
            "K229",
            "K230",
            "K231",
            "K232",
            "K233",
            "K234",
            "K235",
            "K236",
            "K237",
            "K238",
            "K239",
            "K240",
            "K241",
            "K242",
            "K243",
            "K244",
            "K245",
            "K246",
            "K247",
            "K248",
            "K249"
        ]

        # Upvalues definition
        self.upvalue_names = [
            # #define MAXSTACK	250
            # >>> for i in xrange(250):
            # ...     print("\"U%d\"," % i)
            "U0",
            "U1",
            "U2",
            "U3",
            "U4",
            "U5",
            "U6",
            "U7",
            "U8",
            "U9",
            "U10",
            "U11",
            "U12",
            "U13",
            "U14",
            "U15",
            "U16",
            "U17",
            "U18",
            "U19",
            "U20",
            "U21",
            "U22",
            "U23",
            "U24",
            "U25",
            "U26",
            "U27",
            "U28",
            "U29",
            "U30",
            "U31",
            "U32",
            "U33",
            "U34",
            "U35",
            "U36",
            "U37",
            "U38",
            "U39",
            "U40",
            "U41",
            "U42",
            "U43",
            "U44",
            "U45",
            "U46",
            "U47",
            "U48",
            "U49",
            "U50",
            "U51",
            "U52",
            "U53",
            "U54",
            "U55",
            "U56",
            "U57",
            "U58",
            "U59",
            "U60",
            "U61",
            "U62",
            "U63",
            "U64",
            "U65",
            "U66",
            "U67",
            "U68",
            "U69",
            "U70",
            "U71",
            "U72",
            "U73",
            "U74",
            "U75",
            "U76",
            "U77",
            "U78",
            "U79",
            "U80",
            "U81",
            "U82",
            "U83",
            "U84",
            "U85",
            "U86",
            "U87",
            "U88",
            "U89",
            "U90",
            "U91",
            "U92",
            "U93",
            "U94",
            "U95",
            "U96",
            "U97",
            "U98",
            "U99",
            "U100",
            "U101",
            "U102",
            "U103",
            "U104",
            "U105",
            "U106",
            "U107",
            "U108",
            "U109",
            "U110",
            "U111",
            "U112",
            "U113",
            "U114",
            "U115",
            "U116",
            "U117",
            "U118",
            "U119",
            "U120",
            "U121",
            "U122",
            "U123",
            "U124",
            "U125",
            "U126",
            "U127",
            "U128",
            "U129",
            "U130",
            "U131",
            "U132",
            "U133",
            "U134",
            "U135",
            "U136",
            "U137",
            "U138",
            "U139",
            "U140",
            "U141",
            "U142",
            "U143",
            "U144",
            "U145",
            "U146",
            "U147",
            "U148",
            "U149",
            "U150",
            "U151",
            "U152",
            "U153",
            "U154",
            "U155",
            "U156",
            "U157",
            "U158",
            "U159",
            "U160",
            "U161",
            "U162",
            "U163",
            "U164",
            "U165",
            "U166",
            "U167",
            "U168",
            "U169",
            "U170",
            "U171",
            "U172",
            "U173",
            "U174",
            "U175",
            "U176",
            "U177",
            "U178",
            "U179",
            "U180",
            "U181",
            "U182",
            "U183",
            "U184",
            "U185",
            "U186",
            "U187",
            "U188",
            "U189",
            "U190",
            "U191",
            "U192",
            "U193",
            "U194",
            "U195",
            "U196",
            "U197",
            "U198",
            "U199",
            "U200",
            "U201",
            "U202",
            "U203",
            "U204",
            "U205",
            "U206",
            "U207",
            "U208",
            "U209",
            "U210",
            "U211",
            "U212",
            "U213",
            "U214",
            "U215",
            "U216",
            "U217",
            "U218",
            "U219",
            "U220",
            "U221",
            "U222",
            "U223",
            "U224",
            "U225",
            "U226",
            "U227",
            "U228",
            "U229",
            "U230",
            "U231",
            "U232",
            "U233",
            "U234",
            "U235",
            "U236",
            "U237",
            "U238",
            "U239",
            "U240",
            "U241",
            "U242",
            "U243",
            "U244",
            "U245",
            "U246",
            "U247",
            "U248",
            "U249"
        ]

        # Create the ireg_XXXX constants
        for i in xrange(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        # Create the iconst_XXXX constants
        for i in xrange(len(self.constant_names)):
            setattr(self, 'iconst_' + self.constant_names[i], i)

        # Create the iupval_XXXX constants
        for i in xrange(len(self.upvalue_names)):
            setattr(self, 'iupval_' + self.upvalue_names[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg  = self.ireg_DS

        # number of CS register
        self.reg_code_sreg = self.ireg_CS

        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    # ----------------------------------------------------------------------
    def __init__(self):
        processor_t.__init__(self)
        self.PTRSZ = 4 # Assume PTRSZ = 4 by default
        self.init_instructions()
        self.init_registers()

# ----------------------------------------------------------------------
def PROCESSOR_ENTRY():
    return lua_processor_t()
