# ----------------------------------------------------------------------
# a file loader for Lua 5.2 luac bytecodes.
# Copyright (c) 2018 fei_cong@hotmail.com
# ALL RIGHTS RESERVED.

import idaapi
from idc import *
from idaapi import *
from idautils import *


LUA_SIGNATURE = 0x61754c1b        # Image Magic Number

FormatName        = "Lua 5.2"

import ctypes

uint8_t  = ctypes.c_byte
uint32_t = ctypes.c_uint

size_Instruction = 4
size_lua_Number = 8


DEBUG = True

def DEBUG_PRINT(s) :
    if DEBUG:
        print(s)

class global_header(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("signature", uint32_t),
        ("version",  uint8_t),
        ("format",  uint8_t),
        ("endian",  uint8_t),
        ("size_int",  uint8_t),
        ("size_size_t",    uint8_t),
        ("size_Instruction",  uint8_t),
        ("size_lua_Number",    uint8_t),
        ("lua_num_valid",  uint8_t),
        ("luac_tail",  uint8_t * 6),
    ]

class proto_header(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("linedefined", uint32_t),
        ("lastlinedefined", uint32_t),
        ("numparams", uint8_t),
        ("is_vararg", uint8_t),
        ("maxstacksize", uint8_t),
    ]


class Code:
    def __init__(self, li, off):
        self.sizecode = dwordAt(li, off)
        self.off = off
        self.insts = []

        i = 0
        off = off + 4
        while i < self.sizecode:
            self.insts.append(dwordAt(li, off))
            off = off + 4
            i = i + 1

    def size(self):
        return 4 + size_Instruction * self.sizecode

LUA_TNIL		=     0
LUA_TBOOLEAN	=	  1
LUA_TLIGHTUSERDATA =  2
LUA_TNUMBER		=     3
LUA_TSTRING		=     4
LUA_TTABLE		=     5
LUA_TFUNCTION	=     6
LUA_TUSERDATA	=     7
LUA_TTHREAD		=     8
LUA_NUMTAGS	     =    9

class Constant:
    def __init__(self, li, off):
        li.seek(off)
        self.type = charAt(li, off)
        self.tp = ord(self.type)
        self.ival = 0
        self.fltval = 0
        self.str_sz = 0
        self.strval = ''
        self.bval = False

        off += 1
        DEBUG_PRINT("tp: %d" % self.tp)
        if self.tp == LUA_TBOOLEAN:
            self.bval = charAt(li, off)
        elif self.tp == LUA_TNUMBER:
            self.ival = qwordAt(li, off)
            DEBUG_PRINT("off: %x, ival: %x\n" % (off, self.ival))
        elif self.tp == LUA_TSTRING:
            self.str_sz = qwordAt(li, off)
            off += 8
            self.strval = strAt(li, off, self.str_sz)
            #DEBUG_PRINT("str ea:0x%x, end_ea:0x%x" % (off, off + self.str_sz))
            strs.append(get_str_area(self.strval, off, off + self.str_sz))
        elif self.tp == LUA_TNIL:
            pass
        else:
            DEBUG_PRINT("maybe error!\n")
            self.ival = qwordAt(li, off)

    def size(self):
        if self.tp == LUA_TNIL:
            return 1
        elif self.tp == LUA_TBOOLEAN:
            return 2
        elif self.tp == LUA_TSTRING:
            return 1 + size_lua_Number + self.str_sz
        else:
            return 1 + size_lua_Number

def ReadConstant(li, off):
    constant = Constant(li, off)
    return constant


class Constants:
    def __init__(self, li, off):
        self.sizek = dwordAt(li, off)
        self.off = off
        self.constant = []
        self.sz = 4

        i = 0
        off = off + 4
        while i < self.sizek:
            constant = ReadConstant(li, off)
            self.constant.append(constant)
            off = off + constant.size()
            self.sz += constant.size()
            DEBUG_PRINT("constant.size(): %x\n" % constant.size())
            i = i + 1

    def size(self):
        return self.sz

class Upvaldesc:
    def __init__(self, li, off):
        li.seek(off)
        self.instack = charAt(li, off)
        off += 1
        self.idx = charAt(li, off)
        DEBUG_PRINT("instack:%x, idx:%x\n" % (ord(self.instack), ord(self.idx)))

    def size(self):
        return 2

def ReadUpvaldesc(li, off):
    upval = Upvaldesc(li, off)
    return upval

class Upvaldescs:
    def __init__(self, li, off):
        self.sizeupvalues = dwordAt(li, off)
        self.upvalues = []
        self.sz = 4
        DEBUG_PRINT("sizeupvalues: %x\n" % self.sizeupvalues)

        i = 0
        off = off + 4
        while i < self.sizeupvalues:
            upval = ReadUpvaldesc(li, off)
            self.upvalues.append(upval)
            off = off + upval.size()
            self.sz += upval.size()
            i = i + 1

    def size(self):
        return self.sz

class SourceName:
    def __init__(self, li, off):
        self.name_len = qwordAt(li, off)
        off += self.name_len
        self.name_str = li.read(self.name_len)
        DEBUG_PRINT("src name: %s\n" % self.name_str)

    def size(self):
        return 8 + self.name_len

class Lines:
    def __init__(self, li, off):
        self.sizelineinfo = dwordAt(li, off)
        self.lines = []

        i = 0
        off = off + 4
        while i < self.sizelineinfo:
            self.lines.append(dwordAt(li, off))
            off = off + 4
            i = i + 1

    def size(self):
        return 4 + self.sizelineinfo * 4

class LocVar:
    def __init__(self, li, off):
        self.varname_size = qwordAt(li, off)
        off += 8
        self.varname = li.read(self.varname_size)
        off += self.varname_size
        self.startpc = dwordAt(li, off)
        off += 4
        self.endpc = dwordAt(li, off)
        DEBUG_PRINT("locvar name: %s\n" % self.varname)

    def size(self):
        return 8 + self.varname_size + 4 + 4

def ReadLocVar(li, off):
    locvar = LocVar(li, off)
    return locvar

class LocVars:
    def __init__(self, li, off):
        self.sizelocvars = dwordAt(li, off)
        self.local_var = []
        self.sz = 4

        i = 0
        off = off + 4
        while i < self.sizelocvars:
            loc_var = ReadLocVar(li, off)
            self.local_var.append(loc_var)
            off = off + loc_var.size()
            self.sz += loc_var.size()
            i = i + 1

    def size(self):
        return self.sz

class UpValueName:
    def __init__(self, li, off):
        self.name_len = qwordAt(li, off)
        off += self.name_len
        self.name_str = li.read(self.name_len)
        DEBUG_PRINT("upval name: %s\n" % self.name_str)

    def size(self):
        return 8 + self.name_len

def ReadUpValueName(li, off):
    upval_name = UpValueName(li, off)
    return upval_name

class UpValueNames:
    def __init__(self, li, off):
        self.size_upvalue_names = dwordAt(li, off)
        self.upvalue_names = []
        self.sz = 4

        i = 0
        off = off + 4
        while i < self.size_upvalue_names:
            upval_name = ReadUpValueName(li, off)
            self.upvalue_names.append(upval_name)
            off = off + upval_name.size()
            self.sz += upval_name.size()
            i = i + 1

    def size(self):
        return self.sz

def get_func_area(level, startEA, endEA, headerOff):
    DEBUG_PRINT("level: %s, startEA: 0x%x, endEA: 0x%x\n" % (level, startEA, endEA))
    return ['func_' + level, startEA, endEA, headerOff, 'funcheader_' + level]

def get_consts_area(level, startEA, endEA):
    #DEBUG_PRINT("level: %s, startEA: 0x%x, endEA: 0x%x\n" % (level, startEA, endEA))
    return ['const_' + level, startEA, endEA]

def get_str_area(str, startEA, endEA):
    #DEBUG_PRINT("str: %s, startEA: 0x%x, endEA: 0x%x\n" % (str, startEA, endEA))
    return [str, startEA, endEA]

funcs = []
consts = []
strs = []
class Proto:
    def __init__(self, li, off, level):
        self.level = level
        DEBUG_PRINT("level: %s\n" % self.level)
        off_ = off
        li.seek(off)
        self.header = read_struct(li, proto_header)
        off += ctypes.sizeof(proto_header)
        self.code_off = off
        self.code = Code(li, off)
        funcs.append(get_func_area(level, off + 4, off + self.code.size(), off_))
        off = off + self.code.size()
        self.constants = Constants(li, off)
        consts.append(get_consts_area(level, off + 4, off + self.constants.size()))
        off = off + self.constants.size()
        DEBUG_PRINT("protos off:%x\n" % off)
        self.protos = Protos(li, off, level)
        off = off + self.protos.size()
        self.upvaldecs = Upvaldescs(li, off)
        off = off + self.upvaldecs.size()
        self.src_name = SourceName(li, off)
        off = off + self.src_name.size()
        self.lines = Lines(li, off)
        off = off + self.lines.size()
        self.loc_vars = LocVars(li, off)
        off = off + self.loc_vars.size()
        self.upval_names = UpValueNames(li, off)
        off = off + self.upval_names.size()
        self.sz = off - off_

    def size(self):
        return self.sz

def ReadProto(li, off, level):
    proto = Proto(li, off, level)
    return proto

class Protos:
    def __init__(self, li, off, level):
        self.level = level
        self.sizep = dwordAt(li, off)
        self.proto = []
        self.sz = 4
        DEBUG_PRINT("sizep: %x\n" % self.sizep)

        i = 0
        off = off + 4
        while i < self.sizep:
            if self.sizep == 0:
                return
            proto = ReadProto(li, off, self.level + "_" + str(i))
            self.proto.append(proto)
            off = off + proto.size()
            self.sz += proto.size()
            i = i + 1

    def size(self):
        return self.sz

def ReadProtos(li, off, level):
    protos = Protos(li, off, level)
    return protos


# -----------------------------------------------------------------------
def charAt(li, off):
    li.seek(off)
    s = li.read(1)
    return struct.unpack('<c', s)[0]

def strAt(li, off, len):
    li.seek(off)
    s = li.read(len)
    return s

def dwordAt(li, off):
    li.seek(off)
    s = li.read(4)
    if len(s) < 4:
        return 0
    return struct.unpack('<I', s)[0]

def qwordAt(li, off):
    li.seek(off)
    s = li.read(8)
    if len(s) < 8:
        return 0
    return struct.unpack('<Q', s)[0]

def read_struct(li, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    #DEBUG_PRINT("slen:%d" % slen)
    bytes = li.read(slen)
    fit = min(len(bytes), slen)
    ctypes.memmove(ctypes.addressof(s), bytes, fit)
    return s

# -----------------------------------------------------------------------
def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    header = read_struct(li, global_header)
    # check the signature
    if header.signature == LUA_SIGNATURE and 0x52 == header.version:
        global size_Instruction
        global size_lua_Number
        size_Instruction = header.size_Instruction
        size_lua_Number = header.size_lua_Number
        DEBUG_PRINT('signature:%x' %  header.signature)
        DEBUG_PRINT('version:%x' %  header.version)
        DEBUG_PRINT('format:%x' %  header.format)
        DEBUG_PRINT('endian:%x' %  header.endian)
        DEBUG_PRINT('size_int:%x' %  header.size_int)
        DEBUG_PRINT('size_Instruction:%x' %  header.size_Instruction)
        DEBUG_PRINT('size_lua_Number:%x' %  header.size_lua_Number)
        DEBUG_PRINT('lua_num_valid:%x' %  header.lua_num_valid)
        if header.size_Instruction != 4:
            return 0
        #if header.size_lua_Number != 8:
        #    return 0

        return FormatName

    # unrecognized format
    return 0

def add_structs():
    begin_type_updating(UTP_STRUCT)

    AddStrucEx(-1, "GlobalHeader", 0)
    AddStrucEx(-1, "ProtoHeader", 0)

    id = GetStrucIdByName("GlobalHeader")
    AddStrucMember(id, "signature", 0, 0x000400, -1, 4)
    AddStrucMember(id, "version", 0X4, 0x000400, -1, 1)
    AddStrucMember(id, "format", 0X5, 0x000400, -1, 1)
    AddStrucMember(id, "endian", 0X6, 0x000400, -1, 1)
    AddStrucMember(id, "size_int", 0X7, 0x000400, -1, 1)
    AddStrucMember(id, "size_size_t", 0X8, 0x000400, -1, 1)
    AddStrucMember(id, "size_Instruction", 0X9, 0x000400, -1, 1)
    AddStrucMember(id, "size_lua_Number", 0XA, 0x000400, -1, 1)
    AddStrucMember(id, "lua_num_valid", 0XB, 0x000400, -1, 1)
    AddStrucMember(id, "luac_tail", 0XC, 0x000400, -1, 6)

    SetType(get_member_id(id, 0x0), "char[4]")
    SetType(get_member_id(id, 0x4), "unsigned __int8")
    SetType(get_member_id(id, 0x5), "unsigned __int8")
    SetType(get_member_id(id, 0x6), "unsigned __int8")
    SetType(get_member_id(id, 0x7), "unsigned __int8")
    SetType(get_member_id(id, 0x8), "unsigned __int8")
    SetType(get_member_id(id, 0x9), "unsigned __int8")
    SetType(get_member_id(id, 0xA), "unsigned __int8")
    SetType(get_member_id(id, 0xB), "unsigned __int8")
    SetType(get_member_id(id, 0xC), "unsigned __int8[6]")

    id = GetStrucIdByName("ProtoHeader")
    AddStrucMember(id, "linedefined", 0, 0x20000400, -1, 4)
    AddStrucMember(id, "lastlinedefined", 0X4, 0x20000400, -1, 4)
    AddStrucMember(id, "numparams", 0X8, 0x000400, -1, 1)
    AddStrucMember(id, "is_vararg", 0X9, 0x000400, -1, 1)
    AddStrucMember(id, "maxstacksize", 0XA, 0x000400, -1, 1)

    SetType(get_member_id(id, 0x0), "unsigned int")
    SetType(get_member_id(id, 0x4), "unsigned int")
    SetType(get_member_id(id, 0x8), "unsigned __int8")
    SetType(get_member_id(id, 0x9), "unsigned __int8")
    SetType(get_member_id(id, 0xA), "unsigned __int8")

    end_type_updating(UTP_STRUCT)

    set_inf_attr(INF_LOW_OFF, 0x20)
    set_inf_attr(INF_HIGH_OFF, 0x22A)


# -----------------------------------------------------------------------
def load_file(li, neflags, format):

    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    if format.startswith(FormatName):
        global_header_size = ctypes.sizeof(global_header)
        li.seek(global_header_size)
        header = read_struct(li, proto_header)
        DEBUG_PRINT('linedefined:%x' %  header.linedefined)
        DEBUG_PRINT('lastlinedefined:%x' %  header.lastlinedefined)
        DEBUG_PRINT('numparams:%x' %  header.numparams)
        DEBUG_PRINT('is_vararg:%x' %  header.is_vararg)
        DEBUG_PRINT('maxstacksize:%x' %  header.maxstacksize)

        global_header_decl = """
            typedef struct {
                char signature[4];
                unsigned char version;
                unsigned char format;
                unsigned char endian;
                unsigned char size_int;
                unsigned char size_size_t;
                unsigned char size_Instruction;
                unsigned char size_lua_Number;
                unsigned char lua_num_valid;
                unsigned char luac_tail[0x6];
            } GlobalHeader;
        """
        """
        idaapi.set_compiler_string("GNU C++", True)
        t = new_til("luac.til", "luac header types")
        ret = parse_decls(t, global_header_decl, None, PT_PAK1)
        print("parse_decls ret:%d" % ret)
        global_header_struct = import_type(t, -1, "GlobalHeader")
        print("import_type ret:%d" % global_header_struct)
        ret = doStruct(0, global_header_size, global_header_struct)
        print("doStruct ret:%d" % ret)
        free_til(t)
        """

        idaapi.set_processor_type("Luac", SETPROC_ALL|SETPROC_FATAL)

        proto = Proto(li, global_header_size, "0") #function level 0

        add_segm(0, 0, global_header_size, "header", 'HEADER')

        add_structs()
        MakeStruct(0, "GlobalHeader")

        global funcs
        global consts
        global strs
        for func in funcs:
            #add funcheader_xx segment.
            add_segm(0, func[3], func[3] + ctypes.sizeof(proto_header), func[4], 'CONST')
            MakeStruct(func[3], "ProtoHeader")

            # add func_xx_codesize segment.
            add_segm(0, func[1] - 4, func[1], func[0] + "_codesize", 'CONST')
            MakeDword(func[1]-4)
            set_name(func[1]-4, func[0] + "_codesize")

            # add func_xx segment.
            add_segm(0, func[1], func[2], func[0], 'CODE')
            #add_func(func[1], func[2])

        for const in consts:
            # add const_xx_size segment.
            add_segm(0, const[1]-4, const[1], const[0] + "_size", 'CONST')
            MakeDword(const[1]-4)
            set_name(const[1]-4, const[0] + "_size")

            # add const_xx segment.
            add_segm(0, const[1], const[2], const[0], 'CONST')

        for str in strs:
            # add const strings.
            idc.create_strlit(str[1], str[2])


        li.file2base(0, 0, li.size(), 0)    #map all data
        mainfunc_addr = proto.code_off + 4
        print("main func addr:%x" % mainfunc_addr)
        add_entry(mainfunc_addr, mainfunc_addr, 'func_0', 1)

        DEBUG_PRINT("Load Lua bytecode OK.")
        return 1