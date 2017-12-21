# Lua程序逆向之Luac字节码与反汇编

在了解完了Luac字节码文件的整体结构后，让我们把目光聚焦，放到更具体的指令格式上。Luac字节码指令是整个Luac最精华、也是最具有学习意义的一部分，了解它的格式与OpCode相关的知识后，对于逆向分析Luac，会有事半功倍的效果，同时，也为自己开发一款虚拟机执行模板与引擎打下良好的理论基础。

## 指令格式分析
Luac指令在Lua中使用`Instruction`来表示，是一个32位大小的数值。在Luac.bt中，我们将其定义了为`Inst`结构体，回顾一下它的定义与读取函数：
```
typedef struct(int pc) {
    local int pc_ = pc;
    local uchar inst_sz = get_inst_sz();
    if (inst_sz == 4) {
        uint32 inst;
    } else {
        Warning("Error size_Instruction.");
    }
} Inst <optimize=false>;
```

定义的每一条指令为uint32，这与ARM处理器等长的32位指令一样，但不同的是，Lua 5.2使用的指令只有40条，也就是说，要为其Luac编写反汇编引擎，比起ARM指令集，在工作量上要少出很多。

Luac指令完整由：`OpCode`、`OpMode`操作模式，以及不同模式下使用的不同的操作数组成。

官方5.2版本的Lua使用的指令有四种格式，使用`OpMode`表示，它的定义如下：
```
enum OpMode {iABC, iABx, iAsBx, iAx};
```

其中，`i`表示6位的`OpCode`；`A`表示一个8位的数据；`B`表示一个9位的数据，`C`表示一个9位的无符号数据；后面跟的`x`表示数据组合，如`Bx`表示`B`与`C`组合成18位的无符号数据，`Ax`表示`A`与`B`和`C`共同组成26位的无符号数据。`sBx`前的`s`表示是有符号数，即`sBx`是一个18位的有符号数。

ABC这些字节大小与起始位置的定义如下：
```
#define SIZE_C		9
#define SIZE_B		9
#define SIZE_Bx		(SIZE_C + SIZE_B)
#define SIZE_A		8
#define SIZE_Ax		(SIZE_C + SIZE_B + SIZE_A)

#define SIZE_OP		6

#define POS_OP		0
#define POS_A		(POS_OP + SIZE_OP)
#define POS_C		(POS_A + SIZE_A)
#define POS_B		(POS_C + SIZE_C)
#define POS_Bx		POS_C
#define POS_Ax		POS_A
```

从定义中可以看来，从位0开始，ABC的排列为`A`->`C`->`B`。

以小端序为例，完整的指令格式定义如下表所示：

|OpMode|B|C|A|OpCode|
|--|--|--|--|--|
|iABC |B(23~31)|C(14~22)|A(6~13)|opcode(0~5)|
|iABx |Bx     |(14~31)  |A(6~13)|opcode(0~5)|
|iAsBx|sBx    |(14~31)  |A(6~13)|opcode(0~5)|
|iAx  |Ax    |          |A(6~31)|opcode(0~5)|

先来看最低6位的`OpCode`，在Lua中，它使用枚举表示，5.2版本的Lua支持40条指令，它们的定义如下所示：
```
typedef enum {
/*----------------------------------------------------------------------
name		args	description
------------------------------------------------------------------------*/
OP_MOVE,/*	A B	R(A) := R(B)					*/
OP_LOADK,/*	A Bx	R(A) := Kst(Bx)					*/
OP_LOADBOOL,/*	A B C	R(A) := (Bool)B; if (C) pc++			*/
OP_LOADNIL,/*	A B	R(A) := ... := R(B) := nil			*/
OP_GETUPVAL,/*	A B	R(A) := UpValue[B]				*/

OP_GETGLOBAL,/*	A Bx	R(A) := Gbl[Kst(Bx)]				*/
OP_GETTABLE,/*	A B C	R(A) := R(B)[RK(C)]				*/

OP_SETGLOBAL,/*	A Bx	Gbl[Kst(Bx)] := R(A)				*/
OP_SETUPVAL,/*	A B	UpValue[B] := R(A)				*/
OP_SETTABLE,/*	A B C	R(A)[RK(B)] := RK(C)				*/
......
OP_CLOSE,/*	A 	close all variables in the stack up to (>=) R(A)*/
OP_CLOSURE,/*	A Bx	R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))	*/

OP_VARARG/*	A B	R(A), R(A+1), ..., R(A+B-1) = vararg		*/
} OpCode;
```

`OpCode`定义的注释中，详细说明了每一条指令的格式、使用的参数，以及它的含义。以第一条`OP_MOVE`指令为例，它接受两个参数`R(A)`与`R(B)`，的作用是完成一个赋值操作“`R(A) := R(B)`”。


从指令的格式可以看出，尽管`OpCode`定义的注释中描述了每条指令使用的哪种`OpMode`，但32位的指令格式中，并没有指出到底每个`OpCode`对应哪一种`OpMode`，Lua的解决方法是单独做了一张`OpMode`的表格`luaP_opmodes`，它的定义如下：
```
LUAI_DDEF const lu_byte luaP_opmodes[NUM_OPCODES] = {
/*       T  A    B       C     mode		   opcode	*/
  opmode(0, 1, OpArgR, OpArgN, iABC)		/* OP_MOVE */
 ,opmode(0, 1, OpArgK, OpArgN, iABx)		/* OP_LOADK */
 ,opmode(0, 1, OpArgN, OpArgN, iABx)		/* OP_LOADKX */
 ,opmode(0, 1, OpArgU, OpArgU, iABC)		/* OP_LOADBOOL */
 ,opmode(0, 1, OpArgU, OpArgN, iABC)		/* OP_LOADNIL */
 ,opmode(0, 1, OpArgU, OpArgN, iABC)		/* OP_GETUPVAL */
 ,opmode(0, 1, OpArgU, OpArgK, iABC)		/* OP_GETTABUP */
 ,opmode(0, 1, OpArgR, OpArgK, iABC)		/* OP_GETTABLE */
 ,opmode(0, 0, OpArgK, OpArgK, iABC)		/* OP_SETTABUP */
 ,opmode(0, 0, OpArgU, OpArgN, iABC)		/* OP_SETUPVAL */
 ,opmode(0, 0, OpArgK, OpArgK, iABC)		/* OP_SETTABLE */
 ,opmode(0, 1, OpArgU, OpArgU, iABC)		/* OP_NEWTABLE */
 ,opmode(0, 1, OpArgR, OpArgK, iABC)		/* OP_SELF */
 ,opmode(0, 1, OpArgK, OpArgK, iABC)		/* OP_ADD */
 ,opmode(0, 1, OpArgK, OpArgK, iABC)		/* OP_SUB */
 ......
 ,opmode(0, 1, OpArgU, OpArgN, iABx)		/* OP_CLOSURE */
 ,opmode(0, 1, OpArgU, OpArgN, iABC)		/* OP_VARARG */
 ,opmode(0, 0, OpArgU, OpArgU, iAx)		/* OP_EXTRAARG */
};
```

构成完整的`OpMode`列表使用了`opmode`宏，它的定义如下：
```
#define opmode(t,a,b,c,m) (((t)<<7) | ((a)<<6) | ((b)<<4) | ((c)<<2) | (m))
```

它将`OpMode`相关的数据采用一字节表示，并将其组成划分为以下几个部分：

1. `m`位，占最低2位，即前面`OpMode`中定义的四种模式，通过它，可以确定`OpCode`的参数部分。
2. `c`位，占2~3位，使用`OpArgMask`表示，说明`C`参数的类型。定义如下：
    ```
    enum OpArgMask {
        OpArgN,  /* 参数未被使用 */
        OpArgU,  /* 已使用参数 */
        OpArgR,  /* 参数是寄存器或跳转偏移 */
        OpArgK   /* 参数是常量或寄存器常量 */
    };
    ```

3. `b`位，占4~5位。使用`OpArgMask`表示，说明`B`参数的类型。
4. `a`位，占位6。表示是否是寄存器操作。
5. `t`位，占位7。表示是否是测试操作。跳转和测试指令该位为1。

将`luaP_opmodes`的值使用如下代码打印出来：
```
printf("opcode ver 5.2:\n");
for (int i=0; i<sizeof(luaP_opmodes); i++) {
    printf("0x%x, ", luaP_opmodes[i]);
}
printf("\n");
```

输出如下：
```
opcode ver 5.2:
0x60, 0x71, 0x41, 0x54, 0x50, 0x50, 0x5c, 0x6c, 0x3c, 0x10, 0x3c, 0x54, 0x6c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x60, 0x60, 0x60, 0x68, 0x22, 0xbc, 0xbc, 0xbc, 0x84, 0xe4, 0x54, 0x54, 0x10, 0x62, 0x62, 0x4, 0x62, 0x14, 0x51, 0x50, 0x17, 
```

可以看到，有很多指令的`OpMode`是相同的，比如有多条指令对应的值都是0x7c，如果`OpMode`的顺序经过修改，要想通过`OpMode`直接还原所有的指令，是无法做到的，需要配合其他方式来还原，比如Lua虚拟机对指令的处理部分。

## 反汇编引擎实现

编写反汇编引擎需要做到以下几点：

1. 正确的识别指令的`OpCode`。识别该条指令对应的`OpCode`，了解当前指令的作用。
2. 处理指令的参数列表。解析不同指令使用到的参数信息，与`OpCode`在一起可以完成指令反汇编与指令的语义转换。
3. 指令解析。反汇编引擎应该能够支持所有的指令。
3. 指令语义转换。完成反汇编后，加入语义转换，更加方便了解指令的意图。
4. 处理指令依赖关系。处理语义转换时，需要处理好指令之前的关系信息。

下面，我们一条条看如何实现。

### `OpCode`获取

首先是通过指令获取对应的`OpCode`，即传入一个32位的指令值，返回一个`OpCode`的名称。Lua中有一个`GET_OPCODE`宏可以通过指令返回对应的`OpCode`，定义如下：
```
#define GET_OPCODE(i)	(cast(OpCode, ((i)>>POS_OP) & MASK1(SIZE_OP,0)))
```

这个宏在`010 Editor`模板语法中并不支持，因此，实现上，需要编写展开后的代码，并将其定义为函数。功能上就是取32位指令的最低6位，代码如下所示：
```
uchar GET_OPCODE(uint32 inst) {
    return ((inst)>>POS_OP) & ((~((~(Instruction)0)<<(SIZE_OP)))<<(0));
}
```

### 参数获取

取指令的参数，包括取指令的`A`、`B`、`C`、`Bx`、`Ax`、`sBx`等信息。前面已经介绍了它们在指令中的位偏移，因此，获取这些参数信息与获取`OpCode`一样，Lua中提供了`GETARG_A`、`GETARG_B`、`GETARG_C`、`GETARG_Bx`、`GETARG_Ax`、`GETARG_sBx`等宏来完成这些功能，定义如下：
```
#define GETARG_A(i)	getarg(i, POS_A, SIZE_A)
#define GETARG_B(i)	getarg(i, POS_B, SIZE_B)
#define GETARG_C(i)	getarg(i, POS_C, SIZE_C)
#define GETARG_Bx(i)	getarg(i, POS_Bx, SIZE_Bx)
#define GETARG_Ax(i)	getarg(i, POS_Ax, SIZE_Ax)
#define GETARG_sBx(i)	(GETARG_Bx(i)-MAXARG_sBx)
```

同样的，`010 Editor`模板语法不支持直接定义这些宏，需要编写展开后的代码，实现如下：
```
int GETARG_A(uint32 inst) {
    return ((inst)>>POS_A) & ((~((~(Instruction)0)<<(SIZE_A)))<<(0));
}

int GETARG_B(uint32 inst) {
    return ((inst)>>POS_B) & ((~((~(Instruction)0)<<(SIZE_B)))<<(0));
}

int GETARG_C(uint32 inst) {
    return ((inst)>>POS_C) & ((~((~(Instruction)0)<<(SIZE_C)))<<(0));
}

int GETARG_Bx(uint32 inst) {
    return ((inst)>>POS_Bx) & ((~((~(Instruction)0)<<(SIZE_Bx)))<<(0));
}

int GETARG_Ax(uint32 inst) {
    return ((inst)>>POS_Ax) & ((~((~(Instruction)0)<<(SIZE_Ax)))<<(0));
}

int GETARG_sBx(uint32 inst) {
    return GETARG_Bx(inst)-MAXARG_sBx;
}
```

### 指令解析

在指令解析的编写工作上，参考了`luadec`的反汇编引擎。它的实现主要位于`luadec_disassemble()`函数。这里要做的工作就是将它的所有代码与语法都进行一次`010 Editor`模板语法化。代码片断如下：
```
// luadec_disassemble() from luadec disassemble.c
string InstructionRead(Inst &inst) {
    local int i = inst.inst;
    OpCode o = (OpCode)GET_OPCODE(i);
    /*
    Printf("inst: 0x%x\n", o);
    */
    local int a = GETARG_A(i);
    local int b = GETARG_B(i);
    local int c = GETARG_C(i);
    local int bc = GETARG_Bx(i);
    local int sbc = GETARG_sBx(i);
    local int dest;
    local string line;
    local string lend;
    local string tmpconstant1;
    local string tmpconstant2;
    local string tmp;
    local string tmp2;
    local uchar lua_version_num = get_lua_version();
    local int pc = inst.pc_;

    //Printf("Inst: %s\n", EnumToString(o));
    switch (o) {
        case OP_MOVE:
			/*	A B	R(A) := R(B)					*/
			SPrintf(line,"R%d R%d",a,b);
			SPrintf(lend,"R%d := R%d",a,b);
			break;
        case OP_LOADK:  //FIXME OP_LOADK DecompileConstant
			/*	A Bx	R(A) := Kst(Bx)					*/
			SPrintf(line,"R%d K%d",a,bc);
            //Printf("OP_LOADK bc:%d\n", bc);
			tmpconstant1 = DecompileConstant(parentof(parentof(inst)),bc);
			SPrintf(lend,"R%d := %s",a,tmpconstant1);
			break;
        ......
        case OP_CLOSURE:
        {
			/*	A Bx	R(A) := closure(KPROTO[Bx])		*/
			SPrintf(line,"R%d %d",a,bc);
			SPrintf(lend, "R%d := closure(Function #%d)", a, bc);
			break;
        }
		default:
			break;

    }

    local string ss;
    SPrintf(ss, "[%d] %-9s %-13s; %s\n", pc, get_opcode_str(o),line,lend);

    return ss;
}
```

上面的代码中，通过`GET_OPCODE`获取`OpCode`后，分别对它进行判断与处理，参数信息在函数的最开始获取，方便指令中使用。`pc`表示当前执行的指令所在位置，方便代码中做语义转换与依赖处理。代码中这一行需要注意：
```
DecompileConstant(parentof(parentof(inst))
```

因为处理指令时，需要读取指令所在`Proto`的常量信息，但`010 Editor`尴尬的模板语法不支持传递指针，也不支持引用类型作为函数的返回值，这导致无法直接读到到`Proto`的`Constants`信息。幸好新版本的`010 Editor`的模板语法加入了`self`与`parentof`关键字，用于获取当前结构体与父结构体的字段信息，因此，这里需要对`Proto`结构体进行修改，让`Code`结构体成为它的内联的子结构体，如下所示：
```
typedef struct(string level) {
    local string level_ = level;
    //Printf("level:%s\n", level_);

    //header
    ProtoHeader header;

    //code
    //Code code;
    struct Code {
        uint32 sizecode <format=hex>;
        local uchar inst_sz = get_inst_sz();
        local int pc = 1;
        if (inst_sz == 4) {
            local uint32 sz = sizecode;
            while (sz-- > 0) {
                Inst inst(pc);
                pc++;
            }
        } else {
            Warning("Error size_Instruction.");
        }
        
        typedef struct(int pc) {
            local int pc_ = pc;
            local uchar inst_sz = get_inst_sz();
            if (inst_sz == 4) {
                uint32 inst;
            } else {
                Warning("Error size_Instruction.");
            }
        } Inst <read=InstructionRead, optimize=false>;
    
    } code <optimize=false>;

    ......

    // upvalue names
    UpValueNames names;
} Proto <read=ProtoRead>;
```

然后在代码中，通过`parentof(parentof(inst)`就能够返回一个`Proto`的引用类型，然后就可以愉快的读`Proto`中所有的字段数据了。

### 指令语义转换

所谓语义转换，就是将直接的指令格式表示成可以读懂的指令反汇编语句。如指令0x0000C1，反汇编后，它的指令表示为“LOADK R3 K0”，`LOADK`为`OpCode`的助记符，这里取助记符时，直接通过`010 Editor`模板函数`EnumToString()`，传入`OpCode`名，然后去掉前面的`OP_`就可以获得。使用`get_opcode_str()`实现该功能，代码如下：
```
string get_opcode_str(OpCode o) {
    string str = EnumToString(o);
    str = SubStr(str, 3);
    
    return str;
}
```

`R3`表示寄存器，`K0`表示常量1，即当前函数的`Constants`中索引为0的`Constant`。这一条指令经过语义转换后就变成了“`R3 := xxx`”，这个xxx是常量的值，需要通过`DecompileConstant()`获取它具体的值。

在进行语义转换时，将处理后的指令信息保存到`line`字符串中，将语义字符串转换到`lend`字符串中，处理完后输出时加在一起，中间放一个分号。如下所示是指令处理后的输出效果：
```
struct Inst inst[1]	[2] LOADK     R3 K0        ; R3 := 1
```

### 指令依赖处理

指令依赖是什么意思呢？即一条指令想要完整的了解它的语义，需要依赖它前面或后面的指令，就解析该指令时，需要用到指令前面或后面的数据。

拿`OP_LE`指令来说，它的注释部分如下：
```
/*	A B C	if ((RK(B) <= RK(C)) ~= A) then pc++  		*/
```

娄条件满足时，跳转去执行，否则`pc`向下，在编写反汇编引擎时，使用的代码片断如下：
```
case OP_LE:
    {
        /*	A B C	if ((RK(B) <= RK(C)) ~= A) then pc++  		*/
        dest = GETARG_sBx(parentof(inst).inst[pc+1].inst) + pc + 2;
        SPrintf(line,"%d %c%d %c%d",a,CC(b),CV(b),CC(c),CV(c));
        tmpconstant1 = RK(parentof(parentof(inst)), b);
        tmpconstant2 = RK(parentof(parentof(inst)), c);
        SPrintf(lend,"if %s %s %s then goto [%d] else goto [%d]",tmpconstant1,(a?invopstr(o):opstr(o)),tmpconstant2,pc+2,dest);
        break;
    }
```

`dest`是要跳转的目标地址，`GETARG_sBx()`返回的是一个有符号的跳转偏移，因为指令是可以向前与向后进行跳转的，`RK`宏判断参数是寄存器还是常量，然后返回它的值，这里的实现如下：
```
string RegOrConst(Proto &f, int r) {
	if (ISK(r)) {
		return DecompileConstant(f, INDEXK(r));
	} else {
		string tmp;
		SPrintf(tmp, "R%d", r);
		return tmp;
	}
}

//#define RK(r) (RegOrConst(f, r))
string RK(Proto &f, int r) {
    return (RegOrConst(f, r));
}
```

最终，`OP_LE`指令处理后输出如下：
```
struct Inst inst[35] [36] LE 0 R5 R6  ; if R5 <= R6 then goto [38] else goto [40]
```

其他所有的指令的处理可以参看`luadec_disassemble()`的代码，这里不再展开。

最后，所有的代码编写完成后，效果如图所示：
![luac_dis](luac_dis.jpg)

luac.bt的完整实现可以在这里找到：[https://github.com/feicong/lua_re](https://github.com/feicong/lua_re)。
