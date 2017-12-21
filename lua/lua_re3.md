# Lua程序逆向之Luajit文件格式

`Luajit`将原生Lua进行了扩展，使它支持JIT方式编译运行，比起原生Lua程序，它有着如下特点：

1. JIT即时编译器让执行效率更高。
2. 它同时兼容传统的AOT编译。
3. 全新设计的Luajit字节码文件格式，更加高效与更强的调试支持。（这一点在后面会着重介绍）
4. 全新的Lua指令集。引入了中间表示IR，以及编译引擎支持不同平台的处理器指令即时编译，完全的符合现代化编译器设计，是编译理论学习的绝佳好资料。

`Luajit`在游戏软件中应用广泛，学习Lua程序逆向，就避免不了与`Luajit`打交道，下面，我们以最基本的`Luajit`文件格式开始，逐步深入的学习Lua程序的逆向基本知识。

## 安装Luajit

`Luajit`是开源的，它的项目地址是：`https://github.com/LuaDist/luajit`。任何人都可以从网络上下载编译并安装它。

目前，最新正式版本的Luajit为2.0.5版，Beta版本为2.1.0-beta3版，官方还在缓慢的更新中。正式版本的Luajit只只兼容Lua的5.1版本，5.2版本的Lua正在添加支持中。这里重点讨论Luajit2.0.5正式版本。

笔者研究Luajit使用的操作系统是macOS，通过`Homebrew`软件包管理工具，可以执行如下的命令进行快速的安装：
```
$ brew install luajit
```

安装完成后，它的目录结构如下所示：
```
$ tree /usr/local/opt/luajit
/usr/local/opt/luajit
├── COPYRIGHT
├── INSTALL_RECEIPT.json
├── README
├── bin
│   ├── luajit -> luajit-2.0.5
│   └── luajit-2.0.5
├── include
│   └── luajit-2.0
│       ├── lauxlib.h
│       ├── lua.h
│       ├── lua.hpp
│       ├── luaconf.h
│       ├── luajit.h
│       └── lualib.h
├── lib
│   ├── libluajit-5.1.2.0.5.dylib
│   ├── libluajit-5.1.2.dylib -> libluajit-5.1.2.0.5.dylib
│   ├── libluajit-5.1.a
│   ├── libluajit-5.1.dylib -> libluajit-5.1.2.0.5.dylib
│   ├── libluajit.a -> libluajit-5.1.a
│   ├── libluajit.dylib -> libluajit-5.1.dylib
│   └── pkgconfig
│       └── luajit.pc
└── share
    ├── luajit-2.0.5
    │   └── jit
    │       ├── bc.lua
    │       ├── bcsave.lua
    │       ├── dis_arm.lua
    │       ├── dis_mips.lua
    │       ├── dis_mipsel.lua
    │       ├── dis_ppc.lua
    │       ├── dis_x64.lua
    │       ├── dis_x86.lua
    │       ├── dump.lua
    │       ├── v.lua
    │       └── vmdef.lua
    └── man
        └── man1
            └── luajit.1

10 directories, 30 files
```

安装目录下的`luajit`程序是指向`luajit-2.0.5`程序的软链接，它是`Luajit`的主程序，与Lua官方的`lua`程序一样，它是Luajit程序的解释器，不同的是，它没有与`luac`编译器对应的`Luajitc`，`Luajit`同时负责了Lua文件编译为Luajit字节码文件的编译工作。include目录下存放的是`Luajit`的头文件，可以编译C/C++程序与Luajit进行交互。lib目录为链接C/C++程序用到的库文件。share/luajit-2.0.5/jit目录下的lua文件是`Luajit`提供的扩展模块，可以用来反汇编与Dump输出`Luajit`字节码文件的指令信息，在学习`Luajit`字节码指令格式时，这些工具非常有用。man目录下提供了`Luajit`的man帮助信息，即终端中执行`man luajit`显示的帮助内容。

## 编译生成`Luajit`文件

编写hello.lua文件，内容如下：
```

function add(x, y)
	return x+y;
end
function showinfo()
	print("welcome to lua world ")
end

function showstr(str)
	print("The string you input is " .. str)
end

local i = 6;
return 1;
```

这段代码包含了三个函数、一个局部变量，一条返回语句。使用`luajit`的-b参数即可生成hello.luajit文件，命令如下所示：
```
$ luajit -b ./hello.lua ./hello.luajit
```

上面命令生成的hello.luajit文件不包含调试信息，`luajit`默认编译参数中有一个-s参数，作用是去除luajit文件中的调试信息。调度信息中，包含了原Lua源文件中的行号与变量本等信息，如果想要保留这些信息，可以加上-g参数。执行如下命令，可以生成带调试信息的hello_debug.luajit文件：
```
$ luajit -bg ./hello.lua ./hello_debug.luajit
```

## `Luajit`文件格式

Luajit官方并没有直接给出`Luajit`字节码文件的格式文档。但可以通过阅读Luajit源码中加载与生成`Luajit`字节码文件的函数，来单步跟踪分析出它的文件格式，这两个方法分别是`lj_bcread()`与`lj_bcwrite()`。

从这两个函数调用的`bcread_header()`、`bcread_proto()`、`bcwrite_header()`、`bcwrite_proto()`等子函数名可以初步了解到，`Luajit`字节码文件与`Luac`一样，将文件格式分为头部分信息Header与函数信息Proto两部分。具体的内容细节则需要使用`gdb`或`lldb`等工具调试分析得出。

`Luajit`字节码文件的Header部分为了与`Luac`命名上保持一致，这里将其描述为`GlobalHeader`，它的定义如下：
```
typedef struct {
    char signature[3];
    uchar version;
    GlobalHeaderFlags flags;
    if (!is_stripped) {
        uleb128 length;
        char chunkname[uleb128_value(length)];
    }
} GlobalHeader;
```

第一个`signature`字段是`Luajit`文件的Magic Number，它占用三个字节，定义分别如下：
```
/* Bytecode dump header. */
#define BCDUMP_HEAD1		0x1b
#define BCDUMP_HEAD2		0x4c
#define BCDUMP_HEAD3		0x4a
```

即`Luajit`字节码文件的头三个字节必须为“\x1bLJ”。`version`字段为`Luajit`的版本号，目前它的值为1。第三个字段`flags`描述了该文件的一组标志位集合，它们的取值可以为这些值的组合：
```
typedef enum {
    FLAG_IS_BIG_ENDIAN = 0b00000001,
    FLAG_IS_STRIPPED = 0b00000010,
    FLAG_HAS_FFI = 0b00000100
} FLAG;
```

`FLAG_IS_BIG_ENDIAN`标识了该`Luajit`文件是采用大端字节序还是小端字节序、`FLAG_IS_STRIPPED`标识该`Luajit`文件是否去除了调试信息、`FLAG_HAS_FFI`标识是否包含FFI信息。`flags`字段使用的数据类型为uleb128，占用的字节码与数据的实际大小相关。

uleb128是一种常见的压缩形式的数据存储方式，如果了解Android DEX文件格式的话，对它应该不会陌生。它最长采用5个字节表示数据的大小，最少采用1个字节表示数据的大小，具体采用的位数，可以通过判断每字节的最高位是否为1，为1则使用下一字节的数据，如果使用`010 Editor`模板语法表示，则它的数据类型定义如下：
```
typedef struct {
    ubyte val <comment="uleb128 element">;
    if(val > 0x7f) {
        ubyte val <comment="uleb128 element">;
        if (val > 0x7f) {
            ubyte val <comment="uleb128 element">;
            if(val > 0x7f) {
                ubyte val <comment="uleb128 element">;
                if(val > 0x7f) {
                    ubyte val <comment="uleb128 element">;
                }
            }
        }
    }
} uleb128;
```

读取uleb128表示的数据大小的方法如下：
```
uint uleb128_value(uleb128 &u) {
    local uint result;
    local ubyte cur;

    result = u.val[0];
    if(result > 0x7f) {
        cur = u.val[1];
        result = (result & 0x7f) | (uint)((cur & 0x7f) << 7);
        if(cur > 0x7f) {
            cur = u.val[2];
            result |= (uint)(cur & 0x7f) << 14;
            if(cur > 0x7f) {
                cur = u.val[3];
                result |= (uint)(cur & 0x7f) << 21;
                if(cur > 0x7f) {
                    cur = u.val[4];
                    result |= (uint)cur << 28;
                }
            }
        }
    }

    return result;
}
```

接下来`GlobalHeader`中，如果判断`Luajit`文件中包含调试信息，即`flags`字段中的`FLAG_IS_STRIPPED`没有被置位，则会多出`length`与`chunkname`两个字段。`length`是uleb128表示的字段串长度，`chunkname`则是存放了`length`长度的字段串内容，它表示当前`Luajit`文件的源文件名。

在`GlobalHeader`之后，是`Proto`函数体内容。它的定义如下：
```
typedef struct() {
    ProtoHeader header;
    if (uleb128_value(header.size) > 0) {
        if (uleb128_value(header.instructions_count) > 0)
            Instruction inst[uleb128_value(header.instructions_count)];
        Constants constants;
        if (header.debuginfo_size_ > 0)
            DebugInfo debuginfo;
    }
} Proto;
```

这里`Proto`的定义仍然采用与上面`GlobalHeader`一样的`010 Editor`模板语法方式，这种类似C语言的描述，更容易从定义上看出`Proto`结构体的字段信息。

`ProtoHeader`类型的`header`字段描述了`Proto`的头部信息，定义如下：
```
typedef struct {
    uleb128 size;
    if (uleb128_value(size) > 0) {
        ProtoFlags flags;
        uchar arguments_count;
        uchar framesize;
        uchar upvalues_count;
        uleb128 complex_constants_count;
        uleb128 numeric_constants_count;
        uleb128 instructions_count;
        if (!is_stripped) {
            uleb128 debuginfo_size;
            uleb128 first_line_number;
            uleb128 lines_count;
        }
    }
} ProtoHeader;
```

`size`字段是标识了从当前字段开始，整个`Proto`结构体的大小，当该字段的取值大于0时，表示当前`Proto`不为空，即`Proto`的`header`字段后，接下来会包含`Instruction`指令与`Constants`常量等信息，并且`ProtoHeader`部分也会多出其他几个字段。首先是`flags`字段，`ProtoFlags`是一个uchar类型，这里单独使用一个结构体表示，是为了之后编写`010 Editor`模板时，更方便的为其编写read方法。`ProtoFlags`取值如下：
```
typedef enum {
    FLAG_HAS_CHILD = 0b00000001,
    FLAG_IS_VARIADIC = 0b00000010,
    FLAG_HAS_FFI = 0b00000100,
    FLAG_JIT_DISABLED = 0b00001000,
    FLAG_HAS_ILOOP = 0b00010000
} PROTO_FLAG;
```

`FLAG_HAS_CHILD`标识当前`Proto`是一个“子函数”，即闭包(`Closure`)。这个标志位非常重要，为了更好的理解它的用处，先看下如下代码：
```
function Create(n) 
	local function foo1()
		print(n)
        local function foo2()
            n = n + 10 
		    print(n)
            local function foo3()
                n = n + 100
                print(n)
            end
        end
	end
	return foo1,foo2,foo3
end
f1,f2,f3 = Create(1000)
f1()
```

这段Lua代码中，最外层的`Create()`向内，每个function都包含一个`Closure`。现在回忆一下`Luac`文件格式中，它们是如何存储的？

**在`Luac`文件中，每个`Proto`都有一个`Protos`字段，它用来描述`Proto`与`Closure`之间的层次信息，`Proto`采用从外向内的递归方式进行存储。而`Luajit`则采用线性的从内向外的同级结构进行存储，`Proto`与`Closure`之前的层级关系使用`flags`字段的`FLAG_HAS_CHILD`标志位进行标识，当`flags`字段的`FLAG_HAS_CHILD`标志位被置位，则表示当前层的`Proto`是上一层`Proto`的`Closure`**

上面的代码片断在`Luajit`文件结构中的存局如下所示：
```
struct Luajit lj;
    struct GlobalHeader header;
    struct Proto proto[0];  //foo3()
    struct Proto proto[1];  //foo2()
    struct Proto proto[2];  //foo1()
    struct Proto proto[3];  //Create()
    struct Proto proto[4];  //Full file
    struct Proto proto[5];  //empty
```

从存局中可以看出，最内层的`foo3()`位于`Proto`的最外层，它与`Luac`的布局恰恰是相反的，而`proto[4]`表示了整个Lua文件，它是`Proto`的最上层。最后的`proto[5]`，它在读取其`ProtoHeader`的`size`字段时，由于其值为0，而中止了整个文件的解析。即它的内容为空。

`FLAG_IS_VARIADIC`标识了当前`Proto`是否返回多个值，上面的代码中，只有`Create()`的`flags`字段会对该标志置位。`FLAG_HAS_FFI`标识当前`Proto`是否有通过FFI扩展调用系统的功能函数。`FLAG_JIT_DISABLED`标识当前`Proto`是否禁用JIT，对于包含了具体代码的`Proto`，它的值通常没有没有被置位，表示有JIT代码。`FLAG_HAS_ILOOP`标识了当前`Proto`是否包含了`ILOOP`与`JLOOP`等指令。

在`flags`字段后面，是`arguments_count`字段，表示当前`Proto`有几个参数。接着是`framesize`字段，标识了`Proto`使用的栈大小。接下来四个字段`upvalues_count`、`complex_constants_count`、`numeric_constants_count`、`instructions_count`，它们分别表示UpValue个数、复合常数、数值常数、指令条数等信息。

如果当前`Proto`包含调试信息，则接下来是3个uleb128类型的字段`debuginfo_size`、`first_line_number`、`lines_count`。其中`debuginfo_size`字段指明后面`DebugInfo`结构体占用的字节大小，`first_line_number`指明当前`Proto`在源文件中的起始行，`lines_count`字段指明当前`Proto`在源文件中所占的行数。

如果上面的`instructions_count`字段值不为0，接下来则存放的是指令`Instruction`数组，每条指令长度与`Luac`一样，占用32位，但使用的指令格式完全不同，此处不展开讨论它。

指令后面是常量信息，它的定义如下：
```
typedef struct(int32 upvalues_count, int32 complex_constants_count, int32 numeric_constants_count) {
    while (upvalues_count-- > 0) {
        uint16 upvalue;
    }
    
    while (complex_constants_count-- > 0) {
        ComplexConstant constant;
    }

    while (numeric_constants_count-- > 0) {
        NumericConstant numeric;
    }
} Constants;
```

可以看到，`Constants`中包含3个数组字段，每个字段的具体数目与前面指定的`upvalues_count`、`complex_constants_count`、`numeric_constants_count`相关。每个`UpValue`信息占用16位，`ComplexConstant`保存的常量信息比较丰富，它可以保存字符串、整型、浮点型、TAB表结构等信息。它的结构体开始处是一个uleb128类型的`tp`字段，描述了`ComplexConstant`保存的具体的数据。它的类型包括：
```
typedef enum {
    BCDUMP_KGC_CHILD = 0,
    BCDUMP_KGC_TAB = 1,
    BCDUMP_KGC_I64 = 2,
    BCDUMP_KGC_U64 = 3,
    BCDUMP_KGC_COMPLEX = 4,
    BCDUMP_KGC_STR = 5
} BCDUMP_KGC_TYPE;
```

这里重点关注下`BCDUMP_KGC_TAB，它表示这是一个Table表结构，即类似如下代码片断生成的数据内容：
```
tab={key1="val1",key2="val2"};
```

Table数据在`Luajit`中有专门的数据结构进行存储，它的定义如下：
```
typedef struct {
    uleb128 array_items_count;
    uleb128 hash_items_count;

    local int32 array_items_count_ = uleb128_value(array_items_count);
    local int32 hash_items_count_ = uleb128_value(hash_items_count);
    while (array_items_count_-- > 0) {
        ArrayItem array_item;
    }
    while (hash_items_count_-- > 0) {
        HashItem hash_item;
    }
} Table;
```

有基于数组的`ArrayItem`与基于Hash的`HashItem`两种Table类型结构，上面的`tab`即属于`HashItem`，它的定义如下：
```
typedef struct {
    TableItem key;
    TableItem value;
} HashItem;
```

`TableItem`描述了Table的键`key`与值`value`的类型与具体的数据内容，它的开始处是一个uleb128类型的`tp`字段，具体的取值类型如下：
```
typedef enum<uchar> {
    BCDUMP_KGC_CHILD = 0,
    BCDUMP_KGC_TAB = 1,
    BCDUMP_KGC_I64 = 2,
    BCDUMP_KGC_U64 = 3,
    BCDUMP_KGC_COMPLEX = 4,
    BCDUMP_KGC_STR = 5
} BCDUMP_KGC_TYPE;
```

当取到`tp`的类型值后，判断它的具体类型，然后接下来存放的即是具体的数据，`TableItem`在`010 Editor`中的模板结构体表示如下:
```
typedef struct {
    uleb128 tp;
    local int32 data_type = uleb128_value(tp);
    if (data_type >= BCDUMP_KTAB_STR) {
        local int32 len = data_type - BCDUMP_KTAB_STR;
        char str[len];
    } else if (data_type == BCDUMP_KTAB_INT) {
        uleb128 val;
    } else if (data_type == BCDUMP_KTAB_NUM) {
        TNumber num;
    } else if (data_type == BCDUMP_KTAB_TRUE) {
    } else if (data_type == BCDUMP_KTAB_FALSE) {
    } else if (data_type == BCDUMP_KTAB_NIL) {
    } else {
        Warning("TableItem need update\n");
    }
} TableItem;
```

当取值大于5，即大于`BCDUMP_KTAB_STR`时，它的类型为字符串，需要减去5后计算出它的实际内容长度。另外，上面的`TNumber`是由两个uleb128组成的分为高与低各32位的数据类型。

`NumericConstant`存储数值型的常量，比如`local`语句中赋值的整型与浮点型数据。它的定义如下：
```
typedef struct {
    uleb128_33 lo;
    if (lo.val[0] & 0x1)
        uleb128 hi;
} NumericConstant;
```

数值常量分为`lo`低部分与`hi`高部分，注意`lo`的类型为`uleb128_33`，它是一个33位版本的uleb128，即判断第一个字节后面是否还包含后续数据时，首先判断第33位是否置1。它的定义如下：
```
typedef struct {
    ubyte val;
    if((val >> 1) > 0x3f) {
        ubyte val <comment="uleb128 element">;
        if (val > 0x7f) {
            ubyte val <comment="uleb128 element">;
            if(val > 0x7f) {
                ubyte val <comment="uleb128 element">;
                if(val > 0x7f) {
                    ubyte val <comment="uleb128 element">;
                }
            }
        }
    }
} uleb128_33;
```

当读取到`lo`的最低为是1时，说明这是一个`TNumber`类型，还需要解析它的高32位部分。

在`Constants`常量结构体后面，如果`ProtoHeader`的`debuginfo_size`值大于0，那么接下来此处存放的是`Debuginfo`调试信息，它的定义如下：
```
typedef struct(int32 first_line_number, int32 lines_count, int32 instructions_count, int32 debuginfo_size, int32 upvalues_count) {
    if (debuginfo_size > 0) {
        LineInfo lineinfo(lines_count, instructions_count);

        if (upvalues_count > 0)
            UpValueNames upvalue_names(upvalues_count);
        
        VarInfos varinfos;
    }
} DebugInfo
```

分为`LineInfo`与`VarInfos`两部分，前者是存储的一条条的行信息，后者是局部变量信息。`VarInfos`中存储了变量的类型、名称、以及它的作用域起始地址与结束地址，它的定义如下：
```
typedef struct(uchar tp) {
    local uchar tp_ = tp;
    //Printf("tp:0x%x\n", tp);
    if (tp >= VARNAME__MAX) {
        string str;
    } else {
        VARNAME_TYPE vartype;
    }

    if (tp != VARNAME_END) {
        uleb128 start_addr;
        uleb128 end_addr;
    }
} VarInfo;
```

代码中的指令引用一个局部变量时，调试器可以通过其`slot`槽索引值到`VarInfos`中查找它的符号信息，这也是`Luajit`文件支持源码级调试的主要方法。

## 编写`Luajit`文件的`010 Editor`文件模板

在掌握了`Luajit`的完整格式后，编写`010 Editor`文件模板应该没有难度与悬念了。

`Luajit`的线性结构解析起来比`Luac`简单，只需要按顺序解析`Proto`，直接读取到字节0结束。整体部分的代码片断如下：
```
typedef struct() {
    ProtoHeader header;
    if (uleb128_value(header.size) > 0) {
        if (uleb128_value(header.instructions_count) > 0)
            Instruction inst[uleb128_value(header.instructions_count)];
        Constants constants(header.upvalues_count, uleb128_value(header.complex_constants_count), uleb128_value(header.numeric_constants_count));
        if (header.debuginfo_size_ > 0)
            DebugInfo debuginfo(uleb128_value(header.first_line_number), uleb128_value(header.lines_count), uleb128_value(header.instructions_count), header.debuginfo_size_, header.upvalues_count);

        local int64 end = FTell();
        //Printf("start:0x%lx, end:0x%lx, size:0x%lx\n", header.start, end, end - header.start);
        if (uleb128_value(header.size) != end - header.start) {
            Warning("Incorrectly read: from 0x%lx to 0x%lx (0x%lx) instead of 0x%lx\n", header.start, end, end - header.start, uleb128_value(header.size));
        }
    }
} Proto <optimize=false>;

typedef struct {
    GlobalHeader header;
    while (!FEof())
        Proto proto;
} Luajit <read=LuajitRead>;

string LuajitRead(Luajit &lj) {
    return lj.header.name;
}
```

`Proto`的`header`的`size`字段是当前`Proto`的大小，在解析的时候有必要对其合法性进行检查。

在编写模板时，只遇到过一个比较难解决的问题，那就是对`NumericConstant`中浮点数的解析。如下面的代码片断：
```
local dd = 3.1415926;
```

编译生成`Luajit`文件后，它会以浮点数据存储进入`NumericConstant`结构体中，并且它对应的64位数据为0x400921FB4D12D84A。在解析该数据时，并不能像`Luac`中`TValue`那样直接进行解析，`Luac`中声明的结构体`TValue`可以直接解析其内容，但`Luajit`中0x400921FB4D12D84A值的`lo`与`hi`是通过uleb128_33与uleb128两种数据类型动态计算才能得到。

将0x400921FB4D12D84A解析为double，虽然在C语言中只需要如下代码：
```
uint64_t p = 0x400921FB4D12D84A;
double *dd = (double *)&p;
printf("%.14g\n", *dd);
```

但`010 Editor`模板不支持指针数据类型，如果使用结构体UNION方式，C语言中如下方法即可转换：
```
union
{
    long long i;
    double    d;
} value;

value.i = l;

char buf[17];
snprintf (buf, sizeof(buf),"%.14g",value.d);
```

`010 Editor`虽然支持结构体与UNION，但并不支持声明`local`类型的结构体变量。所以，浮点数据的解析工作一度陷入了困境！最后，在`010 Editor`的帮且文档中执行“double”关键字，查找是否有相应的解决方法，最后找到了一个`ConvertBytesToDouble()`方法，编写代码进行测试：
```
local uchar chs[8];
chs[0] = 0x4A;
chs[1] = 0xD8;
chs[2] = 0x12;
chs[3] = 0x4D;
chs[4] = 0xFB;
chs[5] = 0x21;
chs[6] = 0x09;
chs[7] = 0x40;
local double ddd = ConvertBytesToDouble(chs);
Printf("%.14g\n", ddd);
```

输出如下：
```
3.141592502594
```

可见，不是直接进行的内存布局转换，而是进行了内部的计算转换，虽然与原来的3.1415926有少许的出入，但比起不能转换还是要强上许多，通过`ConvertBytesToDouble()`，可以为`NumericConstant`编写其read方法，代码如下：
```
string NumericConstantRead(NumericConstant &constant) {
    if (constant.lo.val[0] & 0x1) {
        local string str;
        local int i_lo = uleb128_33_value(constant.lo);
        local int i_hi = uleb128_value(constant.hi);
        local uchar bytes_lo[4];
        local uchar bytes_hi[4];
        local uchar bytes_double[8];
        ConvertDataToBytes(i_lo, bytes_lo);
        ConvertDataToBytes(i_hi, bytes_hi);
        Memcpy(bytes_double, bytes_lo, 4);
        Memcpy(bytes_double, bytes_hi, 4, 4);
        
        local double n = ConvertBytesToDouble(bytes_double);
        SPrintf(str, "%.14g", ((uleb128_value(constant.hi) == (3 | (1 << 4))) ? 
            i : n));
        return str;
    } else {
        local string str;
        local int number = uleb128_33_value(constant.lo);
        if (number & 0x80000000)
            number = -0x100000000 + number;

        SPrintf(str, "0x%lx", number);
        return str;
    }
}
```

最后，编写完成后，效果如图所示：
![luajit](luajit.jpg)

完整的luajit.bt文件可以在这里找到：
[https://github.com/feicong/lua_re](https://github.com/feicong/lua_re)。