# CTF PWN 知识库（总览与导航）

简体中文 | [English](./README.en.md)

[![Stars](https://img.shields.io/github/stars/largefriessss/ctf-pwn-notes?style=flat-square)](https://github.com/largefriessss/ctf-pwn-notes/stargazers)
[![License](https://img.shields.io/github/license/largefriessss/ctf-pwn-notes?style=flat-square)](./LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/largefriessss/ctf-pwn-notes?style=flat-square)](https://github.com/largefriessss/ctf-pwn-notes/commits/main)
[![内容](https://img.shields.io/badge/内容-13章_%C2%B7_2万行-2f81f7?style=flat-square)](./README.md)
[![English](https://img.shields.io/badge/README-English_%7C_中文-8957e5?style=flat-square)](./README.en.md)

> 一套从零基础到进阶的 CTF PWN 系统化资料，采用**总分结构**：本 README 是"总"（知识地图 + 学习路线 + 题型决策表），其余 13 个分册是"分"（每个题型/主题一章，每章自成体系，含原理、模板、例题、变体、坑与检查清单）。
>
> 全部内容为 Markdown，所有 exp 模板基于 **pwntools (Python3)**，覆盖 **32 位与 64 位**两种架构。

---

## 1. 文件总览

| 序号 | 文件 | 一句话简介 | 难度 |
|---|---|---|---|
| 00 | [README.md](./README.md) | 本页：知识地图、学习路线、题型决策表 | — |
| 01 | [01-基础知识与工具链.md](./01-基础知识与工具链.md) | 内存布局、调用约定、栈帧、ELF/PLT/GOT、保护机制、pwntools/gdb/IDA 工具链 | ★ |
| 02 | [02-ret2text.md](./02-ret2text.md) | 栈溢出跳转程序自带后门/代码片段（入门第一课） | ★ |
| 03 | [03-ret2shellcode.md](./03-ret2shellcode.md) | 注入并执行机器码：跳栈、跳 bss、mprotect 改权限、坏字节处理 | ★★ |
| 04 | [04-ret2syscall.md](./04-ret2syscall.md) | ROP 入门：用 gadget 拼系统调用链 execve("/bin/sh",0,0) | ★★ |
| 05 | [05-ret2libc.md](./05-ret2libc.md) | 泄露 libc → 计算基址 → system("/bin/sh")，两段式标准打法 + one_gadget | ★★★ |
| 06 | [06-ret2plt与ret2dlresolve.md](./06-ret2plt与ret2dlresolve.md) | 借 PLT 函数泄露/写入；伪造重定位表项欺骗动态链接器 | ★★★ |
| 07 | [07-ROP高级技巧.md](./07-ROP高级技巧.md) | ret2csu、栈迁移、SROP、BROP、栈对齐、setcontext | ★★★★ |
| 08 | [08-格式化字符串漏洞.md](./08-格式化字符串漏洞.md) | %n 任意读写：泄露 canary/libc、改 GOT/返回地址、盲注 | ★★★ |
| 09 | [09-整数溢出与Off-by-One.md](./09-整数溢出与Off-by-One.md) | 符号混淆、截断、off-by-one 迁栈、负索引、未初始化 | ★★★ |
| 10 | [10-堆漏洞全解.md](./10-堆漏洞全解.md) | ptmalloc 全解 + UAF/double free/tcache/fastbin/unlink/House 系 | ★★★★ |
| 11 | [11-ORW与沙箱绕过.md](./11-ORW与沙箱绕过.md) | seccomp 沙箱下放弃 getshell，直接 open/read/write 读 flag | ★★★★ |
| 12 | [12-内核PWN入门.md](./12-内核PWN入门.md) | 内核态 exploitation：qemu 环境、ret2usr、内核 ROP、modprobe_path | ★★★★★ |
| 99 | [99-C语言函数手册.md](./99-C语言函数手册.md) | PWN 视角 C 库函数字典：原型/参数个数/参数含义/返回值/危险等级 + 系统调用号表 | 字典 |

---

## 2. 推荐学习路线

```
打地基                入门题型                 进阶题型                    特化方向
──────             ─────────              ─────────                 ─────────
01 基础与工具  ──►  02 ret2text  ──►  04 ret2syscall ──►  07 ROP高级(csu/pivot/SROP) ──► 10 堆漏洞
（必读，全部     │                        │                                        │
 前置知识）     └─►  03 ret2shellcode ──► 05 ret2libc ◄── 06 ret2plt/dlresolve      ▼
                                             │                                        11 ORW与沙箱
                                             └────────► 08 格式化字符串（与 05 互相配合）      │
                                                                                      ▼
                                            09 整数溢出（审计向，随时穿插）              12 内核PWN
```

- **第 0 步（必读）**：01 章。调用约定与栈帧不熟，后面每章都寸步难行；工具链部分可以边做题边回查。
- **入门三连**：02 → 03 → 04。这三章的共同前提是"能栈溢出"，区别只在"跳去哪"。
- **分水岭**：05 ret2libc 是从"程序里有现成东西"到"libc 里什么都有"的思维跃迁，是大多数比赛题的起点。
- **两条腿走路**：栈方向（07）与堆方向（10）可以并行推进；08 格式化字符串与 05 强关联，建议学完 05 立刻学。
- **比赛实战**：09（审计向）贯穿始终；11 是高分题标配；12 是进阶方向，需要前面所有栈/堆基础。
- **99 手册**：当字典用。逆向时忘函数参数、exp 时忘调用号、审计时确认危险函数，都翻它。

---

## 3. 题型决策表（拿到题先看这里）

拿到一道 PWN 题，按这个顺序自查，"命中特征"直接跳对应章节：

### 3.1 第一步：静态信息

```bash
file pwn          # 位数（32/64）、静态还是动态链接、是否 stripped
checksec pwn      # 保护机制（逐项含义见 01 章 §6）
strings pwn | grep -i sh / flag / bin    # 找关键字符串
```

### 3.2 决策表

| 观察到的特征 | 优先考虑的解法 | 章节 |
|---|---|---|
| IDA 里看到 `system("/bin/sh")`、`get_shell`、`backdoor`、`cat flag` 等函数 | **ret2text**：溢出覆盖返回地址跳过去 | 02 |
| checksec 显示 NX 关闭（栈/堆/bss 可执行） | **ret2shellcode**：写入机器码并跳过去 | 03 |
| **静态编译**（file 显示 statically linked）+ 栈溢出 | **ret2syscall**：程序内有大量 gadget，拼系统调用链 | 04 |
| 动态链接 + NX 开 + 无后门 | **ret2libc**：leak GOT → 算 libc 基址 → 二次溢出 | 05 |
| 题目给了 libc 文件 / 已知远程 libc 版本 | ret2libc（直接算偏移，配合 patchelf 本地调试） | 05 |
| 题目用 `write@plt`/`puts@plt` 可调用，或需要"无限次溢出" | **ret2plt**：write 泄露 + read 写 bss | 06 |
| Partial RELRO + 溢出空间很小（放不下完整链） | **ret2dlresolve**：伪造重定位表项 | 06 |
| 64 位缺 `pop rdx` 等传参 gadget | **ret2csu**（`__libc_csu_init` 万能 gadget） | 07 |
| 可溢出长度只有几个字节，放不下链 | **栈迁移 stack pivot**（leave;ret 等） | 07 |
| 程序中没有 leak 手段但能控制 rax / 有 sigreturn | **SROP**（SigreturnFrame 一把梭） | 07 |
| 远程题不给二进制文件 | **BROP**（盲打 ROP） | 07 |
| `printf(buf)` / `printf("...%s...", buf)` 混用 / `sprintf` 用户输入 | **格式化字符串**：任意读写 | 08 |
| 长度检查可疑：`int` 与 `size_t` 混用、`<=` 边界、`n+1`、`strncpy` | **整数溢出 / off-by-one** | 09 |
| 菜单题：add / delete / edit / show，操作堆块 | **堆漏洞**（先看 libc 版本再选打法） | 10 |
| 有 seccomp/沙箱（禁 execve），运行 `seccomp-tools dump` 可见规则 | **ORW**：open/read/write 直取 flag | 11 |
| 题目包是 bzImage + rootfs.cpio + start.sh（qemu 启动） | **内核 PWN** | 12 |
| 忘了某函数原型/参数/调用号 | 查 **C 函数手册** | 99 |

### 3.3 保护机制速查（详细讲解在 01 章 §6）

| 保护 | 关闭时 | 开启时的影响 |
|---|---|---|
| NX | 栈可执行 → ret2shellcode 直接打 | 不能跳栈；转向 ret2text/libc/syscall |
| Canary | — | 覆盖返回地址会被检测；需先格式化字符串等手段泄露 canary 并原样放回 |
| PIE | 程序地址固定，gadget 地址直接用 | 程序基址随机；需泄露程序地址或走 libc/dlresolve |
| RELRO (Full) | — | GOT 只读、无延迟绑定 → ret2dlresolve 失效，改 GOT 需另寻目标 |
| FORTIFY_SOURCE | — | `%n` 不可写、`__chk` 版本函数检查边界；审计时注意绕过条件 |

---

## 4. 每章的统一体例

所有分册遵循同一套结构，方便横向查阅：

> **图示约定**：全套资料所有竖直方向的地址示意图一律**上为低地址、下为高地址**——栈帧图中 buf 在上、返回地址在下；堆内存图中低地址 chunk 在上、相邻高地址 chunk 在下；内存布局图中 .text 在上、内核空间在下。正文中的"图中上方/下方"均以该约定为准。

1. **本章速览**：适用场景 / 前置条件 / 难度星级
2. **原理讲解**：配 ASCII 栈布局图或内存结构图
3. **利用条件与判定方法**：结合 checksec 输出与程序特征
4. **完整 pwntools 模板**：32 位与 64 位各一份，逐行中文注释
5. **典型例题**：伪 C 代码 + checksec + 手算偏移 + 完整 exp
6. **变体与扩展**：该技术的已知变体尽力穷举
7. **常见坑与排错**
8. **本章检查清单 + 相关阅读**（文末互链）

---

## 5. 环境与工具清单（安装速查）

```bash
# Python 侧
pip install pwntools                # exp 框架
pip install LibcSearcher            # libc 符号搜索（或用在线 libc.rip / libc.blukat.me）

# 系统工具
sudo apt install gdb netcat socat patchelf seccomp-tools 2>/dev/null || true
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh   # gdb 增强
# 或 gef: bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# gadget 与 libc
pip install ropgadget               # ROPgadget 命令
git clone https://github.com/JonathanSalwan/ROPgadget
# one_gadget
gem install one_gadget
# libc-database（本地查 libc）
git clone https://github.com/niklasb/libc-database && cd libc-database && ./get ubuntu

# 多 libc 本地调试
patchelf --set-interpreter /path/to/ld-2.27.so --replace-needed libc.so.6 /path/to/libc-2.27.so ./pwn
```

## 6. 最小 pwntools 骨架（每章 exp 都长这样）

```python
from pwn import *

context.arch = 'amd64'          # 或 'i386'；会决定 p64/p32、asm 行为
context.log_level = 'debug'     # 调试期打开，比赛可关

elf  = ELF('./pwn')
libc = ELF('./libc.so.6')       # 题目给了 libc 就加载

def start():
    return process('./pwn') if args.LOCAL else remote('127.0.0.1', 9999)

io = start()

# ... leak / overflow / exploit 逻辑（见各章节） ...

io.interactive()                # 拿到 shell 后进入交互
```

---

## 7. 使用建议

- **别只看不练**：每章的例题都给出了可构造的题目情境，建议自己 `gcc` 编译出来（记得对照章节里的保护选项加 `-z execstack` / `-no-pie` 等参数）再打一遍。
- **交叉引用**：章节文末的"相关阅读"构成一张互链网，比如学到 08 章改 GOT 泄露 libc，会自然引回 05 章。
- **99 手册当字典**：逆向卡壳时先查函数原型（参数个数、含义），再查"危险等级"列确认审计方向，最后查系统调用号表写 exp。
- **版本敏感的堆题**：10 章里的每个打法都标注了 glibc 版本限制，做题先 `strings libc.so.6 | grep "GNU C Library"` 确认版本。

---

## 8. 许可证

本项目以 [MIT License](./LICENSE) 开源：你可以自由地阅读、转载、翻译、修改和二次分发（包括商用），只需在副本中保留原版权声明与许可文本。
