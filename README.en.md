# CTF PWN Knowledge Base (Overview & Navigation)

[简体中文](./README.md) | English

[![Stars](https://img.shields.io/github/stars/largefriessss/ctf-pwn-notes?style=flat-square)](https://github.com/largefriessss/ctf-pwn-notes/stargazers)
[![License](https://img.shields.io/github/license/largefriessss/ctf-pwn-notes?style=flat-square)](./LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/largefriessss/ctf-pwn-notes?style=flat-square)](https://github.com/largefriessss/ctf-pwn-notes/commits/main)
[![Content](https://img.shields.io/badge/Content-13_chapters_%C2%B7_20k%2B_lines-2f81f7?style=flat-square)](./README.md)
[![中文](https://img.shields.io/badge/README-%E4%B8%AD%E6%96%87_%7C_English-8957e5?style=flat-square)](./README.md)

> A systematic CTF PWN study collection from beginner to advanced, organized in a **general-to-specific structure**: this README is the "general" part (knowledge map + learning path + technique decision table), and the 13 chapters are the "specific" parts — one chapter per technique/topic, each self-contained with theory, exploit templates, worked examples, variants, pitfalls, and checklists.
>
> Everything is Markdown. All exploit templates are based on **pwntools (Python3)** and cover both **32-bit and 64-bit** architectures. The chapters are written in Chinese; this page is the English guide to what each file covers.

---

## 1. File Overview

| # | File | One-line summary | Difficulty |
|---|---|---|---|
| 00 | [README.md](./README.md) | This page (Chinese): knowledge map, learning path, technique decision table | — |
| 01 | [01-基础知识与工具链.md](./01-基础知识与工具链.md) | Memory layout, calling conventions, stack frames, ELF/PLT/GOT, protection mechanisms, pwntools/gdb/IDA toolchain | ★ |
| 02 | [02-ret2text.md](./02-ret2text.md) | Stack overflow that reuses backdoors/code fragments already in the binary (lesson one) | ★ |
| 03 | [03-ret2shellcode.md](./03-ret2shellcode.md) | Inject and execute machine code: jump to stack/bss, mprotect upgrade, bad-character handling | ★★ |
| 04 | [04-ret2syscall.md](./04-ret2syscall.md) | ROP basics: chain gadgets into an `execve("/bin/sh", 0, 0)` syscall | ★★ |
| 05 | [05-ret2libc.md](./05-ret2libc.md) | Leak libc → compute base → `system("/bin/sh")`; the standard two-stage pattern + one_gadget | ★★★ |
| 06 | [06-ret2plt与ret2dlresolve.md](./06-ret2plt与ret2dlresolve.md) | Leak/write via PLT functions; forge relocation entries to fool the dynamic linker | ★★★ |
| 07 | [07-ROP高级技巧.md](./07-ROP高级技巧.md) | ret2csu, stack pivot, SROP, BROP, stack alignment, setcontext | ★★★★ |
| 08 | [08-格式化字符串漏洞.md](./08-格式化字符串漏洞.md) | Arbitrary R/W with `%n`: leak canary/libc, hijack GOT/return address, blind fmtstr | ★★★ |
| 09 | [09-整数溢出与Off-by-One.md](./09-整数溢出与Off-by-One.md) | Signedness bugs, truncation, off-by-one pivot, negative indexing, uninitialized data | ★★★ |
| 10 | [10-堆漏洞全解.md](./10-堆漏洞全解.md) | Full ptmalloc guide + UAF/double free/tcache/fastbin/unlink/House of * series | ★★★★ |
| 11 | [11-ORW与沙箱绕过.md](./11-ORW与沙箱绕过.md) | When seccomp blocks execve, skip getshell and read the flag via open/read/write | ★★★★ |
| 12 | [12-内核PWN入门.md](./12-内核PWN入门.md) | Kernel exploitation: qemu setup, ret2usr, kernel ROP, modprobe_path | ★★★★★ |
| 99 | [99-C语言函数手册.md](./99-C语言函数手册.md) | PWN-oriented C library reference: prototype/#params/param meanings/return/danger level + syscall number table | Dictionary |

---

## 2. Recommended Learning Path

```
Foundation            Introductory             Advanced                    Specialization
──────             ─────────              ─────────                 ─────────
01 Basics &   ──►  02 ret2text  ──►  04 ret2syscall ──►  07 ROP Advanced      ──► 10 Heap
   Tools           │                        │              (csu/pivot/SROP)          │
(must read;       └─►  03 ret2shellcode ──► 05 ret2libc ◄── 06 ret2plt/dlresolve      ▼
 everything               (NX off)          │                                        11 ORW & Sandbox
 builds on it)                              │                                              │
                                            └──────► 08 Format String                      ▼
                                                       (pairs with 05)                     12 Kernel PWN

                              09 Integer Overflow (audit-oriented — interleave anytime)
```

- **Step 0 (mandatory)**: Chapter 01. Without calling conventions and stack frames, every later chapter is an uphill battle; the toolchain part can be revisited while solving challenges.
- **Intro trio**: 02 → 03 → 04. All three assume "you can overflow a stack buffer"; they differ only in *where you jump*.
- **The watershed**: Chapter 05 (ret2libc) is the mental shift from "the binary already contains something useful" to "libc contains everything". It is the starting point of most real challenge solutions.
- **Two parallel tracks**: stack (07) and heap (10) can be studied in parallel; Chapter 08 is tightly coupled with 05 — start it right after 05.
- **For live CTFs**: 09 (audit-oriented) applies everywhere; 11 is the staple of high-score challenges; 12 is the advanced track and assumes the stack/heap fundamentals.
- **Chapter 99**: use it as a dictionary — look up prototypes/parameters while reversing, danger levels while auditing, and syscall numbers while writing exploits.

---

## 3. Technique Decision Table (check here first)

Given a PWN challenge, triage in this order and jump to the matching chapter:

### 3.1 Step one: static info

```bash
file pwn          # arch (32/64-bit), static or dynamic, stripped or not
checksec pwn      # protection flags (line-by-line meaning in Chapter 01 §6)
strings pwn | grep -i sh / flag / bin    # look for key strings
```

### 3.2 Decision table

| Observed signature | Technique to try | Chapter |
|---|---|---|
| IDA shows `system("/bin/sh")`, `get_shell`, `backdoor`, `cat flag`, etc. | **ret2text**: overwrite the return address to jump there | 02 |
| checksec shows NX disabled (stack/heap/bss executable) | **ret2shellcode**: inject machine code and jump to it | 03 |
| **Statically linked** binary + stack overflow | **ret2syscall**: plenty of gadgets in-binary; chain syscalls | 04 |
| Dynamic linking + NX on + no backdoor | **ret2libc**: leak GOT → compute base → second overflow | 05 |
| The challenge ships a libc file / remote libc version known | ret2libc (compute offsets directly; patchelf for local debugging) | 05 |
| PLT functions callable (`write@plt`/`puts@plt`), or you need unlimited overflows | **ret2plt**: write-leak + read-into-bss | 06 |
| Partial RELRO + very small overflow space (full chain won't fit) | **ret2dlresolve**: forge relocation entries | 06 |
| 64-bit binary missing `pop rdx` and friends | **ret2csu** (`__libc_csu_init` universal gadgets) | 07 |
| Only a few bytes of overflow — the chain doesn't fit | **stack pivot** (leave;ret and friends) | 07 |
| No leak primitive but controllable rax / sigreturn available | **SROP** (SigreturnFrame all-in-one) | 07 |
| Remote challenge without the binary | **BROP** (blind ROP) | 07 |
| `printf(buf)` style calls / `sprintf` with user input | **format string**: arbitrary read/write | 08 |
| Suspicious length checks: `int` vs `size_t`, `<=` bounds, `n+1`, `strncpy` | **integer overflow / off-by-one** | 09 |
| Menu-style heap challenge: add / delete / edit / show | **heap exploitation** (pick a play by libc version) | 10 |
| seccomp sandbox (execve banned) — visible via `seccomp-tools dump` | **ORW**: open/read/write straight to the flag | 11 |
| Challenge bundle is bzImage + rootfs.cpio + start.sh (qemu) | **kernel PWN** | 12 |
| Forgot a function prototype/parameters/syscall number | look it up in the **C function reference** | 99 |

### 3.3 Protection quick reference (details in Chapter 01 §6)

| Protection | When disabled | Impact when enabled |
|---|---|---|
| NX | stack executable → ret2shellcode directly | can't jump to the stack; switch to ret2text/libc/syscall |
| Canary | — | return-address overwrite is detected; leak the canary (e.g. via format string) and restore it |
| PIE | fixed image → gadget addresses usable directly | image base randomized; leak an address or fall back to libc/dlresolve |
| RELRO (Full) | — | GOT read-only + no lazy binding → ret2dlresolve dies; GOT overwrite needs another target |
| FORTIFY_SOURCE | — | `%n` blocked, `__chk` variants check bounds; mind the bypass conditions when auditing |

---

## 4. Uniform Chapter Structure

Every chapter follows the same layout for easy cross-referencing:

1. **Chapter overview**: applicable scenarios / preconditions / difficulty
2. **Theory**: with ASCII stack-layout or memory-structure diagrams
3. **Exploitation conditions**: how to confirm via checksec output and program traits
4. **Complete pwntools templates**: one 32-bit and one 64-bit, commented line by line
5. **Worked examples**: pseudo-C + checksec + hand-computed offsets + full exploit
6. **Variants & extensions**: exhaustive listing of known variants of the technique
7. **Common pitfalls & troubleshooting**
8. **Checklist + further reading** (cross-linked chapters at the end)

> **Diagram convention**: in every vertical address diagram, **the top is the low address and the bottom is the high address** — in a stack frame, the buffer sits above the return address; in heap layouts, the lower-addressed chunk is drawn above its neighbor; in memory maps, `.text` is at the top and kernel space at the bottom. Phrases like "above/below in the figure" always follow this convention.

---

## 5. Environment & Toolchain (install cheat sheet)

```bash
# Python side
pip install pwntools                # exploit framework
pip install LibcSearcher            # libc symbol search (or online libc.rip / libc.blukat.me)

# System tools
sudo apt install gdb netcat socat patchelf seccomp-tools 2>/dev/null || true
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh   # gdb enhancements
# or gef: bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Gadgets & libc
pip install ropgadget               # the ROPgadget command
git clone https://github.com/JonathanSalwan/ROPgadget
# one_gadget
gem install one_gadget
# libc-database (local libc lookup)
git clone https://github.com/niklasb/libc-database && cd libc-database && ./get ubuntu

# Local debugging against a specific libc
patchelf --set-interpreter /path/to/ld-2.27.so --replace-needed libc.so.6 /path/to/libc-2.27.so ./pwn
```

## 6. Minimal pwntools Skeleton (every exploit looks like this)

```python
from pwn import *

context.arch = 'amd64'          # or 'i386'; decides p64/p32 and asm behavior
context.log_level = 'debug'     # on while debugging, off on game day

elf  = ELF('./pwn')
libc = ELF('./libc.so.6')       # load it when the challenge ships a libc

def start():
    return process('./pwn') if args.LOCAL else remote('127.0.0.1', 9999)

io = start()

# ... leak / overflow / exploit logic (see each chapter) ...

io.interactive()                # drop into the shell
```

---

## 7. Usage Suggestions

- **Don't just read — build**: every worked example describes a constructible challenge. Compile it yourself with `gcc` (match the chapter's protections with `-z execstack` / `-no-pie` etc.) and exploit it.
- **Follow the cross-links**: the "further reading" section at the end of each chapter forms a web; e.g. Chapter 08's GOT overwrite for libc leaking leads right back to Chapter 05.
- **Treat Chapter 99 as a dictionary**: when stuck in IDA, check the prototype (parameter count/meanings) first, the danger level column for audit direction, then the syscall table for the exploit.
- **Heap challenges are version-sensitive**: every play in Chapter 10 lists its glibc version constraints; run `strings libc.so.6 | grep "GNU C Library"` first to identify the version.

---

## 8. License

Released under the [MIT License](./LICENSE): you are free to read, republish, translate, modify, and redistribute this material (commercial use included), as long as the original copyright notice and license text are preserved in your copies.
