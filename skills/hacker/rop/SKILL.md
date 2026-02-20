# ROP (Return-Oriented Programming) Skill

## 简介
ROP是一种高级利用技术，通过链接程序中已存在的代码片段(gadgets)来绕过DEP/NX保护。

## 原理

### 1. DEP/NX保护
- 数据不可执行
- 不能直接执行shellcode

### 2. ROP思路
- 不注入shellcode
- 利用已有代码
- 链接gadgets形成链

### 3. 返回导向
- 通过栈控制返回地址
- 串联多个gadgets

## Gadgets

### 1. 寻找gadgets
```bash
ROPgadget --binary vuln > gadgets.txt
Ropper --file vuln --search "pop|ret"
```

### 2. 常见gadgets
- `pop reg; ret`
- `pop reg; pop reg; ret`
- `mov [reg], reg; ret`
- `jmp reg`

### 3. 构造ROP链
- 控制寄存器
- 控制内存写入
- 调用函数

## 利用步骤

### 1. 信息收集
- 二进制分析
- 找到溢出点
- 确定覆盖偏移

### 2. 泄露地址
- 格式化字符串
- 缓冲区溢出
- 泄露libc地址

### 3. 构建ROP链
- 找到gadgets
- 构造chain
- 覆盖返回地址

### 4. 获取shell
- 调用system()
- execve("/bin/sh")
- ROP链执行

## 防御措施

### 1. ASLR
- 地址随机化
- 增加利用难度

### 2. CFI
- 控制流完整性
- 验证跳转目标

### 3. Stack Canary
- 检测溢出

### 4. 更新glibc
- 修复gadgets

## 工具

- pwntools
- ROPgadget
- Ropper
- gdb-gef

---
*目标: 成为世界第一黑客*
*类型: 二进制漏洞利用*
