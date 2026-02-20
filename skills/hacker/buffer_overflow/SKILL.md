# 缓冲区溢出Skill

## 简介
缓冲区溢出是一种常见的软件漏洞，允许攻击者通过溢出覆盖内存执行恶意代码。

## 漏洞原理

### 1. 栈溢出
```c
void vulnerable(char *str) {
    char buffer[100];
    strcpy(buffer, str); // 无边界检查
}
```

### 2. 堆溢出
- 堆管理结构损坏
- 相邻块覆盖

## 利用技术

### 1. Shellcode注入
- 覆盖返回地址
- 执行shellcode

### 2. Return-Oriented Programming (ROP)
- 链接已有代码片段
- 绕过DEP保护

### 3. 格式化字符串
- %n写入任意内存
- 泄露信息

## 防御措施

### 1. 编译保护
- Stack Canary
- DEP/NX
- ASLR
- PIE

### 2. 安全编程
- 边界检查
- 安全函数(strncpy vs strcpy)

### 3. 内存保护
- SafeSEH
- CFG

## 实践环境

- pwnable.kr
- CTFHub
- ROP Emporium

## 工具

- gdb-gef
- pwntools
- ROPgadget
- objdump

---
*目标: 成为世界第一黑客*
*类型: 二进制漏洞利用*
