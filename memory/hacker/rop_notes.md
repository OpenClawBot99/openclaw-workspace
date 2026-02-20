# ROP(Return-Oriented Programming)学习笔记

## 什么是ROP?
ROP是一种高级漏洞利用技术，通过链接程序中已存在的代码片段(gadgets)来构建攻击payload，绕过DEP保护。

## ROP原理

### 1. 为什么需要ROP?
- DEP/NX使数据区域不可执行
- 无法直接注入shellcode
- 需要重用已有代码

### 2. Gadgets
- 以ret指令结尾的代码序列
- 通常3-10条指令
- 可以执行任意操作

### 3. ROP链
- 将gadgets地址串联
- 控制程序执行流
- 达成攻击目的

## 常见ROP技术

### 1. Stack Pivoting
- 伪造栈帧
- 控制栈指针

### 2. JOP (Jump-Oriented Programming)
- 使用jmp指令
- 调用 dispatched

### 3. COP (Call-Oriented Programming)
- 使用call指令

## 绕过技术

### 1. ROP (Return-Oriented Programming)
- 利用ret链接gadgets

### 2. JOP/COP
- 绕过ret检测

### 3. 利用内存布局
- Heap spray
- Stack spray

## 实践工具

- ROPgadget
- Ropper
- objdump
- gdb

## 防御措施

- CFI (Control Flow Integrity)
- ASLR
- Stack Canary

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
