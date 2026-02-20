# 缓冲区溢出学习笔记

## 什么是缓冲区溢出?
缓冲区溢出是一种常见的软件漏洞，攻击者通过向程序输入超出缓冲区容量的数据，覆盖相邻内存，从而执行恶意代码。

## 常见类型

### 1. 栈溢出 (Stack Overflow)
- 覆盖返回地址
- 执行shellcode

### 2. 堆溢出 (Heap Overflow)
- 堆管理结构损坏
- 覆盖函数指针

### 3. 格式化字符串漏洞
- %x, %n 等格式化符
- 泄露内存信息

## 防御措施

### 1. DEP (Data Execution Prevention)
- 标记内存页为不可执行
- 阻止shellcode执行

### 2. ASLR (Address Space Layout Randomization)
- 随机化地址空间
- 增加利用难度

### 3. Stack Canary
- 栈保护金丝雀
- 检测溢出

## 实践环境

- Pwnable.kr
- CTFHub
- Ghidra逆向分析

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
