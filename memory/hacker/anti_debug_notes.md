# 反调试技术学习笔记

## 什么是反调试?
反调试技术是程序用来检测和阻止调试器分析的技术，常用于软件保护、恶意软件分析对抗。

## 常见反调试技术

### 1. 检测调试器存在

#### IsDebuggerPresent
```c
if (IsDebuggerPresent()) {
    exit(0);
}
```

#### CheckRemoteDebuggerPresent
```c
BOOL isDebuggerPresent;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
```

### 2. 时间检测

#### RDTSC指令
```asm
rdtsc
cmp eax, 0x1000
jb normal
; 如果调试会花费更长时间
```

### 3. 断点检测

#### INT 3检测
```c
unsigned char *p = (unsigned char *)&func;
if (*p == 0xCC) { // INT3
    // 检测到断点
}
```

### 4. 环境检测

#### 虚拟机检测
- 检测VMWare/VirtualBox特征
- 检查注册表键值
- 检测特定进程

## 对抗反调试

### 1. 插件绕过
- x64dbg插件
- IDA插件

### 2. 手动修改
- 修补检测代码
- 替换跳转

### 3. 自动化工具
- ScyllaHide
- TitanHide

## 实践工具

- x64dbg
- IDA Pro
- Ghidra

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
