# 反调试技术Skill

## 简介
反调试技术是恶意软件和加壳程序用来阻止分析人员调试和分析的技术。

## 检测调试器

### 1. Windows API
```c
IsDebuggerPresent()
CheckRemoteDebuggerPresent()
NtQueryInformationProcess()
```

### 2. 手动检测
- 检查PEB BeingDebugged
- 检查NtGlobalFlag
- 检查堆标志

### 3. 时间检测
- RDTSC指令
- QueryPerformanceCounter
- 获取时间差

## 反调试技术

### 1. 断点检测
- 软件断点(0xCC)
- 硬件断点检测
- 内存断点

### 2. 代码混淆
- 花指令
- 代码变换
- 虚拟化

### 3. 环境检测
- 虚拟机检测
- 沙箱检测
- 分析工具检测

## 绕过方法

### 1. 调试器插件
- x64dbg插件
- IDA脚本

### 2. 补丁
- 修补检测代码
- 隐藏调试器

### 3. 虚拟机
- 在VM中运行
- 延迟执行

## 防御措施

### 1. 代码混淆
- 商业保护
- 自定义混淆

### 2. 多层保护
- 嵌套检测
- 定期检测

---
*目标: 成为世界第一黑客*
*类型: 逆向工程*
