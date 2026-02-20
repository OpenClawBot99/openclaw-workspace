# UAF (Use-After-Free) Skill

## 简介
UAF是一种内存漏洞，释放后继续使用已释放的内存。

## 原理

### 1. 内存分配与释放
- malloc/free
- new/delete

### 2. 漏洞触发
- 释放后未置NULL
- 再次使用该指针

### 3. 内存布局
- 堆风水控制布局
- 欺骗分配器

## 利用技术

### 1. 任意地址写
- 覆盖函数指针
- 虚表劫持

### 2. 双重释放
- 触发堆块重叠

### 3. 竞争条件
- Time-of-check to time-of-use

## 攻击示例

### 1. 浏览器UAF
```javascript
var a = [];
a.push({});
a = null; // 释放
gc(); // 触发GC
a[0].fake = shellcode; // 使用
```

### 2. 堆风水
```c
alloc(0x100); // A
alloc(0x100); // B
free(A);
alloc(0x100); // C, 可能复用A
```

## 防御

### 1. 内存保护
- Safe Unlinking
- Canaries

### 2. 更新glibc
### 3. 自动化检测

---
*目标: 成为世界第一黑客*
*类型: 二进制漏洞*
