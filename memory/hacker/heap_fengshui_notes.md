# 堆风水(Heap Feng Shui)漏洞利用学习笔记

## 什么是堆风水?
堆风水是一种高级堆利用技术，通过精确控制堆布局，使其按预期工作以实现漏洞利用。

## 堆管理原理

### 1. 堆结构
- chunks (内存块)
- bins (空闲块链表)
- top chunk (顶部块)

### 2. 分配机制
- fastbin (快速分配)
- smallbin (小分配)
- largebin (大分配)
- unsortedbin (未排序)

### 3. 合并机制
- 相邻空闲块合并
- backward/forward consolidation

## 堆风水技术

### 1. House of Spirit
- 伪造chunk
- 释放到fastbin
- 重新分配

### 2. House of Lore
- 伪造bin链
- 绕过安全检查

### 3. House of Force
- 覆盖top chunk
- 任意分配

### 4. House of Einherjar
- 溢出利用
- 绕过边界检查

### 5. House of Roman
- fastbin attack
- 绕过checks

## 利用前提

### 1. 堆风水条件
- 能够分配任意大小
- 能够溢出相邻chunk
- 能够触发释放

### 2. 信息泄露
- 堆地址泄露
- libc地址泄露

## 防御措施

### 1. 堆保护
- PIE (地址随机化)
- heap canary
- safe-linking

### 2. 更新glibc
- 定期更新
- 修复漏洞

### 3. 代码安全
- 边界检查
- 整数溢出防护

## 实践资源

### 1. CTF题目
- heap相关题目
- 堆风水练习

### 2. 工具
- pwntools
- gdb-gef
- heap inspector

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
