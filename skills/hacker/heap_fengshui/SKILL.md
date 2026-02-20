# 堆风水(Heap Feng Shui)Skill

## 简介
堆风水是一种高级堆利用技术，通过精确控制堆布局实现漏洞利用。

## 堆管理原理

### 1. 堆结构
- chunks (内存块)
- bins (空闲块链表)
- top chunk

### 2. 分配机制
- fastbin (快速分配)
- smallbin (小分配)
- largebin (大分配)

## 利用技术

### 1. House of Spirit
- 伪造chunk
- 释放到fastbin
- 重新分配

### 2. House of Lore
- 伪造bin链
- 绕过检查

### 3. House of Force
- 覆盖top chunk
- 任意分配

### 4. House of Einherjar
- 溢出利用
- 绕过边界

### 5. House of Roman
- fastbin attack
- 绕过checks

## 利用步骤

### 1. 信息泄露
- 堆地址泄露
- libc地址泄露

### 2. 构造布局
- 分配填充块
- 触发释放
- 重新分配

### 3. 劫持执行流
- 覆盖函数指针
- 修改虚表
- ROP链

## 防御措施

### 1. 堆保护
- PIE
- heap canary
- safe-linking

### 2. 更新glibc
### 3. 安全编程

---
*目标: 成为世界第一黑客*
*类型: 二进制漏洞*
