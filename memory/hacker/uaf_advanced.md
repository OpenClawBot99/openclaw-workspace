# UAF (Use-After-Free) 漏洞深度指南

## 漏洞概述

### 基本信息
- **漏洞名称**: Use-After-Free (UAF)
- **严重程度**: Critical
- **影响**: 代码执行
- **利用难度**: 中等

### 漏洞原理
UAF是一种内存漏洞，程序在释放内存后继续使用该内存指针。

## 技术原理

### 内存分配与释放
```c
char *ptr = (char *)malloc(100);
// 使用ptr...
free(ptr);
// 漏洞：ptr未置NULL
strcpy(ptr, "attack"); // 使用已释放内存！
```

### 内存布局
```
堆块A: [元数据][数据]
        ↑
       ptr指向这里

释放后:
堆块A: [已释放][旧数据]
        ↑
       ptr仍然指向这里（悬空指针）

重新分配:
堆块A: [新数据][新数据]
        ↑
       ptr指向新数据（被覆盖）
```

## 利用技术

### 1. 堆风水
```python
# 构造堆布局
alloc(0x100)  # chunk A
alloc(0x100)  # chunk B
free(A)
alloc(0x100)  # 可能复用A
```

### 2. 浏览器UAF
```javascript
var arr = [1.1, 2.2];
arr = null;  // 释放
gc();        // 触发GC
// UAF: 访问已释放的数组
```

## 场景适配

### 不同浏览器
| 浏览器 | 特点 |
|--------|------|
| Chrome | V8引擎，复杂GC |
| Firefox | SpiderMonkey |
| IE | 旧版简单 |

### 不同权限
| 权限 | 利用差异 |
|------|----------|
| 沙箱内 | 需沙箱逃逸 |
| 沙箱外 | 直接RCE |

## 防御

### 代码修复
```c
// 安全的内存管理
free(ptr);
ptr = NULL;  // 置NULL防止悬空指针

// 使用智能指针
std::unique_ptr<char[]> ptr(new char[100]);
```

### 缓解措施
- 内存保护: Safe Unlinking
- 堆隔离: Heap Hard监控: ASanening
- /MSan

---
*学习时间: 2026-02-21*
*目标: 成为世界第一黑客*
