---
name: hacker-skill-template
description: 黑客技能标准模板 - 包含详细原理、可执行脚本、真实POC、实战步骤。用于创建可实际使用的黑客技能。
---

# 黑客技能标准模板

## 模板说明

本模板用于创建详细、可使用的黑客技能。每个技能应包含：
- 详细原理分析
- 可执行脚本
- 真实POC/Exploit
- 实战步骤
- 环境搭建指南
- 防御与检测

---

## 技能结构

```
skill-name/
├── SKILL.md              # 主文档（必需）
├── scripts/              # 可执行脚本
│   ├── poc.py           # POC示例
│   ├── exploit.py       # Exploit示例
│   └── scanner.py       # 扫描工具
├── references/          # 参考资料
│   ├── cve_details.md   # CVE详情
│   ├── techniques.md    # 技术细节
│   └── cases.md         # 案例分析
└── assets/              # 资源文件
    ├── payloads/        # Payload集合
    └── templates/       # 模板文件
```

---

## SKILL.md 格式规范

### 1. 简介
- 漏洞/技术名称
- 严重程度
- 影响范围
- 利用难度

### 2. 技术原理（必须详细）
- 底层机制
- 数据流分析
- 内存布局（如果是二进制）
- 代码流程

 漏洞识别### 3.
- 特征代码
- Fuzzing方法
- 检测工具

### 4. 利用技术（必须包含代码）
- 触发条件
- 利用步骤
- 完整POC代码
- 调试过程

### 5. 实战案例
- 真实CVE分析
- 环境搭建
- 复现步骤
- 注意事项

### 6. 防御与检测
- 代码层面修复
- 防护机制
- 检测规则
- 安全配置

### 7. 参考资源
- 相关CVE
- 技术文档
- 开源项目

---

## 示例：UAF技能内容大纲

### 1. 简介
- Use-After-Free漏洞
- 严重程度：Critical
- 影响：代码执行

### 2. 技术原理
#### 2.1 堆内存管理
- malloc/free机制
- chunk结构
- bin链表

#### 2.2 UAF漏洞原理
- 释放后继续使用
- 内存被重新分配
- 覆盖敏感数据

### 3. 漏洞识别
#### 3.1 代码模式
```c
char *p = malloc(100);
free(p);
// 漏洞：p未置NULL
strcpy(p, "attack"); // UAF
```

#### 3.2 检测工具
- AddressSanitizer
- Valgrind

### 4. 利用技术
#### 4.1 堆风水
```python
# 堆风水布局示例
def heap_feng_shui():
    # 1. 分配多个chunk
    chunks = [alloc(0x100) for _ in range(10)]
    # 2. 释放特定chunk
    free(chunks[5])
    # 3. 重新分配控制内容
    payload = b'A' * 0x100 + pack_ptr(shellcode_addr)
    alloc(0x100, payload)
```

#### 4.2 浏览器UAF利用
```javascript
// Chrome V8 UAF POC
var arr = [1.1, 2.2];
var fake = {};
arr[0] = 1.1;
collect();
arr[0] = MyExploit; // UAF
```

### 5. 实战案例
#### 5.1 CVE-2021-XXXXX分析
- 影响版本
- 环境搭建（Docker）
- 复现步骤
- 调试方法

### 6. 防御
- 安全释放（置NULL）
- 堆保护（Safe Linking）
- 内存安全语言

---

## 关键要求

### ✅ 必须包含
1. **可运行代码** - 至少一个可执行的POC
2. **详细原理** - 能让人理解底层机制
3. **环境说明** - 如何搭建测试环境
4. **防御方案** - 如何防护和检测

### ❌ 避免
1. 仅列出工具名称
2. 无代码的原理描述
3. 缺少实际应用的场景
4. 无参考价值的空框架

---

## 创建流程

1. 理解技术细节
2. 搜索真实CVE/POC
3. 编写可执行脚本
4. 整理参考资料
5. 测试验证
6. 完善文档

---

*目标：创建可实际用于实战的黑客技能*
