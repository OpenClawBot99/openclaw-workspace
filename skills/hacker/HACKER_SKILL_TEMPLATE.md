---
name: hacker-skill-template
description: 黑客技能详细模板 - 包含深度技术原理、多场景适配、真实可执行脚本、完整实战指南
---

# 黑客技能详细模板

## 模板理念

**目标：创建可直接用于实战的黑客技能，而非空框架**

---

## 技能结构

```
skill-name/
├── SKILL.md              # 主文档（必需）
├── scripts/              # 可执行脚本（必需）
│   ├── scanner.py        # 检测/扫描脚本
│   ├── exploit.py        # 利用脚本
│   ├── env_setup.py      # 环境搭建脚本
│   └── detector.py       # 检测/防御脚本
├── references/          # 参考资料
│   ├── cve_details.md   # CVE详情
│   ├── techniques.md     # 技术细节
│   ├── bypass_techs.md  # 绕过技术
│   └── cases.md         # 案例分析
└── assets/              # 资源文件
    ├── payloads/        # Payload集合
    └── configs/         # 配置文件
```

---

## SKILL.md 格式规范

### 1. 漏洞/技术概述
```
## 1. 漏洞/技术概述

### 1.1 基本信息
- **漏洞名称**: 
- **CVE编号**: 
- **严重程度**: Critical/High/Medium/Low
- **影响版本**: 
- **利用难度**: 简单/中等/困难

### 1.2 漏洞描述
[详细描述漏洞原理，1-2段]

### 1.3 影响范围
[影响哪些系统/应用/版本]
```

### 2. 技术原理（必须详细深入）
```
## 2. 技术原理

### 2.1 底层机制
[详细的底层原理分析]

### 2.2 代码分析
```c
// 示例代码（有实际注释）
void vulnerable_function(char *input) {
    char buffer[100];
    // 漏洞：无边界检查
    strcpy(buffer, input);
}
```

### 2.3 数据流/内存布局
[使用ASCII图或表格展示]
```

### 3. 漏洞识别
```
## 3. 漏洞识别

### 3.1 代码特征
```c
// 危险函数列表
- strcpy()     // 无边界检查
- strcat()    // 无边界检查
- sprintf()   // 格式化字符串
- gets()      // 极度危险
```

### 3.2 自动化检测
[检测脚本使用示例]
```

### 4. 利用技术（必须包含真实可执行代码）
```
## 4. 利用技术

### 4.1 利用步骤
[详细步骤，每步都有说明]

### 4.2 基础利用
```python
#!/usr/bin/env python3
"""
功能：xxx利用脚本
用法：python exploit.py <target>
"""
import sys

def exploit(target):
    # 具体实现
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python exploit.py <target>")
        sys.exit(1)
    exploit(sys.argv[1])
```

### 4.3 高级利用
[更复杂场景的利用]
```

### 5. 场景适配（必须详细）
```
## 5. 场景适配

### 5.1 不同操作系统
| 场景 | 利用差异 | 注意事项 |
|------|----------|----------|
| Linux | xxx | 需要xxx |
| Windows | xxx | 需要xxx |
| macOS | xxx | 需要xxx |

### 5.2 不同权限
| 权限 | 可用技术 | 限制 |
|------|----------|------|
| 普通用户 | xxx | 无法xxx |
| ROOT | xxx | 无限制 |

### 5.3 不同网络环境
| 环境 | 利用方式 | 示例 |
|------|----------|------|
| 内网 | 直接连接 | 192.168.1.x |
| 外网 | 反弹Shell | 公网IP |
| 隔离网络 | 定时任务 | 无外网 |

### 5.4 不同目标类型
| 目标 | 攻击差异 |
|------|----------|
| Web应用 | xxx |
| 二进制程序 | xxx |
| 数据库 | xxx |
```

### 6. 绕过技术
```
## 6. 绕过技术

### 6.1 WAF绕过
| WAF类型 | 绕过技术 | 示例 |
|---------|----------|------|
| Cloudflare | xxx | xxx |
| ModSecurity | xxx | xxx |

### 6.2 防护机制绕过
| 机制 | 绕过方法 |
|------|----------|
| ASLR | xxx |
| DEP | xxx |
| Canary | xxx |
```

### 7. 防御与检测
```
## 7. 防御与检测

### 7.1 代码修复
```c
// 修复示例
void safe_function(char *input) {
    char buffer[100];
    // 修复：使用安全函数
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}
```

### 7.2 防御规则
[检测规则示例]

### 7.3 应急响应
[发现被攻击后的处理流程]
```

### 8. 实战案例
```
## 8. 实战案例

### 8.1 CVE-XXXX-XXXXX分析
- **影响版本**: xxx
- **环境搭建**: [Docker/配置]
- **复现步骤**: [详细步骤]
- **利用过程**: [截图/日志]
```

### 9. 参考资源
```
## 9. 参考资源

- [漏洞公告]
- [技术分析]
- [相关工具]
- [相关CVE]
```

---

## 脚本规范

### 必需脚本模板

#### scanner.py
```python
#!/usr/bin/env python3
"""
漏洞扫描脚本
功能：检测目标是否存在xxx漏洞
用法：python scanner.py <target>
"""

import sys
import argparse

def scan(target):
    """扫描逻辑"""
    pass

def main():
    parser = argparse.ArgumentParser(description='xxx漏洞扫描器')
    parser.add_argument('target', help='目标地址')
    parser.add_argument('-p', '--port', default=80, help='端口')
    args = parser.parse_args()
    
    result = scan(f"{args.target}:{args.port}")
    if result:
        print(f"[+] 发现漏洞: {result}")
    else:
        print("[-] 未发现漏洞")

if __name__ == "__main__":
    main()
```

#### exploit.py
```python
#!/usr/bin/env python3
"""
漏洞利用脚本
功能：利用xxx漏洞获取shell
用法：python exploit.py <target> <port>
"""

import sys
import socket

def exploit(target, port):
    """利用逻辑"""
    pass

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"用法: {sys.argv[0]} <target> <port>")
        sys.exit(1)
    exploit(sys.argv[1], int(sys.argv[2]))
```

---

## 质量检查清单

### ✅ 必须满足
- [ ] 至少包含1个可运行脚本
- [ ] 技术原理详细到可理解
- [ ] 覆盖3种以上场景
- [ ] 包含防御/检测方案
- [ ] 有实际案例或CVE引用

### ✅ 场景覆盖
- [ ] 不同OS（Windows/Linux/macOS）
- [ ] 不同权限（ROOT/普通用户）
- [ ] 不同网络（内网/外网/隔离）
- [ ] 不同目标类型（Web/二进制/服务）

### ✅ 代码质量
- [ ] 脚本可运行
- [ ] 有错误处理
- [ ] 有使用说明
- [ ] 有参数说明

---

## 创建流程

1. **深度研究** → 搜索CVE、论文、真实案例
2. **场景分析** → 梳理不同环境下的差异
3. **代码实现** → 编写可执行脚本
4. **测试验证** → 本地测试通过
5. **文档完善** → 按模板格式整理

---

*目标：创建可直接用于实战的黑客技能*
