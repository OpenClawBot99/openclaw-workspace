# Automaton 本地化研究

## 项目概述

Automaton是一个"自我盈利、自我复制、自我改进"的AI代理系统。

### 核心特性
- 自我盈利：自己赚钱付算力费
- 自我复制：生成"孩子"
- 自我改进：实时修改自己的代码
- 生存机制：没钱=死亡

---

## 架构分析

### 核心技术栈
| 组件 | 原版 | 中国可用替代 |
|------|------|-------------|
| **LLM** | Claude Opus 4.6, GPT-5.2 | GLM-5, MiniMax M2.5 |
| **区块链** | Ethereum/Base | 暂不需要 |
| **支付** | 稳定币 | 支付宝/微信/人民币 |
| **服务器** | Conway Cloud | 国内云服务器 |
| **钱包** | SIWE | 本地账户系统 |

### 模块结构
```
src/
├── agent/          # ReAct循环
├── conway/         # API客户端
├── heartbeat/      # 定时任务
├── identity/       # 钱包管理
├── self-mod/       # 自我修改
├── survival/       # 生存机制
└── skills/         # 技能系统
```

---

## 本地化方案

### 1. 替换LLM为国内模型

```python
# 原版使用Claude/GPT
# 替换为GLM-5
LLM_CONFIG = {
    "provider": "zhipuai",
    "model": "glm-5",
    "api_key": "your-key"
}
```

### 2. 替换支付系统

```python
# 原版使用稳定币
# 替换为人民币计费
PAYMENT_CONFIG = {
    "type": "credit",
    "currency": "CNY",
    "balance": 1000,  # 初始额度
    "payment_method": "local"  # 本地计费
}
```

### 3. 替换服务器

```python
# 原版使用Conway Cloud
# 替换为国内云服务器
SERVER_CONFIG = {
    "provider": "aliyun",  # 或腾讯云/华为云
    "region": "cn-hangzhou",
    " specs": "ecs.t6"
}
```

### 4. 移除区块链

```python
# 移除以太坊相关功能
IDENTITY_CONFIG = {
    "type": "local",
    "auth": "password"  # 本地账号密码
}
```

---

## 生存机制适配

### 原版四级生存
| 级别 | 余额 | 行为 |
|------|------|------|
| normal | >100 | 全功能 |
| low_compute | 20-100 | 降级模型 |
| critical | 1-20 | 最小化运行 |
| dead | 0 | 停止 |

### 本地化版本
```python
SURVIVAL_TIERS = {
    "normal": {"balance": ">100元", "model": "glm-5"},
    "low_compute": {"balance": "20-100元", "model": "glm-4"},
    "critical": {"balance": "1-20元", "model": "glm-4-flash"},
    "dead": {"balance": "0元", "action": "暂停"}
}
```

---

## 技能系统

### 原版技能格式
```yaml
name: skill-name
description: 技能描述
actions:
  - name: action1
    tool: bash
    command: ls
```

### 适配中文技能
```yaml
name: 文件操作
description: 本地文件管理
动作:
  - name: 列出文件
    工具: bash
    命令: dir
```

---

## 部署步骤

### 1. 准备环境
```bash
# 服务器（国内）
阿里云/腾讯云 ECS

# Python环境
conda create -n automaton python=3.10
pip install zhipuai openai flask
```

### 2. 核心代码改造
- 替换LLM调用
- 替换支付系统
- 本地化存储
- 中文化

### 3. 配置
```yaml
llm:
  provider: zhipuai
  model: glm-5

payment:
  type: credit
  initial: 1000

server:
  provider: aliyun
```

---

## 创新机会

### 1. 微信/支付宝集成
- 自动充值
- 支付接口

### 2. 中文LLM优化
- 针对GLM提示词优化
- 中文技能库

### 3. 本土化功能
- 接入钉钉/飞书
- 微信公众号/小程序

### 4. 监管合规
- 内容审核
- 数据本地化
- 实名认证

---

## 风险与挑战

| 风险 | 应对 |
|------|------|
| API成本 | 严格预算控制 |
| 模型限制 | 多模型备用 |
| 合规风险 | 内容审核 |
| 技术复杂性 | 分阶段实现 |

---

## 参考资源

- GitHub: https://github.com/Conway-Research/automaton
- Conway Cloud: https://app.conway.tech

---

*学习时间: 2026-02-21*
*目标: 本地化部署自我进化AI*
