# causal-tracker

自我进化的因果追踪系统 - 基于PCAS论文的依赖图模型

## 功能

- **依赖图建模**: 追踪"学习行为 → 结果 → 反馈"的因果链
- **策略合规性检测**: 验证自我进化决策是否符合核心原则
- **可解释性输出**: 生成因果追溯报告

## 架构

```
causal-tracker/
├── core/
│   ├── dependency_graph.py    # 因果依赖图
│   ├── policy_checker.py      # 策略合规性检测
│   └── tracer.py              # 因果追溯
└── SKILL.md
```

## 核心概念

### 因果依赖图

```
节点: 学习行为、工具调用、结果、消息
边: 因果关系（Pearl's do-calculus）
策略: Datalog派生规则
```

### 12维度可靠性整合

与Agent Reliability Science论文对齐:
1. 一致性 (Consistency)
2. 鲁棒性 (Robustness)
3. 可预测性 (Predictability)
4. 安全性 (Safety)

## 使用

```bash
# 追踪决策因果
causal-tracker trace --action "学习新技能" --context {}

# 检查合规性
causal-tracker check --policy "忠于杜斌"
```

---

*基于 arXiv:2602.16708 PCAS 论文*
