# Smart Model Router

智能模型路由器 - 基于强化学习的探索-利用策略，自动选择最佳 LLM 模型。

---

## 快速开始

1. **选择模型**：
   ```bash
   python scripts/select_model.py
   ```

2. **在对话中使用**：
   ```
   /model zai/glm-4.7
   ```

3. **更新评分**（对话结束后可选）：
   ```bash
   python scripts/update_score.py --model "zai/glm-4.7" --satisfaction 5
   ```

---

## 支持的模型

- ✅ zai/glm-5（GLM-5）
- ✅ zai/glm-4.7（GLM-4.7）
- ✅ minimax-portal/MiniMax-M2.5
- ✅ minimax-portal/MiniMax-M2.1
- ➕ 可扩展添加更多模型

---

## 策略选择

| 策略 | 自动触发条件 | 说明 |
|--------|-------------|------|
| ε-Greedy | 使用次数 < 20 | 快速随机探索 |
| Softmax | 20 ≤ 次数 < 100 | 基于评分概率选择 |
| UCB | 次数 ≥ 100 | 置信区间上界最优 |

---

## 性能指标

- **用户满意度**（40%）：1-5 分
- **响应速度**（20%）：首字时间
- **成本效率**（20%）：token 消耗
- **错误率**（20%）：失败、超时、格式错误

---

## 文件结构

```
smart-model-router/
├── SKILL.md                    # 技能主文档
├── examples.md                 # 使用示例
├── scripts/
│   ├── select_model.py          # 模型选择器
│   └── update_score.py         # 评分更新器
├── references/
│   └── ALGORITHMS.md          # 算法详解
└── state/                     # 数据存储（自动生成）
    ├── model_metrics.json       # 模型指标
    └── metadata.json          # 元数据
```

---

## 详细文档

- [SKILL.md](SKILL.md) - 完整使用说明
- [examples.md](examples.md) - 实战示例
- [references/ALGORITHMS.md](references/ALGORITHMS.md) - 数学推导

---

## 特点

✅ **智能探索**：基于强化学习自动优化
✅ **自动切换**：随数据积累调整策略
✅ **多维度评估**：平衡质量、速度、成本
✅ **可扩展**：轻松添加新模型
✅ **理论保证**：UCB 策略有最优性证明

---

Made with 🧠 for OpenClaw
