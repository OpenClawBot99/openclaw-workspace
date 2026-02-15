---
name: smart-model-router
description: Intelligent model routing with explore-exploit strategy. Automatically selects the best model for each conversation using reinforcement learning principles (ε-greedy, softmax, UCB). Use when you need to optimize model selection across multiple LLM providers (GLM, MiniMax, etc.) based on performance metrics like response quality, speed, and cost.
---

# Smart Model Router

智能模型路由器，基于强化学习的探索-利用策略，自动选择最佳模型。

## Quick Start

每次新会话开始时运行模型选择脚本：

```bash
python skills/smart-model-router/scripts/select_model.py
```

脚本会输出推荐的模型，然后在对话中使用该模型。

## 策略选择

支持三种智能路由策略，根据数据积累自动选择：

### 1. ε-Greedy (默认)

- **适用场景**：数据量少，需要快速探索
- **机制**：
  - 探索率 ε：初始 0.5，随数据量线性递减至 0.1
  - 以概率 ε 随机探索，以概率 1-ε 选择当前最优
  - 随数据积累，逐渐偏向贪婪（选择最优）

### 2. Softmax (Boltzmann)

- **适用场景**：数据量中等，需要平衡探索和利用
- **机制**：
  - 温度参数 τ：初始 1.0，随数据量线性递减至 0.5
  - 基于模型评分的概率分布选择：P(model) ∝ exp(score/τ)
  - τ 越高，选择越随机；τ 越低，越倾向于高分模型

### 3. UCB (Upper Confidence Bound)

- **适用场景**：数据量充足，追求理论最优
- **机制**：
  - 计算置信区间上界：UCB = μ + c × √(ln(N)/n)
  - 选择 UCB 值最大的模型
  - 平衡均值（利用）和不确定性（探索）

## 性能指标

追踪以下指标来评估模型：

| 指标 | 权重 | 说明 |
|------|--------|------|
| 用户满意度 | 40% | 用户反馈（手动评分或隐式信号） |
| 响应速度 | 20% | 响应时间（毫秒） |
| 成本效率 | 20% | token 消耗 / 成本 |
| 错误率 | 20% | 调用失败、超时、格式错误 |

## 数据存储

模型使用数据存储在 `skills/smart-model-router/state/model_metrics.json`：

```json
{
  "zai/glm-5": {
    "uses": 10,
    "satisfaction_avg": 4.2,
    "speed_avg_ms": 1500,
    "cost_avg": 0.05,
    "error_rate": 0.1,
    "score": 3.5
  },
  "minimax-portal/MiniMax-M2.5": {
    "uses": 8,
    "satisfaction_avg": 3.8,
    "speed_avg_ms": 1200,
    "cost_avg": 0.04,
    "error_rate": 0.05,
    "score": 3.3
  },
  "minimax-portal/MiniMax-M2.1": {
    "uses": 5,
    "satisfaction_avg": 3.5,
    "speed_avg_ms": 1600,
    "cost_avg": 0.03,
    "error_rate": 0.08,
    "score": 3.0
  }
}
```

## 配置

在脚本顶部配置可用模型列表：

```python
AVAILABLE_MODELS = [
    "zai/glm-5",                    # GLM-5
    "minimax-portal/MiniMax-M2.5",  # MiniMax M2.5 (默认)
    "minimax-portal/MiniMax-M2.1",  # MiniMax M2.1
    # 可以添加更多模型：
    # "anthropic/claude-opus-4-6",
    # "openai/gpt-5.1-codex"
]
```

## 手动反馈

可以在对话结束后手动更新模型评分：

```bash
python skills/smart-model-router/scripts/update_score.py --model "zai/glm-5" --satisfaction 5 --speed 1200 --cost 0.03 --error 0
```

参数说明：
- `--model`: 模型 ID
- `--satisfaction`: 满意度评分 (1-5)
- `--speed`: 响应时间 (毫秒)
- `--cost`: 成本 (美元)
- `--error`: 是否出错 (0 或 1)

## 算法详情

详见 [ALGORITHMS.md](references/ALGORITHMS.md) 了解完整算法推导和参数调优。

## 使用流程

1. 新会话开始 → 运行 `select_model.py` 获取推荐模型
2. 使用该模型进行对话
3. 对话结束（或收到用户反馈）→ 运行 `update_score.py` 更新指标
4. 下次会话自动优化选择策略

## 进阶配置

调整脚本中的参数：

```python
# ε-Greedy 参数
EPSILON_START = 0.5      # 初始探索率
EPSILON_MIN = 0.1         # 最小探索率
EPSILON_DECAY = 0.001    # 每次衰减量

# Softmax 参数
TEMPERATURE_START = 1.0    # 初始温度
TEMPERATURE_MIN = 0.5      # 最小温度
TEMPERATURE_DECAY = 0.002  # 每次衰减量

# UCB 参数
UCB_C = 2.0               # 探索系数
```

## 注意事项

- 首次运行所有模型指标为空，会随机选择
- 建议每个模型至少使用 10 次后再观察策略效果
- 可以手动指定策略：`--strategy epsilon`, `--strategy softmax`, `--strategy ucb`
- 数据文件会自动创建，无需手动初始化