# Smart Model Router - 智能模型路由器

智能模型路由器，基于强化学习的探索-利用策略，自动选择最佳模型。

## 重要更新：400错误排除机制

### 排除的错误类型

| 错误代码 | 错误信息 | 处理方式 |
|---------|---------|---------|
| 400 | "User location is not supported" | **立即移除** |
| 400 | "User location is not supported for the API use" | **立即移除** |
| 401 | Unauthorized | 降低评分 |
| 403 | Forbidden | 降低评分 |
| 429 | Rate limit | 冷却期 |
| 500 | Server error | 降低评分 |
| timeout | 超时 | 冷却期 |

### 冷却机制

- **连续3次错误**: 模型进入冷却期（1小时）
- **400位置错误**: 立即移除，需手动恢复
- **冷却期后**: 恢复使用，评分重置

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

## 错误处理增强

### 1. 立即排除的错误

以下错误会立即将模型从候选列表中移除：

```python
# 立即排除的错误
IMMEDIATE_EXCLUDE_ERRORS = [
    (400, "User location is not supported"),
    (400, "location is not supported for the API use"),
]
```

### 2. 冷却期错误

以下错误会导致模型进入冷却期：

```python
# 冷却期错误
COOLDOWN_ERRORS = [
    (429, "Rate limit"),      # 速率限制
    (timeout, "timeout"),    # 超时
    (503, "Service unavailable"), # 服务不可用
]
```

### 3. 冷却期管理

```python
# 冷却期配置
COOLDOWN_DURATION = 3600  # 1小时（秒）

# 模型状态
model_states = {
    "model_name": {
        "status": "active",  # active, cooldown, excluded
        "cooldown_until": None,  # 时间戳
        "consecutive_errors": 0,
    }
}
```

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
    "score": 3.5,
    "status": "active",
    "cooldown_until": null,
    "consecutive_errors": 0
  },
  "minimax-portal/MiniMax-M2.5": {
    "uses": 8,
    "satisfaction_avg": 3.8,
    "speed_avg_ms": 1200,
    "cost_avg": 0.04,
    "error_rate": 0.05,
    "score": 3.3,
    "status": "cooldown",
    "cooldown_until": 1708500000,
    "consecutive_errors": 3
  }
}
```

## 配置

在脚本顶部配置可用模型列表：

```python
AVAILABLE_MODELS = [
    "zai/glm-5",                    # GLM-5
    "zai/glm-4.7",                  # GLM-4.7
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
4. 如果发生错误 → 更新错误计数和应用冷却期
5. 下次会话自动优化选择策略

##进阶配置

调整脚本中的参数：

```python
# 错误处理配置
CONSECUTIVE_ERROR_THRESHOLD = 3  # 连续错误阈值
COOLDOWN_DURATION = 3600        # 冷却期（秒）
IMMEDIATE_EXCLUDE = True        # 立即排除400错误

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
- **400错误（位置不支持）会自动排除**，这是API地区限制问题，不是模型本身问题
