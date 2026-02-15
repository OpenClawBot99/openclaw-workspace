# 智能模型路由器 - 使用示例

本文档展示如何在实际使用中应用智能模型路由器。

---

## 基础使用流程

### 1. 新会话开始时选择模型

```bash
# 自动选择策略（推荐）
python skills/smart-model-router/scripts/select_model.py

# 输出示例：
# ============================================================
# 当前模型使用情况：
#   zai/glm-5: 使用 10 次, 评分 3.50
#   minimax-portal/MiniMax-M2.5: 使用 8 次, 评分 3.30
#   minimax-portal/MiniMax-M2.1: 使用 5 次, 评分 3.00
#   总使用次数: 23
# ============================================================
# [Auto策略] 数据量中等 (23), 使用 Softmax
# [Softmax] 温度 τ=0.94: 选择 zai/glm-5 (评分=3.50, 概率=45.2%)
#
# ✅ 推荐使用: zai/glm-5
#
# 命令: /model zai/glm-5
```

### 2. 在 OpenClaw 中切换模型

```
/model zai/glm-5
```

或简写：
```
/model glm
```

### 3. 对话结束（可选）后更新评分

```bash
# 更新 GLM 的表现
python skills/smart-model-router/scripts/update_score.py \
  --model "zai/glm-5" \
  --satisfaction 5 \
  --speed 1200 \
  --cost 0.03 \
  --error 0

# 输出示例：
#   满意度: 4.20 → 4.30
#   速度: 1500ms → 1430ms
#   成本: $0.0500 → $0.0400
#   错误率: 10.0% → 7.0%
#
# ✅ zai/glm-5 指标已更新
#   使用次数: 11
#   综合评分: 4.00 / 5.0
```

---

## 手动指定策略

### 强制使用 ε-Greedy

```bash
python skills/smart-model-router/scripts/select_model.py --strategy epsilon
```

### 强制使用 Softmax

```bash
python skills/smart-model-router/scripts/select_model.py --strategy softmax
```

### 强制使用 UCB

```bash
python skills/smart-model-router/scripts/select_model.py --strategy ucb
```

---

## 自动化使用建议

### 创建快捷脚本

在 `~/.bashrc` 或 `~/.zshrc` 中添加：

```bash
# 模型选择快捷命令
alias smr="python ~/workspace/skills/smart-model-router/scripts/select_model.py"
alias smru="python ~/workspace/skills/smart-model-router/scripts/update_score.py"
```

### 使用时

```bash
# 选择模型
smr

# 更新评分
smru --model "zai/glm-5" --satisfaction 5
```

---

## 集成到 OpenClaw 工作流

### 方式 1：手动触发

每次新对话前手动运行 `select_model.py`

**优点**：完全控制，可见决策过程
**缺点**：需要手动操作

### 方式 2：Cron 自动化

设置定时任务，每小时或每天自动选择模型：

```bash
# 添加 cron 任务（示例：每小时检查一次）
openclaw cron add --name "model-rotation" \
  --schedule "every 1h" \
  --sessionTarget isolated \
  --payload '{"kind": "agentTurn", "message": "运行模型选择脚本：python skills/smart-model-router/scripts/select_model.py"}'
```

### 方式 3：Heartbeat 集成

在 `HEARTBEAT.md` 中添加：

```markdown
## 模型轮换

每 4 小时运行一次模型选择脚本：
```bash
python skills/smart-model-router/scripts/select_model.py
```

如果需要，在对话结束后更新评分。
```

---

## 评估策略效果

### 查看当前指标

```bash
# 选择模型时会显示所有模型的使用情况
python skills/smart-model-router/scripts/select_model.py
```

### 评估标准

1. **评分趋势**：随时间推移，评分应稳定或上升
2. **使用均衡**：避免某个模型完全不被使用
3. **响应质量**：根据实际感受调整权重和参数

### 调整权重

如果觉得某个指标更重要，修改 `scripts/select_model.py` 中的 `WEIGHTS`：

```python
WEIGHTS = {
    "satisfaction": 0.2,
    "speed": 0.2,
    "cost": 0.5,    # 成本优先
    "error": 0.1
}
```

---

## 多模型扩展

### 添加新模型

编辑 `scripts/select_model.py`：

```python
AVAILABLE_MODELS = [
    "zai/glm-5",
    "zai/glm-4.7",
    "minimax-portal/MiniMax-M2.5",
    "minimax-portal/MiniMax-M2.1",
    # 可以添加更多模型：
    # "anthropic/claude-opus-4-6",
    # "openai/gpt-5.1-codex"
]
```

### 确保模型可用

运行：

```bash
openclaw models list
```

确认模型 ID 正确。

---

## 常见问题

### Q: 为什么首次运行总是随机选择？

A: 首次运行所有模型的指标为空，评分相同。各策略会随机选择以开始收集数据。

### Q: 多少次使用后策略稳定？

A: 建议：
- ε-Greedy: 20+ 次后 ε 稳定
- Softmax: 50+ 次后温度稳定
- UCB: 100+ 次后置信区间稳定

### Q: 如何重置数据？

A: 删除 `state/model_metrics.json` 和 `state/metadata.json`：

```bash
rm skills/smart-model-router/state/model_metrics.json
rm skills/smart-model-router/state/metadata.json
```

---

## 高级技巧

### A/B 测试

同时运行两个策略，比较效果：

```bash
# 终端 1：使用 ε-Greedy
python select_model.py --strategy epsilon

# 终端 2：使用 Softmax
python select_model.py --strategy softmax
```

### 响应质量量化

定义客观指标：

```bash
# 代码准确性：运行测试用例
python update_score.py --model "zai/glm-5" --error 0  # 通过测试

# 文本质量：使用相似度评分
python update_score.py --model "zai/glm-5" --satisfaction 4.5  # 相似度 90%
```

### 成本优化

对于敏感场景，提高成本权重：

```python
WEIGHTS = {
    "satisfaction": 0.2,
    "speed": 0.2,
    "cost": 0.5,    # 成本优先
    "error": 0.1
}
```

---

## 总结

| 策略 | 探索智能度 | 计算复杂度 | 理论保证 | 适用阶段 |
|--------|-------------|-------------|-----------|---------|
| ε-Greedy | 低 | O(1) | 无 | 早期 |
| Softmax | 中 | O(K) | 无 | 中期 |
| UCB | 高 | O(K) | 有 | 后期 |

选择策略的关键：
1. **数据量**：少 → 多探索，多 → 利用
2. **模型差异**：大 → 随机探索，小 → 智能探索
3. **长期目标**：短期 → 快速探索，长期 → 渐进最优

---

更多问题？查看 SKILL.md 和 references/ALGORITHMS.md。