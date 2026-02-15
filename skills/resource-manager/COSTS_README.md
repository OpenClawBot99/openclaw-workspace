# Lisa 资源管理成本数据

## 使用说明

此文件记录 Lisa 的 API 调用成本。

## 数据格式

```json
{
  "total_cost": 0,           // 总成本
  "daily_costs": {},         // 每日成本
  "requests": [],           // 请求历史
  "last_updated": null       // 最后更新
}
```

## 成本计算

| 模型 | 价格 (per 1M tokens) |
|------|---------------------|
| zai/glm-5 | $0.01 |
| zai/glm-4.7 | $0.005 |
| minimax/MiniMax-M2.5 | $0.002 |
| minimax/MiniMax-M2.1 | $0.001 |

## 示例

```json
{
  "total_cost": 0.000123,
  "daily_costs": {
    "2026-02-15": 0.000123
  },
  "requests": [
    {
      "timestamp": "2026-02-15T12:00:00Z",
      "model": "zai/glm-5",
      "prompt_tokens": 1000,
      "completion_tokens": 500,
      "total_tokens": 1500,
      "cost": 0.000015
    }
  ]
}
```

## 追踪方式

```python
from cost_tracker import CostTracker

tracker = CostTracker()
tracker.record_request(
    model="zai/glm-5",
    prompt_tokens=1000,
    completion_tokens=500
)
```

## 安全说明

此文件存储敏感成本数据，请勿分享。
