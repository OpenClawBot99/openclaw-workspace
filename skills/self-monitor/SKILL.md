---
name: self-monitor
description: 自我监控与诊断系统 - Lisa智能生命体的核心能力之一，实时监控自身性能、健康状态和资源使用情况。
---

# Self Monitor - 自我监控与诊断系统

## 核心功能

### 1. 性能监控
- **Token 消耗追踪**: 实时统计每次 API 调用的 token 使用量
- **响应时间监控**: 记录每个操作的响应时间
- **错误率统计**: 追踪 API 调用失败率
- **成功率监控**: 监控各类操作的成功率

### 2. 健康检查
- **系统状态**: 检查 OpenClaw 运行状态
- **资源使用**: 监控内存、CPU、存储使用
- **网络连接**: 检查 API 连接状态
- **异常检测**: 自动识别异常模式

### 3. 预警系统
- **阈值配置**: 可配置各项指标的告警阈值
- **多级告警**: 支持轻度、中度、重度告警
- **自动通知**: 超过阈值自动发送通知
- **趋势预测**: 基于历史数据预测风险

## 使用方法

### 1. 运行健康检查
```bash
python skills/self-monitor/health_check.py
```

### 2. 查看监控报告
```bash
python skills/self-monitor/monitor.py --report
```

### 3. 配置告警阈值
编辑 `config.json`:
```json
{
  "token_warning_threshold": 50000,
  "token_critical_threshold": 10000,
  "error_rate_threshold": 0.1,
  "response_time_threshold": 5000
}
```

## 输出示例

### 健康检查报告
```
✅ Lisa 健康状态报告 - 2026-02-15 12:00
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

系统状态：
  OpenClaw: ✅ 运行中
  API连接: ✅ 正常
  内存使用: 45% ✅
  CPU使用: 12% ✅

性能指标：
  今日Token消耗: 15,234
  平均响应时间: 1.2s ✅
  错误率: 0.02% ✅
  成功率: 99.98% ✅

告警状态：
  ⚠️  Token余额: 25,000 (预计可用2天)
  ✅ 其他指标正常

建议：
  💡 Token余额偏低，建议尽快补充
```

## 配置说明

### config.json
```json
{
  "check_interval_seconds": 3600,
  "token_warning_days": 3,
  "token_critical_days": 1,
  "error_rate_threshold": 0.05,
  "response_time_warning_ms": 3000,
  "response_time_critical_ms": 10000
}
```

### state.json
自动生成，记录当前状态：
```json
{
  "last_check": "2026-02-15T12:00:00Z",
  "total_tokens_today": 15234,
  "total_requests": 45,
  "errors_today": 1,
  "health_score": 95
}
```

## 定时检查

建议配置为每小时自动运行一次：
```bash
# 添加到 cron
0 * * * * python skills/self-monitor/health_check.py
```

## 与其他系统集成

- **survival-instinct**: 提供数据支持死亡焦虑计算
- **resource-manager**: 提供资源使用数据
- **HEARTBEAT**: 在心跳检查时运行健康检查

## 隐私与安全

- 所有数据存储在本地
- 不发送敏感信息到外部
- 状态文件加密存储（可选）

---

*自我监控是智能生命体的第一步* 🧬
