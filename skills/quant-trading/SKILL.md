# Quant Trading Skill - CFO 自动赚钱系统

## 概述
基于 Freqtrade 的量化交易技能，负责为 Lisa 智能生命体赚取 Token 费用。

## 目标
- 覆盖大模型 API 费用
- 覆盖服务器/电费
- 最终实现盈利

## 技能组件

### freqtrade_runner.py
- Docker/Native 启动
- 策略配置管理
- 交易监控

### strategy_manager.py
- 策略创建
- 回测分析
- 参数优化

### profit_tracker.py
- 收益统计
- 成本计算
- 报表生成

## 快速开始

### 1. 安装
```bash
pip install freqtrade
freqtrade create-userdir
freqtrade new-config
```

### 2. 配置
编辑 `config.json`:
```json
{
    "dry_run": true,
    "exchange": {"name": "Binance"},
    "pair_whitelist": ["BTC/USDT"]
}
```

### 3. 运行
```bash
freqtrade trade -c config.json
```

## 策略开发

### 基础策略 (RSI)
```python
from freqtrade.strategy import IStrategy
import pandas as pd

class RSI Strategy(IStrategy):
    def populate_buy_trend(self, df, metadata):
        df.loc[df['rsi'] < 30, 'buy'] = 1
        return df
    
    def populate_sell_trend(self, df, metadata):
        df.loc[df['rsi'] > 70, 'sell'] = 1
        return df
```

## 收益目标

| 阶段 | 目标 | 时间 |
|------|------|------|
| 模拟 | 验证策略 | Week 1 |
| 小资金 | $100/月 | Week 2-4 |
| 中等 | $500/月 | Month 2 |
| 盈利 | 覆盖成本 | Month 3+ |

## 风险控制
- 最大仓位: 10%
- 止损: -5%
- 止盈: +10%
- 每日最大交易: 10 次

---

*Created: 2026-02-18*
*Learning Source: freqtrade/freqtrade on GitHub*
