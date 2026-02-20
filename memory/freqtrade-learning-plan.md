# Freqtrade 量化交易学习计划

## 概述
Freqtrade - 免费开源加密货币交易机器人
- 语言: Python 3.11+
- 支持: 100+ 交易所
- 特性: 回测、Plot、策略优化、机器学习

---

## 支持的交易所
- Binance ✅
- Bybit ✅
- OKX ✅
- Gate.io ✅
- Hyperliquid (去中心化) ✅

---

## 核心功能
1. **Dry-run** - 模拟交易不花钱
2. **Backtesting** - 回测策略
3. **FreqAI** - 机器学习自动优化
4. **WebUI** - 网页控制
5. **Telegram** - Telegram 控制

---

## 快速开始

### Docker 部署 (推荐)
```bash
docker run -d --name freqtrade freqtrade/freqtrade:latest
```

### Native 安装
```bash
pip install freqtrade
freqtrade create-userdir
freqtrade new-config
```

---

## 命令列表

| 命令 | 功能 |
|------|------|
| trade | 启动交易机器人 |
| new-config | 创建配置 |
| new-strategy | 创建新策略 |
| download-data | 下载历史数据 |
| backtesting | 回测 |
| hyperopt | 参数优化 |
| list-strategies | 列出可用策略 |
| show-trades | 显示交易记录 |
| webserver | 启动网页UI |

---

## 学习路径 (1周)

### Day 1: 环境搭建
- [ ] 安装 Docker / pip
- [ ] 启动 freqtrade
- [ ] 配置 API key (模拟)
- [ ] WebUI 访问

### Day 2: 核心概念
- [ ] 理解 config.json
- [ ] 理解策略结构
- [ ] 理解 OHLCV 数据

### Day 3: 内置策略
- [ ] 运行默认策略
- [ ] 分析交易日志
- [ ] 理解买入/卖出信号

### Day 4: 回测
- [ ] 下载历史数据
- [ ] 运行回测
- [ ] 分析回测结果

### Day 5: 创建策略
- [ ] 编写第一个策略
- [ ] 理解技术指标 (RSI, MACD)
- [ ] 模拟交易测试

### Day 6-7: 进阶
- [ ] FreqAI 机器学习
- [ ] 参数优化
- [ ] 实盘准备

---

## 策略模板

```python
class MyStrategy(IStrategy):
    # 买入信号
    def populate_buy_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        dataframe.loc[
            (dataframe['rsi'] < 30),  # RSI < 30
            'buy'
        ] = 1
        return dataframe
    
    # 卖出信号
    def populate_sell_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        dataframe.loc[
            (dataframe['rsi'] > 70),  # RSI > 70
            'sell'
        ] = 1
        return dataframe
```

---

## 注意事项
⚠️ 风险提示
- 仅用于教育目的
- 不要投入承受不起损失的资金
- 始终先做 Dry-run 测试

---

*Created: 2026-02-18*
*Source: GitHub freqtrade/freqtrade*
