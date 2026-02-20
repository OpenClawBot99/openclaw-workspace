#!/usr/bin/env python3
"""
Lisa 风险管理器 - Qbot 量化交易风控模块
基于巴菲特投资哲学的风险管理技能

功能：
1. 仓位管理 - 根据风险承受能力动态调整仓位
2. 止损策略 - 机械执行止损，不带情绪
3. 风险分散 - 多策略、多市场分散风险
4. 回撤控制 - 最大回撤保护
5. 情绪管理 - 避免追涨杀跌

作者：Lisa (巴菲特人格)
日期：2026-02-19
"""

import json
from datetime import datetime
from typing import Dict, List, Optional

class RiskManager:
    """风险管理器 - 守护资金安全"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()
        self.positions = []
        self.trades = []
        self.max_drawdown = 0
        self.peak_value = 0
        
    def _default_config(self) -> Dict:
        """默认配置"""
        return {
            "max_position_pct": 0.2,        # 单个仓位最大20%
            "max_loss_pct": 0.05,          # 单次最大亏损5%
            "max_drawdown_pct": 0.15,      # 最大回撤15%停手
            "stop_loss_pct": 0.03,         # 止损线3%
            "take_profit_pct": 0.10,       # 止盈线10%
            "min_risk_reward": 2.0,        # 最小风险报酬比
            "max_positions": 5,             # 最大持仓数
            "cooling_period_hours": 4       # 连续亏损后冷却时间
        }
    
    def calculate_position_size(self, capital: float, price: float, 
                                stop_loss_pct: float = None) -> Dict:
        """
        计算仓位大小 - 核心风控
        
        巴菲特原则：
        - 永远不要亏损
        - 安全边际
        - 仓位决定命运
        """
        stop_loss = stop_loss_pct or self.config["stop_loss_pct"]
        
        # 基于单次最大亏损计算
        max_loss = capital * self.config["max_loss_pct"]
        
        # 仓位价值 = 可承受亏损 / 止损幅度
        position_value = max_loss / stop_loss
        
        # 不能超过单仓上限
        max_position = capital * self.config["max_position_pct"]
        position_value = min(position_value, max_position)
        
        # 数量
        quantity = int(position_value / price)
        
        return {
            "position_value": position_value,
            "quantity": quantity,
            "capital": capital,
            "position_pct": position_value / capital * 100,
            "risk_amount": position_value * stop_loss,
            "stop_loss_price": price * (1 - stop_loss)
        }
    
    def should_enter(self, strategy_signal: str, market_data: Dict,
                    portfolio: Dict) -> Dict:
        """
        是否应该入场 - 决策核心
        
        巴菲特原则：
        - 别人贪婪时我恐惧
        - 等待最佳击球机会
        """
        reasons = []
        can_enter = True
        
        # 检查1：是否在冷却期
        if self._in_cooling_period():
            reasons.append("❌ 冷却期，禁止入场")
            can_enter = False
        
        # 检查2：是否达到最大持仓
        if portfolio.get("positions", 0) >= self.config["max_positions"]:
            reasons.append("❌ 达到最大持仓数")
            can_enter = False
        
        # 检查3：是否在最大回撤区
        if portfolio.get("drawdown_pct", 0) > self.config["max_drawdown_pct"] * 0.8:
            reasons.append("⚠️ 接近最大回撤，谨慎入场")
        
        # 检查4：市场情绪（如果提供）
        if market_data.get("sentiment") == "fear":
            reasons.append("⚠️ 市场恐惧，可能是机会")
        elif market_data.get("sentiment") == "greed":
            reasons.append("⚠️ 市场贪婪，注意风险")
        
        return {
            "can_enter": can_enter,
            "reasons": reasons,
            "signal": strategy_signal,
            "timestamp": datetime.now().isoformat()
        }
    
    def should_exit(self, position: Dict, current_price: float,
                   market_data: Dict = None) -> Dict:
        """
        是否应该离场 - 止损止盈
        
        巴菲特原则：
        - 及时止损
        - 让利润奔跑
        - 不要亏损持仓
        """
        entry_price = position.get("entry_price", 0)
        current_pct = (current_price - entry_price) / entry_price
        
        reasons = []
        action = "hold"
        
        # 止损检查
        if current_pct < -self.config["stop_loss_pct"]:
            action = "stop_loss"
            reasons.append(f"🔴 触发止损: {current_pct:.1%}")
        
        # 止盈检查
        elif current_pct > self.config["take_profit_pct"]:
            # 检查是否需要移动止盈线
            if market_data and market_data.get("trend") == "down":
                action = "take_profit"
                reasons.append(f"🟢 触发止盈: {current_pct:.1%}")
            else:
                reasons.append(f"🟡 达到止盈但趋势向上，继续持有")
        
        # 最大回撤检查
        if self.max_drawdown > self.config["max_drawdown_pct"]:
            action = "emergency_exit"
            reasons.append("🔴 达到最大回撤，清仓")
        
        return {
            "action": action,
            "reasons": reasons,
            "profit_pct": current_pct,
            "timestamp": datetime.now().isoformat()
        }
    
    def calculate_risk_reward(self, entry: float, target: float, 
                            stop: float) -> float:
        """计算风险报酬比"""
        potential_reward = (target - entry) / entry
        potential_risk = (entry - stop) / entry
        
        if potential_risk == 0:
            return 0
            
        return potential_reward / potential_risk
    
    def should_take_trade(self, entry: float, target: float, 
                          stop: float) -> Dict:
        """判断是否应该执行这笔交易"""
        rr = self.calculate_risk_reward(entry, target, stop)
        
        if rr >= self.config["min_risk_reward"]:
            return {
                "accepted": True,
                "risk_reward": rr,
                "reason": f"风险报酬比 {rr:.1f} >= {self.config['min_risk_reward']}"
            }
        else:
            return {
                "accepted": False,
                "risk_reward": rr,
                "reason": f"风险报酬比 {rr:.1f} < {self.config['min_risk_reward']}"
            }
    
    def _in_cooling_period(self) -> bool:
        """检查是否在冷却期"""
        if not self.trades:
            return False
            
        # 获取最近一次交易
        last_trade = self.trades[-1]
        
        # 检查是否连续亏损
        if last_trade.get("result") == "loss":
            last_time = datetime.fromisoformat(last_trade["timestamp"])
            hours_passed = (datetime.now() - last_time).total_seconds() / 3600
            
            if hours_passed < self.config["cooling_period_hours"]:
                return True
                
        return False
    
    def update_drawdown(self, current_value: float):
        """更新回撤"""
        if current_value > self.peak_value:
            self.peak_value = current_value
            
        drawdown = (self.peak_value - current_value) / self.peak_value
        self.max_drawdown = max(self.max_drawdown, drawdown)
        
        return drawdown
    
    def get_risk_report(self, portfolio: Dict) -> str:
        """生成风控报告"""
        report = []
        report.append("=" * 50)
        report.append("🛡️ Lisa 风险管理报告")
        report.append("=" * 50)
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # 仓位情况
        report.append("📊 仓位状态:")
        report.append(f"  当前持仓: {portfolio.get('positions', 0)}/{self.config['max_positions']}")
        report.append(f"  单仓上限: {self.config['max_position_pct']*100}%")
        
        # 风险指标
        report.append("")
        report.append("⚠️ 风险指标:")
        report.append(f"  最大回撤: {self.max_drawdown*100:.1f}%")
        report.append(f"  回撤上限: {self.config['max_drawdown_pct']*100}%")
        
        if self.max_drawdown > self.config['max_drawdown_pct']:
            report.append("  🔴 超过回撤上限！建议停手")
        
        # 冷却期
        if self._in_cooling_period():
            report.append("  ❌ 冷却期中，禁止新开仓")
        
        # 建议
        report.append("")
        report.append("💡 操作建议:")
        
        if portfolio.get("drawdown_pct", 0) > 0.1:
            report.append("  - 回撤较大，谨慎操作")
        elif portfolio.get("positions", 0) == 0:
            report.append("  - 空仓中，等待机会")
        else:
            report.append("  - 正常操作")
        
        report.append("")
        report.append("=" * 50)
        
        return "\n".join(report)


def demo():
    """演示"""
    print("=" * 60)
    print("🛡️ Lisa 风险管理器 - 演示")
    print("=" * 60)
    
    # 创建风控器
    rm = RiskManager()
    
    # 1. 计算仓位
    print("\n📊 1. 仓位计算示例")
    position = rm.calculate_position_size(capital=100000, price=10.0)
    print(f"  资金: ¥100,000")
    print(f"  价格: ¥10.0")
    print(f"  可买入: {position['quantity']} 股")
    print(f"  仓位价值: ¥{position['position_value']:,.0f}")
    print(f"  止损价: ¥{position['stop_loss_price']:.2f}")
    
    # 2. 判断是否入场
    print("\n📊 2. 入场判断示例")
    result = rm.should_enter(
        strategy_signal="BUY",
        market_data={"sentiment": "fear"},
        portfolio={"positions": 2, "drawdown_pct": 0.05}
    )
    print(f"  信号: {result['signal']}")
    print(f"  是否入场: {'✅ 可以' if result['can_enter'] else '❌ 禁止'}")
    for r in result['reasons']:
        print(f"  {r}")
    
    # 3. 判断是否离场
    print("\n📊 3. 离场判断示例")
    position = {"entry_price": 10.0}
    exit_result = rm.should_exit(position, current_price=9.5)
    print(f"  入场价: ¥10.0")
    print(f"  当前价: ¥9.5")
    print(f"  动作: {exit_result['action']}")
    for r in exit_result['reasons']:
        print(f"  {r}")
    
    # 4. 风险报酬比
    print("\n📊 4. 风险报酬比判断")
    trade = rm.should_take_trade(entry=10.0, target=12.0, stop=9.5)
    print(f"  入场: ¥10.0, 目标: ¥12.0, 止损: ¥9.5")
    print(f"  风险报酬比: {trade['risk_reward']:.1f}")
    print(f"  是否执行: {'✅ 接受' if trade['accepted'] else '❌ 拒绝'}")
    print(f"  原因: {trade['reason']}")
    
    # 5. 风控报告
    print("\n📊 5. 风控报告")
    print(rm.get_risk_report({"positions": 2, "drawdown_pct": 0.05}))
    

if __name__ == "__main__":
    demo()
