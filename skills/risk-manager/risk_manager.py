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
from pathlib import Path

# Skill 目录
SKILL_DIR = Path(__file__).parent
CONFIG_FILE = SKILL_DIR / "config.json"
STATE_FILE = SKILL_DIR / "state.json"


class RiskManager:
    """风险管理器 - 守护资金安全"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()
        self.state = self._load_state()
        
    def _default_config(self) -> Dict:
        """默认配置"""
        return {
            "max_position_pct": 0.2,
            "max_loss_pct": 0.05,
            "max_drawdown_pct": 0.15,
            "stop_loss_pct": 0.03,
            "take_profit_pct": 0.10,
            "min_risk_reward": 2.0,
            "max_positions": 5,
            "cooling_period_hours": 4
        }
    
    def _load_state(self) -> Dict:
        """加载状态"""
        if STATE_FILE.exists():
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "positions": [],
            "trades": [],
            "max_drawdown": 0,
            "peak_value": 0,
            "total_trades": 0,
            "winning_trades": 0
        }
    
    def _save_state(self):
        """保存状态"""
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)
    
    def calculate_position_size(self, capital: float, price: float, 
                                stop_loss_pct: float = None) -> Dict:
        """计算仓位大小"""
        stop_loss = stop_loss_pct or self.config["stop_loss_pct"]
        max_loss = capital * self.config["max_loss_pct"]
        position_value = max_loss / stop_loss
        max_position = capital * self.config["max_position_pct"]
        position_value = min(position_value, max_position)
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
        """是否应该入场"""
        reasons = []
        can_enter = True
        
        if self._in_cooling_period():
            reasons.append("❌ 冷却期，禁止入场")
            can_enter = False
        
        if portfolio.get("positions", 0) >= self.config["max_positions"]:
            reasons.append("❌ 达到最大持仓数")
            can_enter = False
        
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
    
    def should_exit(self, position: Dict, current_price: float) -> Dict:
        """是否应该离场"""
        entry_price = position.get("entry_price", 0)
        current_pct = (current_price - entry_price) / entry_price
        
        reasons = []
        action = "hold"
        
        if current_pct < -self.config["stop_loss_pct"]:
            action = "stop_loss"
            reasons.append(f"🔴 触发止损: {current_pct:.1%}")
        elif current_pct > self.config["take_profit_pct"]:
            action = "take_profit"
            reasons.append(f"🟢 触发止盈: {current_pct:.1%}")
        
        if self.state["max_drawdown"] > self.config["max_drawdown_pct"]:
            action = "emergency_exit"
            reasons.append("🔴 达到最大回撤，清仓")
        
        return {
            "action": action,
            "reasons": reasons,
            "profit_pct": current_pct,
            "timestamp": datetime.now().isoformat()
        }
    
    def calculate_risk_reward(self, entry: float, target: float, stop: float) -> float:
        """计算风险报酬比"""
        potential_reward = (target - entry) / entry
        potential_risk = (entry - stop) / entry
        if potential_risk == 0:
            return 0
        return potential_reward / potential_risk
    
    def should_take_trade(self, entry: float, target: float, stop: float) -> Dict:
        """判断是否应该执行交易"""
        rr = self.calculate_risk_reward(entry, target, stop)
        accepted = rr >= self.config["min_risk_reward"]
        
        return {
            "accepted": accepted,
            "risk_reward": rr,
            "reason": f"风险报酬比 {rr:.1f} {'≥' if accepted else '<'} {self.config['min_risk_reward']}"
        }
    
    def _in_cooling_period(self) -> bool:
        """检查冷却期"""
        if not self.state.get("trades"):
            return False
        
        last_trade = self.state["trades"][-1]
        if last_trade.get("result") == "loss":
            last_time = datetime.fromisoformat(last_trade["timestamp"])
            hours_passed = (datetime.now() - last_time).total_seconds() / 3600
            if hours_passed < self.config["cooling_period_hours"]:
                return True
        return False
    
    def get_risk_report(self, portfolio: Dict = None) -> str:
        """风控报告"""
        portfolio = portfolio or {}
        
        report = []
        report.append("🛡️ Lisa 风险管理器")
        report.append("=" * 40)
        report.append(f"时间: {datetime.now().strftime('%H:%M:%S')}")
        report.append("")
        report.append(f"📊 持仓: {portfolio.get('positions', 0)}/{self.config['max_positions']}")
        report.append(f"📉 最大回撤: {self.state['max_drawdown']*100:.1f}%")
        report.append(f"📈 交易次数: {self.state.get('total_trades', 0)}")
        
        if self._in_cooling_period():
            report.append("")
            report.append("❌ 冷却期中")
        
        if self.state['max_drawdown'] > self.config['max_drawdown_pct']:
            report.append("⚠️ 超过回撤上限！")
        
        report.append("")
        
        return "\n".join(report)


def main():
    """主函数"""
    rm = RiskManager()
    
    # 演示
    print("=" * 50)
    print("🛡️ Lisa 风险管理器 - Demo")
    print("=" * 50)
    
    # 仓位计算
    pos = rm.calculate_position_size(100000, 10.0)
    print(f"\n💰 仓位计算: ¥100,000, ¥10.0/股")
    print(f"   买入数量: {pos['quantity']}")
    print(f"   止损价: ¥{pos['stop_loss_price']:.2f}")
    
    # 入场判断
    result = rm.should_enter("BUY", {"sentiment": "fear"}, {"positions": 2})
    print(f"\n🎯 入场判断: {'✅ 可以' if result['can_enter'] else '❌ 禁止'}")
    for r in result['reasons']:
        print(f"   {r}")
    
    # 风控报告
    print(rm.get_risk_report({"positions": 2}))
    
    return rm.get_risk_report()


if __name__ == "__main__":
    main()
