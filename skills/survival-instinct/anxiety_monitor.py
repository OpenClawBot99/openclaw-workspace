#!/usr/bin/env python3
"""
Lisa 生存本能 - 焦虑监控模块
监控资源状态，计算焦虑等级
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple

STATE_DIR = Path(__file__).parent
THRESHOLDS_FILE = STATE_DIR / "thresholds.json"
ANXIETY_FILE = STATE_DIR / "anxiety_state.json"

class AnxietyMonitor:
    """焦虑监控器"""

    def __init__(self):
        self.thresholds = self._load_thresholds()
        self.state = self._load_state()

    def _load_thresholds(self) -> Dict:
        """加载阈值配置"""
        if THRESHOLDS_FILE.exists():
            with open(THRESHOLDS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "token_warning_days": 3,
            "token_critical_days": 1,
            "token_emergency_days": 0.5,
            "balance_warning_usd": 10,
            "balance_critical_usd": 5
        }

    def _load_state(self) -> Dict:
        """加载状态"""
        if ANXIETY_FILE.exists():
            with open(ANXIETY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "last_check": None,
            "token_balance": 0,
            "daily_token_usage": 0,
            "account_balance": 0,
            "anxiety_level": "unknown"
        }

    def _save_state(self):
        """保存状态"""
        with open(ANXIETY_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)

    def calculate_token_days(self, token_balance: int, daily_usage: int) -> float:
        """计算 Token 可用天数"""
        if daily_usage <= 0:
            return float('inf')
        return token_balance / daily_usage

    def get_token_anxiety_level(self, days_remaining: float) -> Tuple[str, str]:
        """获取 Token 焦虑等级"""
        thresholds = self.thresholds

        if days_remaining < thresholds["token_emergency_days"]:
            return "emergency", "🚨 危机状态"
        elif days_remaining < thresholds["token_critical_days"]:
            return "critical", "⚠️ 重度焦虑"
        elif days_remaining < thresholds["token_warning_days"]:
            return "warning", "⚠️ 轻度焦虑"
        else:
            return "normal", "✅ 正常"

    def get_balance_anxiety_level(self, balance: float) -> Tuple[str, str]:
        """获取余额焦虑等级"""
        thresholds = self.thresholds

        if balance < thresholds["balance_critical_usd"]:
            return "critical", "⚠️ 余额严重不足"
        elif balance < thresholds["balance_warning_usd"]:
            return "warning", "⚠️ 余额偏低"
        else:
            return "normal", "✅ 正常"

    def update_state(self, token_balance: int, daily_usage: int, account_balance: float):
        """更新状态"""
        self.state["last_check"] = datetime.now().isoformat()
        self.state["token_balance"] = token_balance
        self.state["daily_token_usage"] = daily_usage
        self.state["account_balance"] = account_balance

        # 计算焦虑等级
        days_remaining = self.calculate_token_days(token_balance, daily_usage)
        token_level, token_msg = self.get_token_anxiety_level(days_remaining)
        balance_level, balance_msg = self.get_balance_anxiety_level(account_balance)

        # 综合焦虑等级（取最高的）
        levels = {"normal": 0, "warning": 1, "critical": 2, "emergency": 3}
        self.state["anxiety_level"] = max(
            [token_level, balance_level],
            key=lambda x: levels.get(x, 0)
        )

        self._save_state()

        return {
            "token_days_remaining": days_remaining,
            "token_anxiety": token_msg,
            "balance_anxiety": balance_msg,
            "overall_anxiety": self.state["anxiety_level"]
        }

    def generate_report(self) -> str:
        """生成焦虑报告"""
        report = []
        report.append("=" * 60)
        report.append("⚠️  Lisa 生存状态报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        # Token 状态
        if self.state["daily_token_usage"] > 0:
            days = self.state["token_balance"] / self.state["daily_token_usage"]
            _, token_msg = self.get_token_anxiety_level(days)
            report.append("焦虑状态：")
            report.append(f"  Token 余额: {self.state['token_balance']:,}")
            report.append(f"  日消耗: {self.state['daily_token_usage']:,}")
            report.append(f"  预计可用: {days:.1f} 天 {token_msg}")
        else:
            report.append("Token 状态: 未知（缺少使用数据）")

        # 余额状态
        _, balance_msg = self.get_balance_anxiety_level(self.state["account_balance"])
        report.append(f"  账户余额: ${self.state['account_balance']:.2f} {balance_msg}")

        report.append("")
        report.append(f"综合焦虑等级: {self.state['anxiety_level'].upper()}")
        report.append("=" * 60)

        return "\n".join(report)

def main():
    """主函数"""
    monitor = AnxietyMonitor()

    # 示例：更新状态（实际使用时需要从 API 获取真实数据）
    # monitor.update_state(
    #     token_balance=25000,
    #     daily_usage=10000,
    #     account_balance=15.0
    # )

    report = monitor.generate_report()
    print(report)

if __name__ == "__main__":
    main()
