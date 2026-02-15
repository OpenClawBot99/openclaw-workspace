#!/usr/bin/env python3
"""
Lisa 资源管理 - 预算管理模块
设置和管理每日/每月预算
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple

STATE_DIR = Path(__file__).parent
BUDGET_FILE = STATE_DIR / "budget.json"
COSTS_FILE = STATE_DIR / "costs.json"

DEFAULT_BUDGET = {
    "daily_usd": 1.0,
    "monthly_usd": 30.0,
    "alert_threshold": 0.8,   # 80% 时告警
    "emergency_threshold": 0.95  # 95% 时紧急
}

class BudgetManager:
    """预算管理器"""

    def __init__(self):
        self.budget = self._load_budget()

    def _load_budget(self) -> Dict:
        """加载预算配置"""
        if BUDGET_FILE.exists():
            with open(BUDGET_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "config": DEFAULT_BUDGET,
            "daily_spent": 0,
            "monthly_spent": 0,
            "last_reset_daily": None,
            "last_reset_monthly": None
        }

    def _save_budget(self):
        """保存预算数据"""
        with open(BUDGET_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.budget, f, indent=2, ensure_ascii=False)

    def _check_reset(self):
        """检查是否需要重置"""
        today = datetime.now()

        # 每日重置
        if self.budget["last_reset_daily"] != today.strftime("%Y-%m-%d"):
            self.budget["daily_spent"] = 0
            self.budget["last_reset_daily"] = today.strftime("%Y-%m-%d")

        # 每月重置
        if self.budget["last_reset_monthly"] != today.strftime("%Y-%m"):
            self.budget["monthly_spent"] = 0
            self.budget["last_reset_monthly"] = today.strftime("%Y-%m")

        if self.budget["last_reset_daily"] or self.budget["last_reset_monthly"]:
            self._save_budget()

    def add_cost(self, cost: float):
        """添加成本"""
        self._check_reset()
        self.budget["daily_spent"] += cost
        self.budget["monthly_spent"] += cost
        self._save_budget()

    def get_status(self) -> Tuple[float, str]:
        """获取预算状态"""
        self._check_reset()

        daily_budget = self.budget["config"]["daily_usd"]
        daily_spent = self.budget["daily_spent"]
        daily_percentage = (daily_spent / daily_budget) * 100 if daily_budget > 0 else 0

        monthly_budget = self.budget["config"]["monthly_usd"]
        monthly_spent = self.budget["monthly_spent"]
        monthly_percentage = (monthly_spent / monthly_budget) * 100 if monthly_budget > 0 else 0

        # 判断状态
        if daily_percentage >= self.budget["config"]["emergency_threshold"]:
            status = "🚨 紧急"
        elif daily_percentage >= self.budget["config"]["alert_threshold"]:
            status = "⚠️ 警告"
        else:
            status = "✅ 正常"

        return daily_percentage, status

    def generate_status_report(self) -> str:
        """生成状态报告"""
        daily_percentage, status = self.get_status()

        report = []
        report.append("=" * 60)
        report.append("💵 Lisa 预算状态报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        daily_budget = self.budget["config"]["daily_usd"]
        daily_spent = self.budget["daily_spent"]
        report.append(f"📅 今日预算: ${daily_budget:.2f}")
        report.append(f"💸 今日已用: ${daily_spent:.6f}")
        report.append(f"📊 使用比例: {daily_percentage:.1f}% {status}")
        report.append("")

        # 进度条
        bar_length = 20
        filled = int(bar_length * daily_percentage / 100)
        bar = "█" * filled + "░" * (bar_length - filled)
        report.append(f"进度: [{bar}]")
        report.append("")

        monthly_budget = self.budget["config"]["monthly_usd"]
        monthly_spent = self.budget["monthly_spent"]
        monthly_percentage = (monthly_spent / monthly_budget) * 100 if monthly_budget > 0 else 0

        report.append(f"📆 本月预算: ${monthly_budget:.2f}")
        report.append(f"💰 本月已用: ${monthly_spent:.6f}")
        report.append(f"📈 使用比例: {monthly_percentage:.1f}%")
        report.append("")

        # 建议
        if daily_percentage < 50:
            report.append("💡 状态良好，继续保持")
        elif daily_percentage < 80:
            report.append("💡 使用适中，注意控制")
        elif daily_percentage < 95:
            report.append("⚠️ 接近预算上限，建议优化使用")
        else:
            report.append("🚨 接近紧急阈值，考虑降级模型")

        report.append("=" * 60)

        return "\n".join(report)

def main():
    """主函数"""
    manager = BudgetManager()
    report = manager.generate_status_report()
    print(report)

if __name__ == "__main__":
    main()
