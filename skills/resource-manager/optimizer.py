#!/usr/bin/env python3
"""
Lisa 资源管理 - 优化器模块
自动优化资源使用
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

STATE_DIR = Path(__file__).parent
COSTS_FILE = STATE_DIR / "costs.json"

# 模型优先级（按性价比排序，最优在前）
MODEL_PRIORITY = [
    ("minimax-portal/MiniMax-M2.1", 0.001),  # 最便宜
    ("minimax-portal/MiniMax-M2.5", 0.002),
    ("zai/glm-4.7", 0.005),
    ("zai/glm-5", 0.01),  # 最贵
]

class Optimizer:
    """资源优化器"""

    def __init__(self):
        self.costs = self._load_costs()

    def _load_costs(self) -> Dict:
        """加载成本数据"""
        if COSTS_FILE.exists():
            with open(COSTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "total_cost": 0,
            "daily_costs": {},
            "requests": []
        }

    def get_recommended_model(self, task_complexity: str = "normal") -> Dict:
        """推荐最优模型

        Args:
            task_complexity: 任务复杂度 (simple/normal/complex)
        """
        # 根据复杂度选择模型
        if task_complexity == "simple":
            # 简单任务用最便宜的模型
            return {
                "model": MODEL_PRIORITY[0][0],
                "price": MODEL_PRIORITY[0][1],
                "reason": "简单任务，用最便宜的模型"
            }
        elif task_complexity == "normal":
            # 正常任务用中档模型
            return {
                "model": MODEL_PRIORITY[1][0],
                "price": MODEL_PRIORITY[1][1],
                "reason": "正常任务，性价比最优"
            }
        else:  # complex
            # 复杂任务可能需要更强的模型
            return {
                "model": MODEL_PRIORITY[2][0],
                "price": MODEL_PRIORITY[2][1],
                "reason": "复杂任务，需要更好的模型"
            }

    def calculate_savings(self) -> Dict:
        """计算节省"""
        total_cost = self.costs["total_cost"]

        # 如果全部用最贵的模型
        expensive_scenario = total_cost * 10  # 假设

        # 如果全部用最便宜的模型
        cheap_scenario = total_cost  # 已经是优化后的

        savings = expensive_scenario - cheap_scenario
        percentage = (savings / expensive_scenario) * 100 if expensive_scenario > 0 else 0

        return {
            "current_cost": total_cost,
            "potential_savings": savings,
            "savings_percentage": percentage
        }

    def generate_optimization_report(self) -> str:
        """生成优化报告"""
        report = []
        report.append("=" * 60)
        report.append("⚡ Lisa 资源优化报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        # 节省计算
        savings = self.calculate_savings()
        report.append(f"💰 当前成本: ${savings['current_cost']:.6f}")
        report.append(f"💡 预估节省: ${savings['potential_savings']:.6f} ({savings['savings_percentage']:.1f}%)")
        report.append("")

        # 模型推荐
        report.append("🤖 推荐模型：")
        report.append("  简单任务 → minimax/MiniMax-M2.1 ($0.001/1M)")
        report.append("  正常任务 → minimax/MiniMax-M2.5 ($0.002/1M)")
        report.append("  复杂任务 → zai/glm-4.7 ($0.005/1M)")
        report.append("")

        # 优化建议
        report.append("💡 优化建议：")
        report.append("  1. 简单任务用 MiniMax-M2.1")
        report.append("  2. 批量处理请求，减少 API 调用次数")
        report.append("  3. 使用缓存，避免重复请求")
        report.append("")

        report.append("=" * 60)

        return "\n".join(report)

def main():
    """主函数"""
    optimizer = Optimizer()
    report = optimizer.generate_optimization_report()
    print(report)

if __name__ == "__main__":
    main()
