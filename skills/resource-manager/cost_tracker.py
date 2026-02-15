#!/usr/bin/env python3
"""
Lisa 资源管理 - 成本追踪模块
监控所有 API 调用的成本
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

STATE_DIR = Path(__file__).parent
COSTS_FILE = STATE_DIR / "costs.json"
MODELS_FILE = STATE_DIR / "models.json"

# 模型定价（每 1M tokens）
MODEL_PRICES = {
    "zai/glm-5": 0.01,        # $0.01 per 1M tokens
    "zai/glm-4.7": 0.005,      # $0.005 per 1M tokens
    "minimax-portal/MiniMax-M2.5": 0.002,  # $0.002 per 1M tokens
    "minimax-portal/MiniMax-M2.1": 0.001,  # $0.001 per 1M tokens
}

class CostTracker:
    """成本追踪器"""

    def __init__(self):
        self.costs = self._load_costs()
        self.models = self._load_models()

    def _load_costs(self) -> Dict:
        """加载成本数据"""
        if COSTS_FILE.exists():
            with open(COSTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "total_cost": 0,
            "daily_costs": {},
            "requests": [],
            "last_updated": None
        }

    def _save_costs(self):
        """保存成本数据"""
        self.costs["last_updated"] = datetime.now().isoformat()
        with open(COSTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.costs, f, indent=2, ensure_ascii=False)

    def _load_models(self) -> Dict:
        """加载模型定价"""
        if MODELS_FILE.exists():
            with open(MODELS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return MODEL_PRICES

    def record_request(self, model: str, prompt_tokens: int, completion_tokens: int):
        """记录一次 API 请求"""
        # 计算成本
        total_tokens = prompt_tokens + completion_tokens
        price_per_token = self.models.get(model, 0.01) / 1_000_000
        cost = total_tokens * price_per_token

        # 更新总成本
        self.costs["total_cost"] += cost

        # 更新每日成本
        today = datetime.now().strftime("%Y-%m-%d")
        if today not in self.costs["daily_costs"]:
            self.costs["daily_costs"][today] = 0
        self.costs["daily_costs"][today] += cost

        # 记录请求
        self.costs["requests"].append({
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cost": round(cost, 6)
        })

        # 只保留最近1000条记录
        if len(self.costs["requests"]) > 1000:
            self.costs["requests"] = self.costs["requests"][-1000:]

        self._save_costs()

    def get_daily_cost(self, days: int = 1) -> float:
        """获取最近 N 天的成本"""
        total = 0
        today = datetime.now()

        for i in range(days):
            date = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            total += self.costs["daily_costs"].get(date, 0)

        return total

    def get_model_usage(self) -> Dict[str, int]:
        """获取各模型使用量"""
        usage = defaultdict(int)
        for req in self.costs["requests"]:
            usage[req["model"]] += req["total_tokens"]
        return dict(usage)

    def generate_report(self) -> str:
        """生成成本报告"""
        report = []
        report.append("=" * 60)
        report.append("💰 Lisa 成本追踪报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        # 总成本
        report.append(f"📊 总成本: ${self.costs['total_cost']:.6f}")
        report.append("")

        # 今日成本
        daily = self.get_daily_cost(1)
        report.append(f"📅 今日成本: ${daily:.6f}")

        # 最近7天成本
        weekly = self.get_daily_cost(7)
        report.append(f"📈 周成本: ${weekly:.6f}")
        report.append("")

        # 模型使用量
        usage = self.get_model_usage()
        if usage:
            report.append("🤖 模型使用量：")
            for model, tokens in sorted(usage.items(), key=lambda x: x[1], reverse=True):
                cost = self.costs["total_cost"]
                percentage = (tokens / sum(usage.values())) * 100 if usage else 0
                report.append(f"  • {model}: {tokens:,} tokens ({percentage:.1f}%)")
        else:
            report.append("暂无 API 调用记录")

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)

def main():
    """主函数"""
    tracker = CostTracker()
    report = tracker.generate_report()
    print(report)

if __name__ == "__main__":
    main()
