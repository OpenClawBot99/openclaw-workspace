#!/usr/bin/env python3
"""
Lisa 资源管理 - 增强版优化器
增加了智能模型选择、缓存策略、预算告警、成本预测
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

STATE_DIR = Path(__file__).parent
COSTS_FILE = STATE_DIR / "costs.json"
BUDGET_FILE = STATE_DIR / "budget.json"
MODELS_FILE = STATE_DIR / "models.json"
CACHE_FILE = STATE_DIR / "cache.json"

# 模型定价和能力
MODEL_INFO = {
    "minimax-portal/MiniMax-M2.1": {
        "price": 0.001,
        "strength": 1.0,
        "speed": 1.0,
        "best_for": ["简单对话", "快速摘要", "批量处理"]
    },
    "minimax-portal/MiniMax-M2.5": {
        "price": 0.002,
        "strength": 1.5,
        "speed": 1.2,
        "best_for": ["正常任务", "代码生成", "分析"]
    },
    "zai/glm-4.7": {
        "price": 0.005,
        "strength": 2.0,
        "speed": 1.0,
        "best_for": ["复杂推理", "长文本", "多语言"]
    },
    "zai/glm-5": {
        "price": 0.01,
        "strength": 2.5,
        "speed": 0.9,
        "best_for": ["高难度任务", "创意写作", "复杂代码"]
    }
}

class EnhancedOptimizer:
    """增强版资源优化器"""

    def __init__(self):
        self.costs = self._load_costs()
        self.budget = self._load_budget()
        self.cache = self._load_cache()
        self.models = MODEL_INFO

    def _load_costs(self) -> Dict:
        """加载成本数据"""
        if COSTS_FILE.exists():
            with open(COSTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return self._get_default_costs()

    def _get_default_costs(self) -> Dict:
        """获取默认成本结构"""
        return {
            "total_cost": 0,
            "daily_costs": {},
            "requests": [],
            "last_updated": None,
            "model_usage": {}  # 新增：按模型统计
        }

    def _save_costs(self):
        """保存成本数据"""
        self.costs["last_updated"] = datetime.now().isoformat()
        with open(COSTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.costs, f, indent=2, ensure_ascii=False)

    def _load_budget(self) -> Dict:
        """加载预算配置"""
        if BUDGET_FILE.exists():
            with open(BUDGET_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "daily_budget_usd": 1.0,
            "monthly_budget_usd": 30.0,
            "alert_threshold": 0.8,
            "emergency_threshold": 0.95,
            "spent_today": 0,
            "spent_monthly": 0,
            "month_start": datetime.now().strftime("%Y-%m-%d")
        }

    def _save_budget(self):
        """保存预算数据"""
        with open(BUDGET_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.budget, f, indent=2, ensure_ascii=False)

    def _load_cache(self) -> Dict:
        """加载缓存"""
        if CACHE_FILE.exists():
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "entries": {},
            "stats": {"hits": 0, "misses": 0}
        }

    def _save_cache(self):
        """保存缓存"""
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.cache, f, indent=2, ensure_ascii=False)

    def record_request(self, model: str, prompt_tokens: int, completion_tokens: int, cache_key: str = None):
        """记录 API 请求"""
        total_tokens = prompt_tokens + completion_tokens
        price = self.models.get(model, {}).get("price", 0.01)
        cost = total_tokens * price / 1_000_000

        # 更新总成本
        self.costs["total_cost"] += cost

        # 更新每日成本
        today = datetime.now().strftime("%Y-%m-%d")
        if today not in self.costs["daily_costs"]:
            self.costs["daily_costs"][today] = 0
        self.costs["daily_costs"][today] += cost

        # 更新模型使用统计
        if model not in self.costs.get("model_usage", {}):
            self.costs["model_usage"] = self.costs.get("model_usage", {})
            self.costs["model_usage"][model] = {"tokens": 0, "requests": 0, "cost": 0}
        self.costs["model_usage"][model]["tokens"] += total_tokens
        self.costs["model_usage"][model]["requests"] += 1
        self.costs["model_usage"][model]["cost"] += cost

        # 记录请求
        self.costs["requests"].append({
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cost": round(cost, 6)
        })

        # 限制记录数量
        if len(self.costs["requests"]) > 1000:
            self.costs["requests"] = self.costs["requests"][-1000:]

        # 更新预算
        self._update_budget(cost)

        self._save_costs()

        # 如果有缓存key，添加到缓存
        if cache_key:
            self.cache["entries"][cache_key] = {
                "model": model,
                "result_tokens": completion_tokens,
                "timestamp": datetime.now().isoformat()
            }
            self._save_cache()

    def _update_budget(self, cost: float):
        """更新预算消费"""
        # 检查是否是新月
        month_start = self.budget.get("month_start", "")
        today = datetime.now().strftime("%Y-%m-%d")
        
        if not month_start or month_start[:7] != today[:7]:
            # 新月，重置月度预算
            self.budget["spent_monthly"] = 0
            self.budget["month_start"] = today
        
        # 更新消费
        self.budget["spent_today"] += cost
        self.budget["spent_monthly"] += cost
        
        self._save_budget()

    def check_cache(self, cache_key: str) -> Optional[Dict]:
        """检查缓存"""
        if cache_key in self.cache["entries"]:
            entry = self.cache["entries"][cache_key]
            # 检查是否过期（24小时）
            timestamp = datetime.fromisoformat(entry["timestamp"])
            if (datetime.now() - timestamp).total_seconds() < 86400:
                self.cache["stats"]["hits"] += 1
                self._save_cache()
                return entry
        
        self.cache["stats"]["misses"] += 1
        self._save_cache()
        return None

    def smart_model_select(self, task_type: str, complexity: str = "normal") -> Dict:
        """智能模型选择
        
        Args:
            task_type: 任务类型 (conversation/summarize/code/analyze/create/chat)
            complexity: 复杂度 (simple/normal/complex)
        """
        # 根据任务类型选择
        task_models = {
            "chat": "minimax-portal/MiniMax-M2.1",
            "summarize": "minimax-portal/MiniMax-M2.1", 
            "code": "minimax-portal/MiniMax-M2.5",
            "conversation": "minimax-portal/MiniMax-M2.5",
            "analyze": "zai/glm-4.7",
            "create": "zai/glm-5"
        }
        
        # 预算检查
        budget_status = self.get_budget_status()
        if budget_status.get("emergency"):
            # 预算紧急，使用最便宜的模型
            return {
                "model": "minimax-portal/MiniMax-M2.1",
                "price": 0.001,
                "reason": "预算紧急，自动切换到最便宜模型"
            }
        
        # 基于复杂度和预算选择
        base_model = task_models.get(task_type, "minimax-portal/MiniMax-M2.5")
        
        # 复杂度调整
        if complexity == "simple":
            # 简单任务降级
            if base_model == "zai/glm-5":
                base_model = "zai/glm-4.7"
            elif base_model == "zai/glm-4.7":
                base_model = "minimax-portal/MiniMax-M2.5"
            elif base_model == "minimax-portal/MiniMax-M2.5":
                base_model = "minimax-portal/MiniMax-M2.1"
        elif complexity == "complex":
            # 复杂任务升级
            if base_model == "minimax-portal/MiniMax-M2.1":
                base_model = "minimax-portal/MiniMax-M2.5"
            elif base_model == "minimax-portal/MiniMax-M2.5":
                base_model = "zai/glm-4.7"
        
        model_info = self.models.get(base_model, {})
        return {
            "model": base_model,
            "price": model_info.get("price", 0.01),
            "strength": model_info.get("strength", 1.0),
            "reason": f"{task_type}任务，使用{model_info.get('best_for', ['通用'])[0]}"
        }

    def get_budget_status(self) -> Dict:
        """获取预算状态"""
        daily_budget = self.budget.get("daily_budget_usd", 1.0)
        monthly_budget = self.budget.get("monthly_budget_usd", 30.0)
        
        spent_today = self.budget.get("spent_today", 0)
        spent_monthly = self.budget.get("spent_monthly", 0)
        
        daily_pct = (spent_today / daily_budget * 100) if daily_budget > 0 else 0
        monthly_pct = (spent_monthly / monthly_budget * 100) if monthly_budget > 0 else 0
        
        return {
            "daily_budget": daily_budget,
            "monthly_budget": monthly_budget,
            "spent_today": spent_today,
            "spent_monthly": spent_monthly,
            "daily_pct": daily_pct,
            "monthly_pct": monthly_pct,
            "warning": daily_pct >= 80 or monthly_pct >= 80,
            "emergency": daily_pct >= 95 or monthly_pct >= 95
        }

    def predict_cost(self, days: int = 7) -> Dict:
        """成本预测"""
        if len(self.costs.get("daily_costs", {})) < 3:
            return {"status": "insufficient_data"}
        
        # 获取最近数据
        costs = self.costs["daily_costs"]
        sorted_dates = sorted(costs.keys(), reverse=True)[:7]
        daily_values = [costs[d] for d in sorted_dates]
        
        avg_daily = sum(daily_values) / len(daily_values)
        
        # 简单趋势
        if len(daily_values) >= 2:
            trend = (daily_values[0] - daily_values[-1]) / len(daily_values)
            predicted = daily_values[0] + trend * days
        else:
            predicted = avg_daily * days
        
        return {
            "status": "ok",
            "avg_daily": avg_daily,
            "predicted_next_days": predicted,
            "trend": "increasing" if trend > 0 else "decreasing" if trend < 0 else "stable"
        }

    def calculate_savings(self) -> Dict:
        """计算节省"""
        total = self.costs.get("total_cost", 0)
        
        # 如果全部用最贵的模型
        expensive_rate = 0.01  # glm-5
        cheap_rate = 0.001     # M2.1
        
        savings = 0
        potential_savings = 0
        expensive_cost = 0
        
        if self.costs.get("model_usage"):
            total_tokens = sum(m.get("tokens", 0) for m in self.costs["model_usage"].values())
            expensive_cost = total_tokens * expensive_rate / 1_000_000
            cheap_cost = total_tokens * cheap_rate / 1_000_000
            savings = expensive_cost - total
            potential_savings = expensive_cost - cheap_cost
            
        return {
            "current_cost": total,
            "savings_so_far": savings,
            "potential_savings": potential_savings,
            "savings_pct": (savings / expensive_cost * 100) if expensive_cost > 0 else 0
        }

    def get_cache_stats(self) -> Dict:
        """获取缓存统计"""
        stats = self.cache.get("stats", {"hits": 0, "misses": 0})
        total = stats["hits"] + stats["misses"]
        hit_rate = (stats["hits"] / total * 100) if total > 0 else 0
        
        return {
            "hits": stats["hits"],
            "misses": stats["misses"],
            "hit_rate": hit_rate,
            "cached_items": len(self.cache.get("entries", {}))
        }

    def generate_optimization_report(self) -> str:
        """生成优化报告"""
        savings = self.calculate_savings()
        budget = self.get_budget_status()
        prediction = self.predict_cost()
        cache_stats = self.get_cache_stats()
        
        report = []
        report.append("=" * 60)
        report.append("⚡ Lisa 增强型资源优化报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        # 成本概览
        report.append("")
        report.append("💰 成本概览:")
        report.append(f"  总成本: ${savings['current_cost']:.6f}")
        report.append(f"  已节省: ${savings['savings_so_far']:.6f}")
        report.append(f"  潜在节省: ${savings['potential_savings']:.6f}")
        
        # 预算状态
        report.append("")
        report.append("📊 预算状态:")
        report.append(f"  今日: ${budget['spent_today']:.4f} / ${budget['daily_budget']:.2f} ({budget['daily_pct']:.1f}%)")
        report.append(f"  本月: ${budget['spent_monthly']:.4f} / ${budget['monthly_budget']:.2f} ({budget['monthly_pct']:.1f}%)")
        
        if budget["emergency"]:
            report.append("  🚨 预算紧急！请降低使用")
        elif budget["warning"]:
            report.append("  ⚠️ 预算警告，接近限额")
        
        # 成本预测
        if prediction.get("status") == "ok":
            report.append("")
            report.append("📈 成本预测:")
            report.append(f"  日均: ${prediction['avg_daily']:.4f}")
            report.append(f"  趋势: {prediction['trend']}")
            report.append(f"  预测7天: ${prediction['predicted_next_days']:.4f}")
        
        # 缓存统计
        report.append("")
        report.append("💾 缓存效率:")
        report.append(f"  命中: {cache_stats['hits']}")
        report.append(f"  未命中: {cache_stats['misses']}")
        report.append(f"  命中率: {cache_stats['hit_rate']:.1f}%")
        
        # 模型使用
        if self.costs.get("model_usage"):
            report.append("")
            report.append("🤖 模型使用分布:")
            for model, data in sorted(self.costs["model_usage"].items(), 
                                       key=lambda x: x[1].get("cost", 0), reverse=True):
                pct = (data.get("cost", 0) / savings['current_cost'] * 100) if savings['current_cost'] > 0 else 0
                report.append(f"  • {model.split('/')[-1]}: ${data.get('cost', 0):.4f} ({pct:.1f}%)")
        
        # 智能推荐
        report.append("")
        report.append("💡 优化建议:")
        if cache_stats["hit_rate"] < 30:
            report.append("  1. 建议增加缓存使用，减少重复请求")
        if budget["daily_pct"] > 70:
            report.append("  2. 建议使用更便宜的模型处理简单任务")
        report.append("  3. 简单任务 → MiniMax-M2.1 ($0.001/1M)")
        report.append("  4. 正常任务 → MiniMax-M2.5 ($0.002/1M)")
        
        report.append("")
        report.append("=" * 60)
        
        return "\n".join(report)


def main():
    """主函数"""
    optimizer = EnhancedOptimizer()
    report = optimizer.generate_optimization_report()
    print(report)

if __name__ == "__main__":
    main()
