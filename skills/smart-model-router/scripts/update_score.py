#!/usr/bin/env python3
"""
更新模型评分脚本
在对话结束后手动或自动更新模型指标
"""

import json
import argparse
from pathlib import Path
from typing import Dict

# ========== 状态管理 ==========
STATE_DIR = Path(__file__).parent.parent / "state"
STATE_FILE = STATE_DIR / "model_metrics.json"


def load_state() -> Dict:
    """加载模型指标数据"""
    if not STATE_FILE.exists():
        return {}

    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_state(state: Dict):
    """保存模型指标数据"""
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def update_model_metrics(model: str, satisfaction: float = None,
                     speed_ms: int = None, cost: float = None,
                     error: int = None):
    """
    更新模型指标
    使用增量平均（exponential moving average）
    """
    state = load_state()

    if model not in state:
        state[model] = {
            "uses": 0,
            "satisfaction_avg": 3.0,
            "speed_avg_ms": 2000,
            "cost_avg": 0.05,
            "error_rate": 0.0,
            "score": 0.0
        }

    metrics = state[model]
    uses = metrics["uses"]

    # 更新指标（使用增量平均，α = 0.3）
    alpha = 0.3

    if satisfaction is not None:
        new_satisfaction = alpha * satisfaction + (1 - alpha) * metrics["satisfaction_avg"]
        metrics["satisfaction_avg"] = round(new_satisfaction, 2)
        print(f"  满意度: {metrics['satisfaction_avg']} → {new_satisfaction:.2f}")

    if speed_ms is not None:
        new_speed = alpha * speed_ms + (1 - alpha) * metrics["speed_avg_ms"]
        metrics["speed_avg_ms"] = round(new_speed)
        print(f"  速度: {metrics['speed_avg_ms']}ms → {new_speed:.0f}ms")

    if cost is not None:
        new_cost = alpha * cost + (1 - alpha) * metrics["cost_avg"]
        metrics["cost_avg"] = round(new_cost, 4)
        print(f"  成本: ${metrics['cost_avg']} → ${new_cost:.4f}")

    if error is not None:
        # 错误率：新的错误率 = α × error + (1-α) × 旧错误率
        new_error = alpha * error + (1 - alpha) * metrics["error_rate"]
        metrics["error_rate"] = round(new_error, 3)
        print(f"  错误率: {metrics['error_rate']*100:.1f}% → {new_error*100:.1f}%")

    # 增加使用次数
    metrics["uses"] += 1

    # 重新计算综合评分
    # 满意度 40%, 速度 20%, 成本 20%, 错误率 20%
    satisfaction_norm = metrics["satisfaction_avg"] / 5.0
    speed_norm = min(1.0, 3000 / metrics["speed_avg_ms"])
    cost_norm = min(1.0, 0.1 / metrics["cost_avg"])
    error_norm = 1.0 - metrics["error_rate"]

    score = (
        0.4 * satisfaction_norm +
        0.2 * speed_norm +
        0.2 * cost_norm +
        0.2 * error_norm
    )
    metrics["score"] = round(score * 5, 2)

    # 保存
    save_state(state)

    print(f"\n✅ {model} 指标已更新")
    print(f"  使用次数: {metrics['uses']}")
    print(f"  综合评分: {metrics['score']:.2f} / 5.0")


def main():
    parser = argparse.ArgumentParser(description="更新模型指标")
    parser.add_argument("--model", required=True, help="模型 ID (如: zai/glm-4.7)")
    parser.add_argument("--satisfaction", type=float, choices=range(1, 6),
                    help="满意度评分 (1-5)")
    parser.add_argument("--speed", type=int, help="响应时间 (毫秒)")
    parser.add_argument("--cost", type=float, help="成本 (美元)")
    parser.add_argument("--error", type=int, choices=[0, 1],
                    help="是否出错 (0=正常, 1=出错)")

    args = parser.parse_args()

    # 至少提供一个指标
    if all(v is None for v in [args.satisfaction, args.speed, args.cost, args.error]):
        parser.error("至少提供一个指标参数")

    update_model_metrics(
        model=args.model,
        satisfaction=args.satisfaction,
        speed_ms=args.speed,
        cost=args.cost,
        error=args.error
    )


if __name__ == "__main__":
    main()
