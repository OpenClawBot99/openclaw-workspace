#!/usr/bin/env python3
"""
智能模型选择器 - 探索-利用策略实现
支持：ε-Greedy, Softmax, UCB
"""

import json
import random
import math
import os
from pathlib import Path
from typing import List, Dict, Tuple
import argparse

# ========== 配置 ==========
AVAILABLE_MODELS = [
    "zai/glm-5",                    # GLM-5
    "zai/glm-4.7",                  # GLM-4.7
    "minimax-portal/MiniMax-M2.5",  # MiniMax M2.5 (默认)
    "minimax-portal/MiniMax-M2.1",  # MiniMax M2.1
    # 可以添加更多模型：
    # "anthropic/claude-opus-4-6",
    # "openai/gpt-5.1-codex"
]

# 性能指标权重
WEIGHTS = {
    "satisfaction": 0.4,  # 用户满意度
    "speed": 0.2,        # 响应速度（反向）
    "cost": 0.2,         # 成本（反向）
    "error": 0.2         # 错误率（反向）
}

# ε-Greedy 参数
EPSILON_START = 0.5
EPSILON_MIN = 0.1
EPSILON_DECAY = 0.001

# Softmax 参数
TEMPERATURE_START = 1.0
TEMPERATURE_MIN = 0.5
TEMPERATURE_DECAY = 0.002

# UCB 参数
UCB_C = 2.0  # 探索系数

# ========== 状态管理 ==========
STATE_DIR = Path(__file__).parent.parent / "state"
STATE_FILE = STATE_DIR / "model_metrics.json"
METADATA_FILE = STATE_DIR / "metadata.json"


def load_state() -> Dict:
    """加载模型指标数据"""
    STATE_DIR.mkdir(exist_ok=True)

    if not STATE_FILE.exists():
        # 首次运行，初始化空状态
        save_state({})
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


def load_metadata() -> Dict:
    """加载元数据（总使用次数等）"""
    if not METADATA_FILE.exists():
        save_metadata({"total_uses": 0})
        return {"total_uses": 0}

    try:
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {"total_uses": 0}


def save_metadata(metadata: Dict):
    """保存元数据"""
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)


def calculate_score(metrics: Dict) -> float:
    """
    计算综合评分
    满意度和速度、成本、错误率加权
    """
    if not metrics:
        return 0.0

    satisfaction = metrics.get("satisfaction_avg", 3.0)  # 默认中等
    speed = metrics.get("speed_avg_ms", 2000)
    cost = metrics.get("cost_avg", 0.05)
    error_rate = metrics.get("error_rate", 0.1)

    # 归一化到 0-1 范围（使用经验值作为参考）
    satisfaction_norm = satisfaction / 5.0  # 1-5 -> 0-1
    speed_norm = min(1.0, 3000 / speed)  # 越快越好，3000ms 为参考
    cost_norm = min(1.0, 0.1 / cost)  # 越便宜越好，$0.1 为参考
    error_norm = 1.0 - error_rate  # 越小越好

    # 加权求和
    score = (
        WEIGHTS["satisfaction"] * satisfaction_norm +
        WEIGHTS["speed"] * speed_norm +
        WEIGHTS["cost"] * cost_norm +
        WEIGHTS["error"] * error_norm
    )

    return round(score * 5, 2)  # 返回 0-5 分范围


def epsilon_greedy(state: Dict, metadata: Dict) -> str:
    """ε-Greedy 策略"""
    total_uses = metadata.get("total_uses", 0)

    # 探索率随数据量线性递减
    epsilon = max(EPSILON_MIN, EPSILON_START - total_uses * EPSILON_DECAY)

    if random.random() < epsilon:
        # 探索：随机选择
        model = random.choice(AVAILABLE_MODELS)
        print(f"[ε-Greedy] 探索模式 (ε={epsilon:.3f}): 随机选择 {model}")
    else:
        # 利用：选择评分最高的
        scores = {model: calculate_score(state.get(model, {})) for model in AVAILABLE_MODELS}
        best_model = max(scores, key=scores.get)
        print(f"[ε-Greedy] 利用模式 (ε={epsilon:.3f}): 选择最优 {best_model} (评分={scores[best_model]:.2f})")
        model = best_model

    return model


def softmax(state: Dict, metadata: Dict) -> str:
    """Softmax (Boltzmann) 策略"""
    total_uses = metadata.get("total_uses", 0)

    # 温度随数据量线性递减
    temperature = max(TEMPERATURE_MIN, TEMPERATURE_START - total_uses * TEMPERATURE_DECAY)

    # 计算每个模型的概率
    scores = [calculate_score(state.get(model, {})) for model in AVAILABLE_MODELS]
    exp_scores = [math.exp(score / temperature) for score in scores]
    total = sum(exp_scores)
    probs = [e / total for e in exp_scores]

    # 按概率选择
    idx = random.choices(range(len(AVAILABLE_MODELS)), weights=probs, k=1)[0]
    model = AVAILABLE_MODELS[idx]

    print(f"[Softmax] 温度 τ={temperature:.3f}: 选择 {model} (评分={scores[idx]:.2f}, 概率={probs[idx]:.2%})")

    return model


def ucb(state: Dict, metadata: Dict) -> str:
    """UCB (Upper Confidence Bound) 策略"""
    total_uses = sum(state.get(model, {}).get("uses", 0) for model in AVAILABLE_MODELS)
    total_uses = max(1, total_uses)  # 避免除以零

    # 计算每个模型的 UCB 值
    ucb_values = {}
    for model in AVAILABLE_MODELS:
        metrics = state.get(model, {})
        uses = metrics.get("uses", 0)
        avg_score = metrics.get("score", 0)

        if uses == 0:
            # 未使用过的模型，给予高探索优先级
            ucb = float('inf')
        else:
            # UCB = μ + c × √(ln(N)/n)
            uncertainty = math.sqrt(math.log(total_uses) / uses)
            ucb = avg_score + UCB_C * uncertainty

        ucb_values[model] = ucb

    best_model = max(ucb_values, key=ucb_values.get)
    print(f"[UCB] c={UCB_C}: 选择 {best_model} (UCB={ucb_values[best_model]:.2f})")

    return best_model


def auto_select_strategy(state: Dict, metadata: Dict) -> str:
    """
    自动选择策略
    - 数据量少 (<20) → ε-Greedy（快速探索）
    - 数据量中等 (20-100) → Softmax（平衡）
    - 数据量多 (>100) → UCB（追求最优）
    """
    total_uses = metadata.get("total_uses", 0)

    if total_uses < 20:
        print(f"[Auto策略] 数据量少 ({total_uses}), 使用 ε-Greedy")
        return epsilon_greedy(state, metadata)
    elif total_uses < 100:
        print(f"[Auto策略] 数据量中等 ({total_uses}), 使用 Softmax")
        return softmax(state, metadata)
    else:
        print(f"[Auto策略] 数据量充足 ({total_uses}), 使用 UCB")
        return ucb(state, metadata)


def main():
    parser = argparse.ArgumentParser(description="智能模型选择器")
    parser.add_argument("--strategy", choices=["epsilon", "softmax", "ucb", "auto"],
                    default="auto", help="选择策略")
    args = parser.parse_args()

    # 加载状态
    state = load_state()
    metadata = load_metadata()

    # 显示当前状态
    print("=" * 60)
    print("当前模型使用情况：")
    for model in AVAILABLE_MODELS:
        metrics = state.get(model, {})
        uses = metrics.get("uses", 0)
        score = metrics.get("score", 0)
        print(f"  {model}: 使用 {uses} 次, 评分 {score:.2f}")
    print(f"  总使用次数: {metadata.get('total_uses', 0)}")
    print("=" * 60)

    # 选择策略
    if args.strategy == "epsilon":
        selected_model = epsilon_greedy(state, metadata)
    elif args.strategy == "softmax":
        selected_model = softmax(state, metadata)
    elif args.strategy == "ucb":
        selected_model = ucb(state, metadata)
    else:  # auto
        selected_model = auto_select_strategy(state, metadata)

    # 输出结果
    print(f"\n✅ 推荐使用: {selected_model}")
    print(f"\n命令: /model {selected_model}")

    # 更新元数据
    metadata["total_uses"] = metadata.get("total_uses", 0) + 1
    save_metadata(metadata)


if __name__ == "__main__":
    main()
