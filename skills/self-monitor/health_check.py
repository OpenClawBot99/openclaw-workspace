#!/usr/bin/env python3
"""
Lisa 健康检查模块
快速检查系统健康状况
"""

import json
from datetime import datetime
from pathlib import Path

STATE_FILE = Path(__file__).parent / "state.json"
CONFIG_FILE = Path(__file__).parent / "config.json"

def check_health():
    """快速健康检查"""
    print("=" * 60)
    print("Lisa 健康检查")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    # 加载状态
    if STATE_FILE.exists():
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            state = json.load(f)
    else:
        print("⚠️  状态文件不存在")
        return False

    # 检查各项指标
    checks = []

    # 1. 健康分数
    health_score = state.get("health_score", 100)
    if health_score >= 80:
        checks.append(("健康分数", "✅", f"{health_score}/100"))
    elif health_score >= 60:
        checks.append(("健康分数", "⚠️", f"{health_score}/100"))
    else:
        checks.append(("健康分数", "❌", f"{health_score}/100"))

    # 2. 错误率
    total_requests = state.get("total_requests", 0)
    errors_today = state.get("errors_today", 0)

    if total_requests > 0:
        error_rate = (errors_today / total_requests) * 100
        if error_rate < 5:
            checks.append(("错误率", "✅", f"{error_rate:.2f}%"))
        elif error_rate < 10:
            checks.append(("错误率", "⚠️", f"{error_rate:.2f}%"))
        else:
            checks.append(("错误率", "❌", f"{error_rate:.2f}%"))
    else:
        checks.append(("错误率", "➖", "暂无数据"))

    # 3. 响应时间
    avg_response = state.get("avg_response_time_ms", 0)
    if avg_response > 0:
        if avg_response < 3000:
            checks.append(("响应时间", "✅", f"{avg_response:.0f}ms"))
        elif avg_response < 10000:
            checks.append(("响应时间", "⚠️", f"{avg_response:.0f}ms"))
        else:
            checks.append(("响应时间", "❌", f"{avg_response:.0f}ms"))
    else:
        checks.append(("响应时间", "➖", "暂无数据"))

    # 4. Token 消耗
    tokens_today = state.get("total_tokens_today", 0)
    checks.append(("今日Token", "ℹ️", f"{tokens_today:,}"))

    # 打印检查结果
    print("检查项目：")
    for name, status, value in checks:
        print(f"  {status} {name}: {value}")

    print()

    # 计算总体状态
    all_ok = all(status in ["✅", "➖", "ℹ️"] for _, status, _ in checks)

    if all_ok:
        print("💚 总体状态: 良好")
        return True
    else:
        print("💛 总体状态: 需要关注")
        return False

if __name__ == "__main__":
    check_health()
