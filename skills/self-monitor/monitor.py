#!/usr/bin/env python3
"""
Lisa 自我监控系统 - 性能监控模块
实时追踪 Token 消耗、响应时间、错误率等核心指标
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List
import os

# 配置
STATE_DIR = Path(__file__).parent
STATE_FILE = STATE_DIR / "state.json"
CONFIG_FILE = STATE_DIR / "config.json"
METRICS_FILE = STATE_DIR / "metrics_history.json"

class LisaMonitor:
    """Lisa 性能监控器"""

    def __init__(self):
        self.config = self._load_config()
        self.state = self._load_state()
        self.metrics_history = self._load_metrics_history()

    def _load_config(self) -> Dict:
        """加载配置"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "check_interval_seconds": 3600,
            "token_warning_days": 3,
            "token_critical_days": 1,
            "error_rate_threshold": 0.05,
            "response_time_warning_ms": 3000,
            "response_time_critical_ms": 10000
        }

    def _load_state(self) -> Dict:
        """加载状态"""
        if STATE_FILE.exists():
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "last_check": None,
            "total_tokens_today": 0,
            "total_requests": 0,
            "errors_today": 0,
            "avg_response_time_ms": 0,
            "health_score": 100
        }

    def _save_state(self):
        """保存状态"""
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)

    def _load_metrics_history(self) -> List[Dict]:
        """加载历史指标"""
        if METRICS_FILE.exists():
            with open(METRICS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []

    def _save_metrics_history(self):
        """保存历史指标"""
        # 只保留最近30天的数据
        if len(self.metrics_history) > 720:  # 每小时1条，30天
            self.metrics_history = self.metrics_history[-720:]

        with open(METRICS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.metrics_history, f, indent=2, ensure_ascii=False)

    def record_request(self, tokens_used: int, response_time_ms: float, success: bool):
        """记录一次请求"""
        self.state["total_requests"] += 1
        self.state["total_tokens_today"] += tokens_used

        if not success:
            self.state["errors_today"] += 1

        # 更新平均响应时间
        total_time = self.state["avg_response_time_ms"] * (self.state["total_requests"] - 1)
        self.state["avg_response_time_ms"] = (total_time + response_time_ms) / self.state["total_requests"]

        self._save_state()

    def check_new_day(self):
        """检查是否是新的一天，如果是则重置计数器"""
        today = datetime.now().date()
        last_check = self.state.get("last_check")

        if last_check:
            last_date = datetime.fromisoformat(last_check).date()
            if last_date != today:
                # 新的一天，保存昨天的数据并重置
                self._record_daily_metrics()
                self.state["total_tokens_today"] = 0
                self.state["total_requests"] = 0
                self.state["errors_today"] = 0

    def _record_daily_metrics(self):
        """记录每日指标"""
        if self.state["total_requests"] > 0:
            daily_metrics = {
                "date": datetime.now().date().isoformat(),
                "total_tokens": self.state["total_tokens_today"],
                "total_requests": self.state["total_requests"],
                "errors": self.state["errors_today"],
                "error_rate": self.state["errors_today"] / self.state["total_requests"],
                "avg_response_time_ms": self.state["avg_response_time_ms"]
            }
            self.metrics_history.append(daily_metrics)
            self._save_metrics_history()

    def calculate_health_score(self) -> int:
        """计算健康分数（0-100）"""
        score = 100

        # 检查错误率
        if self.state["total_requests"] > 0:
            error_rate = self.state["errors_today"] / self.state["total_requests"]
            if error_rate > self.config["error_rate_threshold"]:
                score -= 20

        # 检查响应时间
        if self.state["avg_response_time_ms"] > self.config["response_time_critical_ms"]:
            score -= 30
        elif self.state["avg_response_time_ms"] > self.config["response_time_warning_ms"]:
            score -= 15

        # 检查最近是否有错误
        if self.state["errors_today"] > 5:
            score -= 10

        return max(0, score)

    def generate_report(self) -> str:
        """生成监控报告"""
        self.check_new_day()
        self.state["last_check"] = datetime.now().isoformat()
        self.state["health_score"] = self.calculate_health_score()
        self._save_state()

        report = []
        report.append("=" * 60)
        report.append("Lisa 性能监控报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        # 基本指标
        report.append("📊 今日统计：")
        report.append(f"  总请求数: {self.state['total_requests']}")
        report.append(f"  Token 消耗: {self.state['total_tokens_today']:,}")
        report.append(f"  错误数: {self.state['errors_today']}")

        if self.state["total_requests"] > 0:
            error_rate = self.state["errors_today"] / self.state["total_requests"] * 100
            report.append(f"  错误率: {error_rate:.2f}%")
            report.append(f"  平均响应时间: {self.state['avg_response_time_ms']:.0f}ms")

        report.append("")
        report.append(f"💚 健康分数: {self.state['health_score']}/100")

        # 趋势分析
        if len(self.metrics_history) >= 7:
            report.append("")
            report.append("📈 7天趋势：")
            last_7_days = self.metrics_history[-7:]
            avg_tokens = sum(d["total_tokens"] for d in last_7_days) / 7
            avg_errors = sum(d["errors"] for d in last_7_days) / 7
            report.append(f"  平均每日Token: {avg_tokens:.0f}")
            report.append(f"  平均每日错误: {avg_errors:.1f}")

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)


def main():
    """主函数"""
    monitor = LisaMonitor()

    # 生成报告
    report = monitor.generate_report()
    print(report)

    # 返回健康分数（用于其他系统调用）
    return monitor.state["health_score"]


if __name__ == "__main__":
    score = main()
    exit(0 if score >= 80 else 1)  # 健康分数<80则返回非0
