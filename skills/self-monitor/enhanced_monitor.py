#!/usr/bin/env python3
"""
Lisa 自我监控系统 - 增强版
增加了趋势预测、异常检测、与 survival-instinct 集成
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from collections import deque

# 配置路径
SKILL_DIR = Path(__file__).parent
STATE_FILE = SKILL_DIR / "state.json"
CONFIG_FILE = SKILL_DIR / "config.json"
METRICS_FILE = SKILL_DIR / "metrics_history.json"
ALERTS_FILE = SKILL_DIR / "alerts.json"

class EnhancedLisaMonitor:
    """增强版 Lisa 监控器"""

    def __init__(self):
        self.config = self._load_config()
        self.state = self._load_state()
        self.metrics_history = self._load_metrics_history()
        self.alerts = self._load_alerts()
        
        # 滑动窗口用于趋势分析
        self.recent_tokens = deque(maxlen=24)  # 最近24小时
        self.recent_errors = deque(maxlen=24)
        
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
            "response_time_critical_ms": 10000,
            "trend_analysis_hours": 24,
            "anomaly_threshold": 2.0,  # 超过2倍标准差视为异常
            "enable_survival_integration": True
        }

    def _load_state(self) -> Dict:
        """加载状态"""
        if STATE_FILE.exists():
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return self._get_default_state()

    def _get_default_state(self) -> Dict:
        """获取默认状态"""
        return {
            "last_check": None,
            "total_tokens_today": 0,
            "total_requests": 0,
            "errors_today": 0,
            "avg_response_time_ms": 0,
            "health_score": 100,
            "consecutive_errors": 0,
            "last_error_time": None,
            "uptime_hours": 0,
            "session_start": datetime.now().isoformat()
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

    def _load_alerts(self) -> List[Dict]:
        """加载告警历史"""
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []

    def _save_alerts(self):
        """保存告警"""
        # 只保留最近100条告警
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.alerts, f, indent=2, ensure_ascii=False)

    def record_request(self, tokens_used: int, response_time_ms: float, success: bool):
        """记录一次请求"""
        self.state["total_requests"] += 1
        self.state["total_tokens_today"] += tokens_used

        if not success:
            self.state["errors_today"] += 1
            self.state["consecutive_errors"] += 1
            self.state["last_error_time"] = datetime.now().isoformat()
        else:
            self.state["consecutive_errors"] = 0

        # 更新平均响应时间（滑动平均）
        current_avg = self.state["avg_response_time_ms"]
        n = self.state["total_requests"]
        self.state["avg_response_time_ms"] = ((current_avg * (n - 1)) + response_time_ms) / n

        # 更新滑动窗口
        self.recent_tokens.append(tokens_used)
        self.recent_errors.append(1 if not success else 0)
        
        self._save_state()

    def check_new_day(self):
        """检查是否是新的一天"""
        today = datetime.now().date()
        last_check = self.state.get("last_check")

        if last_check:
            last_date = datetime.fromisoformat(last_check).date()
            if last_date != today:
                self._record_daily_metrics()
                self.state = self._get_default_state()
                self.state["last_check"] = datetime.now().isoformat()

    def _record_daily_metrics(self):
        """记录每日指标"""
        if self.state["total_requests"] > 0:
            daily_metrics = {
                "date": datetime.now().date().isoformat(),
                "total_tokens": self.state["total_tokens_today"],
                "total_requests": self.state["total_requests"],
                "errors": self.state["errors_today"],
                "error_rate": self.state["errors_today"] / self.state["total_requests"],
                "avg_response_time_ms": self.state["avg_response_time_ms"],
                "health_score": self.state["health_score"]
            }
            self.metrics_history.append(daily_metrics)
            
            # 只保留最近30天数据
            if len(self.metrics_history) > 720:  # 30天 * 24小时
                self.metrics_history = self.metrics_history[-720:]
                
            with open(METRICS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.metrics_history, f, indent=2, ensure_ascii=False)

    def detect_anomalies(self) -> List[str]:
        """异常检测 - 基于统计方法"""
        anomalies = []
        
        if len(self.metrics_history) < 7:
            return anomalies
            
        # 分析最近7天的数据
        recent = self.metrics_history[-7:]
        
        # 计算标准差
        tokens = [m["total_tokens"] for m in recent]
        avg_tokens = sum(tokens) / len(tokens)
        std_tokens = (sum((x - avg_tokens) ** 2 for x in tokens) / len(tokens)) ** 0.5
        
        # 检查今天是否异常
        if std_tokens > 0:
            z_score = (self.state["total_tokens_today"] - avg_tokens) / std_tokens
            if abs(z_score) > self.config["anomaly_threshold"]:
                anomalies.append(f"Token使用异常: Z-score = {z_score:.2f}")
        
        # 检查连续错误
        if self.state["consecutive_errors"] >= 5:
            anomalies.append(f"连续错误: {self.state['consecutive_errors']}次")
            
        return anomalies

    def predict_resource_needs(self) -> Dict:
        """资源需求预测"""
        if len(self.metrics_history) < 3:
            return {"status": "insufficient_data"}
            
        # 简单线性趋势预测
        recent = self.metrics_history[-7:]
        tokens = [m["total_tokens"] for m in recent]
        
        # 计算日均增长
        if len(tokens) >= 2:
            daily_change = (tokens[-1] - tokens[0]) / len(tokens)
            predicted_next_week = tokens[-1] + daily_change * 7
            
            return {
                "status": "ok",
                "avg_daily_tokens": sum(tokens) / len(tokens),
                "daily_trend": "increasing" if daily_change > 0 else "decreasing",
                "predicted_next_week": max(0, predicted_next_week),
                "trend_strength": abs(daily_change) / (sum(tokens) / len(tokens)) if tokens else 0
            }
        
        return {"status": "insufficient_data"}

    def calculate_health_score(self) -> int:
        """计算健康分数（0-100）"""
        score = 100
        
        # 确保字段存在
        self.state.setdefault("consecutive_errors", 0)
        self.state.setdefault("uptime_hours", 0)
        self.state.setdefault("session_start", datetime.now().isoformat())
        
        # 错误率扣分
        if self.state["total_requests"] > 0:
            error_rate = self.state["errors_today"] / self.state["total_requests"]
            if error_rate > 0.1:
                score -= 30
            elif error_rate > self.config["error_rate_threshold"]:
                score -= 15

        # 响应时间扣分
        avg_time = self.state["avg_response_time_ms"]
        if avg_time > self.config["response_time_critical_ms"]:
            score -= 25
        elif avg_time > self.config["response_time_warning_ms"]:
            score -= 10

        # 连续错误扣分
        consecutive_errors = self.state.get("consecutive_errors", 0)
        if consecutive_errors >= 3:
            score -= 20
            
        # 异常检测扣分
        anomalies = self.detect_anomalies()
        if anomalies:
            score -= len(anomalies) * 5

        return max(0, min(100, score))

    def check_and_trigger_alerts(self) -> List[Dict]:
        """检查并触发告警"""
        new_alerts = []
        score = self.state["health_score"]
        
        # 健康分数告警
        if score < 60:
            new_alerts.append({
                "type": "critical",
                "message": f"健康分数过低: {score}/100",
                "time": datetime.now().isoformat()
            })
        elif score < 80:
            new_alerts.append({
                "type": "warning",
                "message": f"健康分数偏低: {score}/100",
                "time": datetime.now().isoformat()
            })
            
        # 连续错误告警
        if self.state["consecutive_errors"] >= 5:
            new_alerts.append({
                "type": "critical",
                "message": f"连续错误: {self.state['consecutive_errors']}次",
                "time": datetime.now().isoformat()
            })
            
        # 异常检测告警
        anomalies = self.detect_anomalies()
        for anomaly in anomalies:
            new_alerts.append({
                "type": "warning",
                "message": anomaly,
                "time": datetime.now().isoformat()
            })
            
        # 保存新告警
        if new_alerts:
            self.alerts.extend(new_alerts)
            self._save_alerts()
            
        return new_alerts

    def generate_report(self) -> str:
        """生成监控报告"""
        self.check_new_day()
        self.state["last_check"] = datetime.now().isoformat()
        self.state["health_score"] = self.calculate_health_score()
        self._save_state()
        
        # 检查告警
        alerts = self.check_and_trigger_alerts()

        report = []
        report.append("=" * 60)
        report.append("🔬 Lisa 增强型监控报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        # 告警显示
        if alerts:
            report.append("")
            report.append("🚨 告警:")
            for alert in alerts:
                emoji = "🔴" if alert["type"] == "critical" else "🟡"
                report.append(f"  {emoji} {alert['message']}")

        # 基本指标
        report.append("")
        report.append("📊 今日统计:")
        report.append(f"  总请求数: {self.state['total_requests']}")
        report.append(f"  Token消耗: {self.state['total_tokens_today']:,}")
        report.append(f"  错误数: {self.state['errors_today']}")
        report.append(f"  连续错误: {self.state['consecutive_errors']}")

        if self.state["total_requests"] > 0:
            error_rate = self.state["errors_today"] / self.state["total_requests"] * 100
            report.append(f"  错误率: {error_rate:.2f}%")
            report.append(f"  平均响应: {self.state['avg_response_time_ms']:.0f}ms")

        # 健康分数
        score = self.state["health_score"]
        emoji = "💚" if score >= 80 else "💛" if score >= 60 else "❤️"
        report.append("")
        report.append(f"{emoji} 健康分数: {score}/100")

        # 趋势分析
        prediction = self.predict_resource_needs()
        if prediction.get("status") == "ok":
            report.append("")
            report.append("📈 趋势分析:")
            report.append(f"  日均Token: {prediction['avg_daily_tokens']:.0f}")
            report.append(f"  趋势: {prediction['daily_trend']}")
            report.append(f"  预测下周: {prediction['predicted_next_week']:.0f}")

        # 异常检测
        anomalies = self.detect_anomalies()
        if anomalies:
            report.append("")
            report.append("⚠️ 异常检测:")
            for a in anomalies:
                report.append(f"  • {a}")

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)


def main():
    """主函数"""
    monitor = EnhancedLisaMonitor()
    report = monitor.generate_report()
    print(report)
    return monitor.state["health_score"]

if __name__ == "__main__":
    score = main()
    exit(0 if score >= 80 else 1)
