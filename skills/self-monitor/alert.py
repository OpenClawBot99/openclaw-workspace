#!/usr/bin/env python3
"""
Lisa 预警系统
自动检测异常并发送告警
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict

STATE_FILE = Path(__file__).parent / "state.json"
CONFIG_FILE = Path(__file__).parent / "config.json"
ALERTS_FILE = Path(__file__).parent / "alerts.json"

class LisaAlerter:
    """Lisa 预警系统"""

    def __init__(self):
        self.config = self._load_config()
        self.state = self._load_state()
        self.alerts = self._load_alerts()

    def _load_config(self) -> Dict:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def _load_state(self) -> Dict:
        if STATE_FILE.exists():
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def _load_alerts(self) -> List[Dict]:
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []

    def check_alerts(self) -> List[Dict]:
        """检查是否需要告警"""
        new_alerts = []

        # 1. 检查健康分数
        health_score = self.state.get("health_score", 100)
        if health_score < self.config.get("health_score_critical", 60):
            new_alerts.append({
                "level": "critical",
                "type": "health_score",
                "message": f"健康分数严重偏低: {health_score}/100",
                "timestamp": datetime.now().isoformat()
            })
        elif health_score < self.config.get("health_score_warning", 80):
            new_alerts.append({
                "level": "warning",
                "type": "health_score",
                "message": f"健康分数偏低: {health_score}/100",
                "timestamp": datetime.now().isoformat()
            })

        # 2. 检查错误率
        total_requests = self.state.get("total_requests", 0)
        errors_today = self.state.get("errors_today", 0)

        if total_requests > 0:
            error_rate = errors_today / total_requests
            if error_rate > self.config.get("error_rate_threshold", 0.05):
                new_alerts.append({
                    "level": "warning",
                    "type": "error_rate",
                    "message": f"错误率过高: {error_rate*100:.2f}%",
                    "timestamp": datetime.now().isoformat()
                })

        # 3. 检查响应时间
        avg_response = self.state.get("avg_response_time_ms", 0)
        if avg_response > self.config.get("response_time_critical_ms", 10000):
            new_alerts.append({
                "level": "critical",
                "type": "response_time",
                "message": f"响应时间过长: {avg_response:.0f}ms",
                "timestamp": datetime.now().isoformat()
            })
        elif avg_response > self.config.get("response_time_warning_ms", 3000):
            new_alerts.append({
                "level": "warning",
                "type": "response_time",
                "message": f"响应时间偏慢: {avg_response:.0f}ms",
                "timestamp": datetime.now().isoformat()
            })

        return new_alerts

    def send_alert(self, alert: Dict):
        """发送告警（打印到控制台）"""
        level_emoji = {
            "critical": "🚨",
            "warning": "⚠️",
            "info": "ℹ️"
        }

        emoji = level_emoji.get(alert["level"], "❗")
        print(f"{emoji} [{alert['level'].upper()}] {alert['message']}")
        print(f"   时间: {alert['timestamp']}")

    def run(self):
        """运行预警检查"""
        print("=" * 60)
        print("Lisa 预警检查")
        print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print()

        new_alerts = self.check_alerts()

        if new_alerts:
            print(f"检测到 {len(new_alerts)} 个告警：")
            print()
            for alert in new_alerts:
                self.send_alert(alert)
                print()

            # 保存告警历史
            self.alerts.extend(new_alerts)
            with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.alerts[-100:], f, indent=2, ensure_ascii=False)  # 保留最近100条

            return False
        else:
            print("✅ 没有检测到告警，系统运行正常")
            return True

if __name__ == "__main__":
    alerter = LisaAlerter()
    alerter.run()
