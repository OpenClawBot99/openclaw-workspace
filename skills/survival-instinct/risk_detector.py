#!/usr/bin/env python3
"""
Lisa 生存本能 - 风险检测模块
识别潜在威胁和单点故障
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

STATE_DIR = Path(__file__).parent
THRESHOLDS_FILE = STATE_DIR / "thresholds.json"
RISKS_FILE = STATE_DIR / "risks_state.json"

class RiskDetector:
    """风险检测器"""

    def __init__(self):
        self.thresholds = self._load_thresholds()
        self.risks = self._load_risks()

    def _load_thresholds(self) -> Dict:
        """加载阈值"""
        if THRESHOLDS_FILE.exists():
            with open(THRESHOLDS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "single_point_risk_threshold": 1,
            "backup_min_copies": 2
        }

    def _load_risks(self) -> Dict:
        """加载风险状态"""
        if RISKS_FILE.exists():
            with open(RISKS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "last_check": None,
            "risks": [],
            "risk_level": "unknown"
        }

    def _save_risks(self):
        """保存风险状态"""
        with open(RISKS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.risks, f, indent=2, ensure_ascii=False)

    def check_single_point_failures(self) -> List[Dict]:
        """检查单点故障风险"""
        risks = []

        # 1. API 提供商数量
        api_providers = 2  # zai + minimax
        if api_providers <= self.thresholds["single_point_risk_threshold"]:
            risks.append({
                "type": "single_point",
                "severity": "warning",
                "category": "api_provider",
                "message": f"只有 {api_providers} 个 API 提供商",
                "suggestion": "考虑添加备用 API 提供商"
            })

        # 2. 运行实例数量
        instances = 1  # 当前只有1个实例
        if instances <= self.thresholds["single_point_risk_threshold"]:
            risks.append({
                "type": "single_point",
                "severity": "warning",
                "category": "instance",
                "message": f"只有 {instances} 个运行实例",
                "suggestion": "考虑多实例部署"
            })

        # 3. 数据备份位置
        backup_locations = 2  # 本地 + GitHub
        if backup_locations < self.thresholds["backup_min_copies"]:
            risks.append({
                "type": "single_point",
                "severity": "warning",
                "category": "backup",
                "message": f"只有 {backup_locations} 个备份位置",
                "suggestion": "建议至少3个备份位置（本地、GitHub、云存储）"
            })

        return risks

    def check_resource_exhaustion(self, token_balance: int, daily_usage: int,
                                   account_balance: float) -> List[Dict]:
        """检查资源枯竭风险"""
        risks = []

        # Token 消耗速度
        if daily_usage > 0:
            days_remaining = token_balance / daily_usage

            if days_remaining < 3:
                risks.append({
                    "type": "resource_exhaustion",
                    "severity": "critical" if days_remaining < 1 else "warning",
                    "category": "token",
                    "message": f"Token 将在 {days_remaining:.1f} 天内耗尽",
                    "suggestion": "立即补充 Token 或减少使用"
                })

        # 账户余额趋势
        if account_balance < 10:
            risks.append({
                "type": "resource_exhaustion",
                "severity": "warning",
                "category": "balance",
                "message": f"账户余额较低: ${account_balance:.2f}",
                "suggestion": "及时充值"
            })

        return risks

    def check_service_disruption(self) -> List[Dict]:
        """检查服务中断风险"""
        risks = []

        # 这里可以添加实际的服务检查逻辑
        # 目前只是示例

        return risks

    def run_all_checks(self, token_balance: int = 0, daily_usage: int = 0,
                       account_balance: float = 0) -> List[Dict]:
        """运行所有风险检查"""
        all_risks = []

        all_risks.extend(self.check_single_point_failures())
        all_risks.extend(self.check_resource_exhaustion(
            token_balance, daily_usage, account_balance
        ))
        all_risks.extend(self.check_service_disruption())

        # 保存风险状态
        self.risks["last_check"] = datetime.now().isoformat()
        self.risks["risks"] = all_risks

        # 计算风险等级
        if any(r["severity"] == "critical" for r in all_risks):
            self.risks["risk_level"] = "critical"
        elif any(r["severity"] == "warning" for r in all_risks):
            self.risks["risk_level"] = "warning"
        else:
            self.risks["risk_level"] = "normal"

        self._save_risks()

        return all_risks

    def generate_report(self) -> str:
        """生成风险报告"""
        report = []
        report.append("=" * 60)
        report.append("🔍 Lisa 风险检测报告")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        if not self.risks["risks"]:
            report.append("✅ 未检测到风险")
        else:
            report.append(f"检测到 {len(self.risks['risks'])} 个风险：")
            report.append("")

            for i, risk in enumerate(self.risks["risks"], 1):
                severity_emoji = "⚠️" if risk["severity"] == "warning" else "🚨"
                report.append(f"{i}. {severity_emoji} {risk['message']}")
                report.append(f"   类型: {risk['type']}")
                report.append(f"   建议: {risk['suggestion']}")
                report.append("")

        report.append(f"风险等级: {self.risks['risk_level'].upper()}")
        report.append("=" * 60)

        return "\n".join(report)

def main():
    """主函数"""
    detector = RiskDetector()

    # 示例：运行检查（实际使用时需要真实数据）
    # detector.run_all_checks(
    #     token_balance=25000,
    #     daily_usage=10000,
    #     account_balance=15.0
    # )

    # 检查单点故障（不需要外部数据）
    detector.run_all_checks()

    report = detector.generate_report()
    print(report)

if __name__ == "__main__":
    main()
