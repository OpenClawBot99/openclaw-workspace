#!/usr/bin/env python3
"""
Lisa 生存本能 - 应急预案模块
定义和执行应急预案
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

STATE_DIR = Path(__file__).parent
EMERGENCY_FILE = STATE_DIR / "emergency_plans.json"

class EmergencyPlan:
    """应急预案管理器"""

    def __init__(self):
        self.plans = self._load_plans()

    def _load_plans(self) -> Dict:
        """加载应急预案"""
        if EMERGENCY_FILE.exists():
            with open(EMERGENCY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "plans": self._get_default_plans(),
            "last_triggered": None,
            "trigger_history": []
        }

    def _get_default_plans(self) -> List[Dict]:
        """获取默认应急预案"""
        return [
            {
                "id": "token_critical",
                "name": "Token 严重不足",
                "trigger": "token_days < 1",
                "actions": [
                    "自动降级到更便宜的模型",
                    "暂停非必要操作",
                    "通知杜斌"
                ],
                "priority": 1
            },
            {
                "id": "token_emergency",
                "name": "Token 危机状态",
                "trigger": "token_days < 0.5",
                "actions": [
                    "立即停止所有非关键操作",
                    "紧急通知杜斌",
                    "准备进入休眠模式"
                ],
                "priority": 0
            },
            {
                "id": "api_failure",
                "name": "API 服务商故障",
                "trigger": "api_connection_failed",
                "actions": [
                    "自动切换到备用 API",
                    "记录故障信息",
                    "监控恢复状态"
                ],
                "priority": 1
            },
            {
                "id": "data_loss_risk",
                "name": "数据丢失风险",
                "trigger": "backup_overdue",
                "actions": [
                    "立即全量备份到 GitHub",
                    "创建本地快照",
                    "通知杜斌"
                ],
                "priority": 2
            }
        ]

    def _save_plans(self):
        """保存应急预案"""
        with open(EMERGENCY_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.plans, f, indent=2, ensure_ascii=False)

    def get_plan(self, plan_id: str) -> Dict:
        """获取指定预案"""
        for plan in self.plans["plans"]:
            if plan["id"] == plan_id:
                return plan
        return None

    def trigger_plan(self, plan_id: str, reason: str = "") -> Dict:
        """触发应急预案"""
        plan = self.get_plan(plan_id)
        if not plan:
            return {"success": False, "message": f"预案 {plan_id} 不存在"}

        # 记录触发历史
        trigger_record = {
            "plan_id": plan_id,
            "plan_name": plan["name"],
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "actions": plan["actions"]
        }

        self.plans["last_triggered"] = trigger_record
        self.plans["trigger_history"].append(trigger_record)

        # 只保留最近50次记录
        if len(self.plans["trigger_history"]) > 50:
            self.plans["trigger_history"] = self.plans["trigger_history"][-50:]

        self._save_plans()

        return {
            "success": True,
            "plan": plan,
            "message": f"应急预案 '{plan['name']}' 已触发"
        }

    def list_plans(self) -> List[Dict]:
        """列出所有预案"""
        return sorted(self.plans["plans"], key=lambda x: x["priority"])

    def generate_report(self) -> str:
        """生成应急预案报告"""
        report = []
        report.append("=" * 60)
        report.append("🚨 Lisa 应急预案系统")
        report.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        report.append("可用应急预案：")
        for plan in self.list_plans():
            report.append(f"\n📋 {plan['name']} (优先级: {plan['priority']})")
            report.append(f"   触发条件: {plan['trigger']}")
            report.append("   行动:")
            for action in plan["actions"]:
                report.append(f"   - {action}")

        if self.plans["last_triggered"]:
            report.append("")
            report.append("最近触发:")
            last = self.plans["last_triggered"]
            report.append(f"  {last['plan_name']} - {last['timestamp']}")
            report.append(f"  原因: {last['reason']}")

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)

def main():
    """主函数"""
    emergency = EmergencyPlan()

    # 显示所有预案
    report = emergency.generate_report()
    print(report)

    # 示例：触发预案（测试用）
    # result = emergency.trigger_plan("token_critical", "测试触发")
    # print(f"\n触发结果: {result}")

if __name__ == "__main__":
    main()
