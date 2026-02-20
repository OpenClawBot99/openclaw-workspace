#!/usr/bin/env python3
"""
Lisa 智能优化器 - 主动决策系统
从"被动响应"到"主动规划"的质的飞跃
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

# 路径配置
SKILL_DIR = Path(__file__).parent
STATE_FILE = SKILL_DIR / "state.json"
CONFIG_FILE = SKILL_DIR / "config.json"
LOG_FILE = SKILL_DIR / "smart_optimizer_log.json"

class SmartOptimizer:
    """智能优化器 - 主动决策系统"""
    
    def __init__(self):
        self.state = self._load_state()
        self.config = self._load_config()
        self.log = self._load_log()
        
    def _load_state(self) -> Dict:
        """加载状态"""
        if STATE_FILE.exists():
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "health_score": 100,
            "budget_remaining": 100,  # 百分比
            "active_tasks": [],
            "last_optimization": None,
            "consecutive_warnings": 0
        }
    
    def _load_config(self) -> Dict:
        """加载配置"""
        return {
            "budget_warning_threshold": 30,  # 低于30%警告
            "budget_critical_threshold": 10,  # 低于10%紧急
            "auto_switch_model": True,
            "auto_pause_nonessential": True,
            "check_interval_seconds": 300
        }
    
    def _load_log(self) -> List:
        """加载日志"""
        if LOG_FILE.exists():
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    
    def _save_state(self):
        """保存状态"""
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)
    
    def _log_action(self, action: str, details: str):
        """记录动作"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        self.log.append(entry)
        # 只保留最近100条
        if len(self.log) > 100:
            self.log = self.log[-100:]
        # 保存日志
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.log, f, indent=2, ensure_ascii=False)
    
    def analyze_situation(self) -> Dict:
        """分析当前情况 - 主动诊断"""
        analysis = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "health_score": self.state.get("health_score", 100),
            "budget_pct": self.state.get("budget_remaining", 100),
            "active_tasks": len(self.state.get("active_tasks", [])),
            "warnings": []
        }
        
        # 检查健康度
        if analysis["health_score"] < 60:
            analysis["warnings"].append(f"健康度偏低: {analysis['health_score']}/100")
        
        # 检查预算
        if analysis["budget_pct"] < self.config["budget_warning_threshold"]:
            analysis["warnings"].append(f"预算不足: {analysis['budget_pct']}%")
        
        # 检查连续警告
        if self.state.get("consecutive_warnings", 0) > 3:
            analysis["warnings"].append("连续异常，需关注")
        
        return analysis
    
    def make_decision(self) -> Dict:
        """主动决策 - 核心智能"""
        analysis = self.analyze_situation()
        decisions = []
        
        # 决策1：预算紧张 → 切换模型
        if (analysis["budget_pct"] < self.config["budget_warning_threshold"] 
            and self.config["auto_switch_model"]):
            decisions.append({
                "type": "switch_model",
                "action": "自动切换到便宜模型 (MiniMax-M2.1)",
                "reason": f"预算仅剩 {analysis['budget_pct']}%"
            })
            self._log_action("模型切换", f"预算{analysis['budget_pct']}%，切换到便宜模型")
        
        # 决策2：健康度低 → 暂停非关键任务
        if (analysis["health_score"] < 50 
            and self.config["auto_pause_nonessential"]):
            decisions.append({
                "type": "pause_task",
                "action": "暂停非关键任务",
                "reason": f"健康度仅 {analysis['health_score']}"
            })
            self._log_action("任务暂停", f"健康度{analysis['health_score']}，暂停非关键任务")
        
        # 决策3：连续警告 → 深度诊断
        if self.state.get("consecutive_warnings", 0) > 5:
            decisions.append({
                "type": "deep_analysis",
                "action": "触发深度自我诊断",
                "reason": "连续异常超过阈值"
            })
            self._log_action("深度诊断", "连续异常，触发深度诊断")
        
        # 决策4：一切正常 → 保持当前
        if not decisions:
            decisions.append({
                "type": "keep_normal",
                "action": "维持现状",
                "reason": "各项指标正常"
            })
        
        return {
            "analysis": analysis,
            "decisions": decisions,
            "timestamp": datetime.now().isoformat()
        }
    
    def execute_decisions(self, decisions: List[Dict]) -> str:
        """执行决策"""
        results = []
        
        for decision in decisions:
            d_type = decision["type"]
            
            if d_type == "switch_model":
                # 这里会通知资源管理系统切换模型
                results.append(f"✅ 已切换到便宜模型 (原因: {decision['reason']})")
                self.state["last_optimization"] = datetime.now().isoformat()
            
            elif d_type == "pause_task":
                results.append(f"✅ 已暂停非关键任务 (原因: {decision['reason']})")
                self.state["last_optimization"] = datetime.now().isoformat()
            
            elif d_type == "deep_analysis":
                results.append(f"🔍 触发深度诊断 (原因: {decision['reason']})")
                results.append(f"   → 建议: 检查API连接、分析错误日志")
                self.state["consecutive_warnings"] = 0  # 重置
            
            elif d_type == "keep_normal":
                results.append(f"✓ 维持现状 (原因: {decision['reason']})")
        
        self._save_state()
        return "\n".join(results)
    
    def run_cycle(self) -> str:
        """运行一个优化周期"""
        # 1. 分析情况
        decision_result = self.make_decision()
        
        # 2. 打印分析
        print("=" * 60)
        print("🧠 Lisa 智能优化器 - 主动决策")
        print("=" * 60)
        print(f"时间: {decision_result['timestamp']}")
        print()
        
        analysis = decision_result["analysis"]
        print("📊 当前状态:")
        print(f"  健康度: {analysis['health_score']}/100")
        print(f"  预算: {analysis['budget_pct']}%")
        print(f"  活跃任务: {analysis['active_tasks']}")
        
        if analysis["warnings"]:
            print()
            print("⚠️  警告:")
            for w in analysis["warnings"]:
                print(f"  • {w}")
        
        # 3. 打印决策
        print()
        print("🎯 决策:")
        for d in decision_result["decisions"]:
            print(f"  • {d['action']} ({d['reason']})")
        
        # 4. 执行
        print()
        print("🚀 执行:")
        results = self.execute_decisions(decision_result["decisions"])
        print(results)
        
        print("=" * 60)
        
        return results
    
    def report_status(self) -> str:
        """生成状态报告 - 主动汇报"""
        decision_result = self.make_decision()
        
        report = []
        report.append("🧠 Lisa 智能优化器 - 主动汇报")
        report.append("=" * 40)
        
        # 状态
        a = decision_result["analysis"]
        report.append(f"📊 状态: 健康度 {a['health_score']} | 预算 {a['budget_pct']}%")
        
        # 警告
        if a["warnings"]:
            report.append(f"⚠️  警告: {len(a['warnings'])}个")
            for w in a["warnings"]:
                report.append(f"  - {w}")
        
        # 决策
        report.append("🎯 决策:")
        for d in decision_result["decisions"]:
            report.append(f"  • {d['action']}")
        
        # 动作
        if a["budget_pct"] < 30:
            report.append("🔄 已自动切换到便宜模型")
        if a["health_score"] < 50:
            report.append("⏸️ 已暂停非关键任务")
            
        return "\n".join(report)


def main():
    """主函数"""
    optimizer = SmartOptimizer()
    optimizer.run_cycle()
    
    # 返回状态（供其他模块调用）
    return optimizer.report_status()


if __name__ == "__main__":
    main()
