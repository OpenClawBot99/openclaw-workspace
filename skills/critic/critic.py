#!/usr/bin/env python3
"""
Lisa 自我批评家
检验循环输出，批评自身不足
"""

import random
from datetime import datetime

class Critic:
    """自我批评家"""
    
    def __init__(self):
        self.criteria = {
            "content_quality": ["空洞", "表面", "缺乏深度"],
            "closed_loop": ["只有计划", "没有结果", "缺乏沉淀"],
            "resource_mgmt": ["浪费资源", "忽略成本", "效率低下"],
            "actionability": ["无法执行", "过于抽象", "缺乏具体"]
        }
        
    def review(self, task_output: str) -> dict:
        """审查输出"""
        
        # 模拟批评（实际使用时分析输入）
        issues = []
        strengths = []
        
        # 检查是否只有计划
        if "计划" in task_output and "结果" not in task_output:
            issues.append("❌ 只有计划，缺乏实际执行结果")
        
        # 检查是否空洞
        if len(task_output) < 100:
            issues.append("❌ 输出内容过于简短，可能缺乏深度")
        
        # 检查是否有具体产出
        if "代码" not in task_output and "文档" not in task_output and "笔记" not in task_output:
            issues.append("❌ 缺乏具体产出（代码/文档/笔记）")
        
        # 检查资源管理
        if "磁盘" not in task_output and "内存" not in task_output:
            issues.append("⚠️ 缺乏资源管理意识")
        
        # 随机优点
        if not issues:
            strengths.append("✅ 输出结构完整")
            strengths.append("✅ 有明确的行动计划")
        
        # 改进建议
        suggestions = []
        if issues:
            suggestions.append("📝 增加具体产出（代码/文档）")
            suggestions.append("🎯 将目标分解为可执行步骤")
            suggestions.append("💾 沉淀到知识库")
        
        return {
            "time": datetime.now().isoformat(),
            "strengths": strengths,
            "issues": issues,
            "suggestions": suggestions,
            "score": max(0, 100 - len(issues) * 20)
        }
    
    def auto_critic(self) -> dict:
        """自动批评模式"""
        
        # 模拟对最近输出的批评
        return {
            "time": datetime.now().isoformat(),
            "strengths": [
                "✅ 建立了智能任务生成系统",
                "✅ 创建了磁盘监控技能",
                "✅ 有详细输出格式意识"
            ],
            "issues": [
                "❌ 循环中实际执行的任务较少",
                "❌ 缺乏对GitHub项目的实际复现",
                "❌ 资源管理刚起步，未集成到循环"
            ],
            "suggestions": [
                "📝 下一个循环必须执行具体任务",
                "🎯 找到一个GitHub项目并复现",
                "💾 将disk-monitor集成到定时检查"
            ],
            "score": 60
        }

def demo():
    """演示"""
    critic = Critic()
    
    print("=" * 60)
    print("🔍 Lisa 自我批评家")
    print("=" * 60)
    
    result = critic.auto_critic()
    
    print(f"\n⏰ 时间: {result['time']}")
    print(f"\n✅ 优点:")
    for s in result["strengths"]:
        print(f"   {s}")
    
    print(f"\n❌ 不足:")
    for i in result["issues"]:
        print(f"   {i}")
    
    print(f"\n💡 改进建议:")
    for s in result["suggestions"]:
        print(f"   {s}")
    
    print(f"\n📊 自评分数: {result['score']}/100")
    
    print("\n" + "=" * 60)
    print("💪 批评是为了更好的进化！")
    print("=" * 60)

if __name__ == "__main__":
    demo()
