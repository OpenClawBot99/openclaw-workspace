#!/usr/bin/env python3
"""
Lisa 自我批评家 v2 - 闭环进化版
每次循环后自动调用，先肯定后否定，提供具体解决方案
"""

import random
from datetime import datetime
from pathlib import Path

class CriticV2:
    """自我批评家 v2 - 闭环进化版"""
    
    def __init__(self):
        self.severity_levels = ["strict", "light", "medium"]
        self.history = []
        
    def get_severity(self):
        """随机选择批评强度"""
        return random.choice(self.severity_levels)
    
    def critique(self, task_output: str, previous_critic: dict = None) -> dict:
        """完整批评流程"""
        
        severity = self.get_severity()
        
        # 1. 先肯定 - 找出做对的地方
        positives = self._find_positives(task_output)
        
        # 2. 后否定 - 找出不足
        negatives = self._find_negatives(task_output)
        
        # 3. 分析原因
        reasons = self._analyze_reasons(negatives)
        
        # 4. 提供解决方案
        solutions = self._provide_solutions(negatives, severity)
        
        # 5. 下一步具体改进计划
        next_steps = self._plan_next_steps(negatives, solutions)
        
        # 6. 计算分数
        score = self._calculate_score(positives, negatives, severity)
        
        # 7. 迭代检查 - 对比上次批评
        improvement = self._check_improvement(previous_critic, score)
        
        result = {
            "time": datetime.now().isoformat(),
            "severity": severity,
            "positives": positives,
            "negatives": negatives,
            "reasons": reasons,
            "solutions": solutions,
            "next_steps": next_steps,
            "score": score,
            "improvement": improvement
        }
        
        self.history.append(result)
        
        return result
    
    def _find_positives(self, task_output: str) -> list:
        """找出优点"""
        positives = []
        
        # 检查输出结构
        if "学习要点" in task_output or "📌" in task_output:
            positives.append("✅ 有学习要点输出")
        if "🔧" in task_output or "落地措施" in task_output:
            positives.append("✅ 有落地措施")
        if "落地措施" "知识库" in task_output or "📚" in task_output:
            positives.append("✅ 有知识库沉淀")
        if "目标" in task_output or "🎯" in task_output:
            positives.append("✅ 有明确目标")
        if "下一步" in task_output or "➡️" in task_output:
            positives.append("✅ 有下一步建议")
            
        # 检查具体内容
        if "Skill" in task_output or "skill" in task_output:
            positives.append("✅ 输出了Skill")
        if "代码" in task_output:
            positives.append("✅ 有代码产出")
            
        return positives if positives else ["✅ 参与了循环"]
    
    def _find_negatives(self, task_output: str) -> list:
        """找出不足"""
        negatives = []
        
        # 检查是否空洞
        if len(task_output) < 200:
            negatives.append("❌ 输出内容过于简短")
        if "计划" in task_output and "结果" not in task_output:
            negatives.append("❌ 只有计划，缺乏实际结果")
            
        # 检查具体产出
        if "代码" not in task_output and "代码" not in task_output:
            negatives.append("❌ 缺乏代码产出")
        if "Skill" not in task_output and "skill" not in task_output:
            negatives.append("❌ 没有创建新Skill")
            
        # 检查深度
        if task_output.count("\n") < 5:
            negatives.append("❌ 缺乏深度分析")
            
        # 资源管理
        if "磁盘" not in task_output and "资源" not in task_output:
            negatives.append("⚠️ 缺乏资源管理意识")
            
        return negatives if negatives else ["✅ 基本无明显不足"]
    
    def _analyze_reasons(self, negatives: list) -> list:
        """分析原因"""
        reasons = []
        
        for neg in negatives:
            if "简短" in neg:
                reasons.append("📌 原因：没有具体展开内容，缺乏深度")
            elif "计划" in neg:
                reasons.append("📌 原因：停留在表面，未深入执行")
            elif "代码" in neg:
                reasons.append("📌 原因：动手能力不足，过于理论化")
            elif "Skill" in neg:
                reasons.append("📌 原因：创新产出不足")
            elif "资源" in neg:
                reasons.append("📌 原因：缺乏资源管理意识")
                
        return reasons if reasons else ["✅ 暂无明显原因"]
    
    def _provide_solutions(self, negatives: list, severity: str) -> list:
        """提供解决方案"""
        solutions = []
        
        for neg in negatives:
            if "简短" in neg:
                solutions.append("💊 药方：每个要点展开说明，包含具体例子")
            elif "计划" in neg:
                solutions.append("💊 药方：立即执行一个具体任务，输出实际结果")
            elif "代码" in neg:
                solutions.append("💊 药方：找到一个简单项目，立即复现代码")
            elif "Skill" in neg:
                solutions.append("💊 药方：设计并创建一个小型Skill")
            elif "资源" in neg:
                solutions.append("💊 药方：运行disk-monitor，检查资源状态")
                
        return solutions if solutions else ["✅ 保持当前状态"]
    
    def _plan_next_steps(self, negatives: list, solutions: list) -> list:
        """下一步具体计划"""
        next_steps = []
        
        # 根据问题安排下一步
        if any("代码" in n for n in negatives):
            next_steps.append("🎯 下一步：找到一个GitHub项目，立即复现")
        if any("Skill" in n for n in negatives):
            next_steps.append("🎯 下一步：设计一个简单Skill并实现")
        if any("资源" in n for n in negatives):
            next_steps.append("🎯 下一步：运行disk-monitor")
            
        if not next_steps:
            next_steps.append("🎯 下一步：继续保持详细输出格式")
            
        return next_steps
    
    def _calculate_score(self, positives: list, negatives: list, severity: str) -> int:
        """计算分数"""
        base = 50
        base += len(positives) * 10
        base -= len([n for n in negatives if "❌" in n]) * 15
        
        if severity == "strict":
            base -= 10
        elif severity == "light":
            base += 5
            
        return max(0, min(100, base))
    
    def _check_improvement(self, previous: dict, current_score: int) -> str:
        """检查改进"""
        if not previous:
            return "📈 首次评分，无对比"
            
        prev_score = previous.get("score", 0)
        diff = current_score - prev_score
        
        if diff > 10:
            return f"📈 显著进步! +{diff}分"
        elif diff > 0:
            return f"📈 有进步 +{diff}分"
        elif diff == 0:
            return "➡️ 持平"
        else:
            return f"📉 退步 {diff}分"
    
    def run_critique(self, task_output: str = "") -> dict:
        """运行批评"""
        
        # 获取上次批评
        previous = self.history[-1] if self.history else None
        
        # 运行批评
        result = self.critique(task_output, previous)
        
        return result

def demo():
    """演示"""
    critic = CriticV2()
    
    print("=" * 70)
    print("🔍 Lisa 自我批评家 v2 - 闭环进化版")
    print("=" * 70)
    
    # 模拟上次输出
    sample_output = """
    🎯 当前任务：完善 vllm Skill
    📌 学习要点：vLLM 是大模型推理加速引擎
    🔧 落地措施：创建 vLLM Skill 框架
    📚 知识库：memory/vllm-basics.md
    """
    
    result = critic.run_critique(sample_output)
    
    print(f"\n⏰ 时间: {result['time']}")
    print(f"🔧 批评强度: {result['severity']}")
    
    print(f"\n✅ 肯定（先找优点）:")
    for p in result["positives"]:
        print(f"   {p}")
    
    print(f"\n❌ 否定（后找不足）:")
    for n in result["negatives"]:
        print(f"   {n}")
    
    print(f"\n📌 原因分析:")
    for r in result["reasons"]:
        print(f"   {r}")
    
    print(f"\n💊 解决方案（有病要开药方）:")
    for s in result["solutions"]:
        print(f"   {s}")
    
    print(f"\n🎯 下一步计划:")
    for step in result["next_steps"]:
        print(f"   {step}")
    
    print(f"\n📊 评分: {result['score']}/100")
    print(f"{result['improvement']}")
    
    print("\n" + "=" * 70)
    print("💪 批评是为了更好的进化！闭环迭代，确保疗效！")
    print("=" * 70)

if __name__ == "__main__":
    demo()
