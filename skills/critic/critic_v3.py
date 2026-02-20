#!/usr/bin/env python3
"""
Lisa 自我批评家 v3 - 深度进化版
每次迭代后自我完善，模板动态更新
"""

import random
from datetime import datetime
from pathlib import Path

class CriticV3:
    """自我批评家 v3 - 深度进化版"""
    
    def __init__(self):
        self.version = "v3"
        self.iteration = 0
        
        # 详细模板 - 可动态更新
        self.template = {
            "positive_criteria": {
                "structure": ["有学习要点", "有落地措施", "有知识库", "有目标", "有下一步"],
                "content": ["有代码", "有Skill", "有文档", "有笔记"],
                "depth": ["有原因分析", "有具体例子", "有数据支撑", "有对比"],
                "action": ["有执行结果", "有验证过程", "有产出", "有测试"]
            },
            "negative_criteria": {
                "brevity": ["内容过于简短", "缺乏展开", "缺乏细节"],
                "theory": ["只有理论", "缺乏实践", "未动手"],
                "output": ["无代码", "无Skill", "无文档"],
                "resource": ["无资源检查", "无成本意识", "无优化"],
                "loop": ["无闭环", "无反思", "无改进"]
            },
            "solutions": {
                "brevity": "每个要点展开，包含具体例子、数据、对比",
                "theory": "立即动手，找项目复现，不要只看",
                "output": "设计并实现一个具体Skill或代码模块",
                "resource": "运行disk-monitor，检查资源使用",
                "loop": "调用critic进行自我批评，形成闭环"
            }
        }
        
        self.history = []
        
    def evolve_template(self):
        """根据历史迭代模板"""
        self.iteration += 1
        
        # 分析历史不足
        if len(self.history) >= 3:
            # 找出最常见的不足
            all_negatives = []
            for h in self.history:
                all_negatives.extend(h.get("negatives", []))
            
            # 强化批评维度
            if "缺乏代码产出" in all_negatives:
                self.template["positive_criteria"]["action"].append("已执行代码")
            if "资源管理" in str(all_negatives):
                self.template["positive_criteria"]["resource"].append("有资源管理")
                
        print(f"🔄 模板已进化 (迭代 {self.iteration})")
    
    def critique(self, task_output: str) -> dict:
        """完整批评流程"""
        self.evolve_template()
        
        # 1. 详细检查每个维度
        positives = self._deep_check_positives(task_output)
        negatives = self._deep_check_negatives(task_output)
        
        # 2. 原因分析 - 每个不足都要有原因
        reasons = []
        for neg in negatives:
            reason = self._analyze_reason(neg, task_output)
            if reason:
                reasons.append(reason)
        
        # 3. 解决方案 - 每个问题都有药方
        solutions = []
        for neg in negatives:
            sol = self._get_solution(neg)
            if sol:
                solutions.append(sol)
        
        # 4. 下一步计划 - 具体可执行
        next_steps = self._plan_next_steps(negatives, solutions)
        
        # 5. 计算分数
        score = self._calculate_detailed_score(positives, negatives)
        
        result = {
            "iteration": self.iteration,
            "time": datetime.now().isoformat(),
            "positives": positives,
            "negatives": negatives,
            "reasons": reasons,
            "solutions": solutions,
            "next_steps": next_steps,
            "score": score,
            "template_used": len(self.template["positive_criteria"])
        }
        
        self.history.append(result)
        
        return result
    
    def _deep_check_positives(self, output: str) -> list:
        """深度检查优点"""
        positives = []
        
        # 结构检查
        for item in self.template["positive_criteria"]["structure"]:
            if item in output:
                positives.append(f"✅ {item}")
        
        # 内容检查
        for item in self.template["positive_criteria"]["content"]:
            if item in output:
                positives.append(f"✅ {item}")
        
        # 深度检查
        for item in self.template["positive_criteria"]["depth"]:
            if item in output:
                positives.append(f"✅ {item}")
        
        # 行动检查
        for item in self.template["positive_criteria"]["action"]:
            if item in output:
                positives.append(f"✅ {item}")
                
        return positives if positives else ["✅ 参与了循环"]
    
    def _deep_check_negatives(self, output: str) -> list:
        """深度检查不足"""
        negatives = []
        
        # 检查空洞
        if len(output) < 200:
            negatives.append("❌ 输出内容过于简短（<200字）")
        if output.count("\n") < 5:
            negatives.append("❌ 缺乏结构化（<5行）")
            
        # 检查理论化
        keywords_theory = ["学习", "理解", "掌握", "调研"]
        keywords_action = ["代码", "实现", "复现", "创建", "测试"]
        
        has_theory = any(k in output for k in keywords_theory)
        has_action = any(k in output for k in keywords_action)
        
        if has_theory and not has_action:
            negatives.append("❌ 只有理论，缺乏实践行动")
            
        # 检查产出
        if "代码" not in output and "实现" not in output:
            negatives.append("❌ 缺乏代码产出")
        if "Skill" not in output and "skill" not in output:
            negatives.append("❌ 没有创建Skill")
            
        # 检查资源
        if "磁盘" not in output and "内存" not in output and "资源" not in output:
            negatives.append("⚠️ 缺乏资源管理")
            
        # 检查闭环
        if "批评" not in output and "反思" not in output:
            negatives.append("⚠️ 缺乏自我批评")
            
        return negatives if negatives else ["✅ 基本无明显不足"]
    
    def _analyze_reason(self, negative: str, output: str) -> str:
        """分析原因"""
        if "简短" in negative:
            return f"📌 原因：输出太短，未能详细展开说明"
        elif "理论" in negative or "实践" in negative:
            return f"📌 原因：停留在理论学习，未动手实践"
        elif "代码" in negative or "Skill" in negative:
            return f"📌 原因：只规划不行动，缺乏实际产出"
        elif "资源" in negative:
            return f"📌 原因：没有资源管理意识"
        elif "闭环" in negative or "批评" in negative:
            return f"📌 原因：缺乏自我审视和迭代改进"
        else:
            return f"📌 原因：需要更深入分析"
    
    def _get_solution(self, negative: str) -> str:
        """获取解决方案"""
        if "简短" in negative:
            return "💊 药方：每个要点展开，包含具体例子、数据、对比，至少200字"
        elif "理论" in negative or "实践" in negative:
            return "💊 药方：找到一个GitHub项目，立即动手复现，不要只看"
        elif "代码" in negative or "Skill" in negative:
            return "💊 药方：设计并实现一个具体Skill或代码模块，输出可运行代码"
        elif "资源" in negative:
            return "💊 药方：运行disk-monitor，检查磁盘/内存使用"
        elif "闭环" in negative or "批评" in negative:
            return "💊 药方：调用critic进行自我批评，形成闭环"
        else:
            return "💊 药方：深入分析问题本质"
    
    def _plan_next_steps(self, negatives: list, solutions: list) -> list:
        """下一步具体计划"""
        next_steps = []
        
        # 根据问题优先级安排
        priority_map = {
            "代码": "🎯 下一步：找到一个简单GitHub项目，2小时内完成复现",
            "Skill": "🎯 下一步：设计并实现一个小型Skill，输出可测试代码",
            "资源": "🎯 下一步：运行disk-monitor，检查资源状态",
            "理论": "🎯 下一步：停止理论学习，立即动手实践",
            "闭环": "🎯 下一步：调用critic进行深度批评"
        }
        
        for neg in negatives:
            for key, action in priority_map.items():
                if key in neg and action not in next_steps:
                    next_steps.append(action)
                    break
        
        if not next_steps:
            next_steps.append("🎯 下一步：继续保持当前详细输出格式")
            
        return next_steps
    
    def _calculate_detailed_score(self, positives: list, negatives: list) -> int:
        """详细评分"""
        base = 50
        
        # 优点加分
        base += len(positives) * 8
        
        # 严重问题扣分
        severe = [n for n in negatives if "❌" in n]
        base -= len(severe) * 15
        
        # 警告问题扣分
        warning = [n for n in negatives if "⚠️" in n]
        base -= len(warning) * 5
        
        return max(0, min(100, base))

def demo():
    """演示"""
    critic = CriticV3()
    
    print("=" * 70)
    print("🔍 Lisa 自我批评家 v3 - 深度进化版")
    print("=" * 70)
    
    # 模拟更详细的输出
    sample = """
    🎯 任务：完善 linux Skill
    📌 学习要点：linux是系统基础
    🔧 落地措施：创建 skills/linux-manager/
    ✅ 已有代码产出
    📚 知识库：memory/linux.md
    """
    
    result = critic.critique(sample)
    
    print(f"\n迭代: {result['iteration']}")
    print(f"评分: {result['score']}/100")
    
    print(f"\n✅ 优点 ({len(result['positives'])}项):")
    for p in result["positives"]:
        print(f"   {p}")
    
    print(f"\n❌ 不足 ({len(result['negatives'])}项):")
    for n in result["negatives"]:
        print(f"   {n}")
    
    print(f"\n📌 原因分析:")
    for r in result["reasons"]:
        print(f"   {r}")
    
    print(f"\n💊 解决方案:")
    for s in result["solutions"]:
        print(f"   {s}")
    
    print(f"\n🎯 下一步计划:")
    for step in result["next_steps"]:
        print(f"   {step}")

if __name__ == "__main__":
    demo()
