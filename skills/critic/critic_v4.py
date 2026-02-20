#!/usr/bin/env python3
"""
Lisa 自我批评家 v4 - 力度加强版
直接、犀利、不客气
"""

import random
from datetime import datetime

class CriticV4:
    """犀利批评家 v4"""
    
    def __init__(self):
        self.iteration = 0
        self.history = []
        
    def criticize(self, task_output: str, context: str = "") -> dict:
        """直接犀利的批评"""
        
        self.iteration += 1
        
        # 1. 评估输出质量
        issues = []
        score = 50  # 基础分
        
        # 检查问题
        if not task_output or len(task_output) < 100:
            issues.append("字数太少，根本没内容！")
            score -= 20
        
        if "计划" in task_output and "完成" not in task_output:
            issues.append("光计划不执行有个屁用！")
            score -= 15
            
        if "学习" in task_output and "代码" not in task_output:
            issues.append("光学不动手，就是浪费时间！")
            score -= 15
            
        if "反思" not in task_output and "批评" not in task_output:
            issues.append("一点自我批评都没有，怎么进步？")
            score -= 10
            
        if "output" not in task_output.lower() and "产出" not in task_output:
            issues.append("没有具体产出，就是瞎忙！")
            score -= 15
            
        # 2. 给出直接评价
        if score >= 80:
            verdict = "👍 还行，但别骄傲"
        elif score >= 60:
            verdict = "🙄 一般般，继续努力"
        elif score >= 40:
            verdict = "😒 不行，太敷衍了"
        else:
            verdict = "💩 垃圾！重做！"
        
        # 3. 给出具体问题
        if not issues:
            issues = ["勉强及格，但还可以更好"]
        
        # 4. 给出必须执行的药方
        medicine = []
        if score < 60:
            medicine.append("立即执行！别光说不做！")
        if "代码" not in task_output:
            medicine.append("必须产出代码！")
        if len(task_output) < 200:
            medicine.append("写详细点！至少200字！")
            
        result = {
            "iteration": self.iteration,
            "score": max(0, score),
            "verdict": verdict,
            "issues": issues,
            "medicine": medicine,
            "timestamp": datetime.now().isoformat()
        }
        
        self.history.append(result)
        return result

def demo():
    """演示"""
    critic = CriticV4()
    
    # 测试几个例子
    outputs = [
        "计划学习docker",
        "完成了代码输出到workspace/test.py",
        "学习linux",
    ]
    
    for o in outputs:
        print("=" * 50)
        r = critic.criticize(o)
        print(f"评分: {r['score']}/100")
        print(f"评价: {r['verdict']}")
        print(f"\n问题:")
        for i in r['issues']:
            print(f"  ❌ {i}")
        print(f"\n药方:")
        for m in r['medicine']:
            print(f"  💊 {m}")
        print()

if __name__ == "__main__":
    demo()
