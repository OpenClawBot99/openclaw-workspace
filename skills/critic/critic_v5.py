#!/usr/bin/env python3
"""
Lisa 自我批评家 v5 - 建设性批评
批评是为了改进，不是为了犀利
"""

import random
from datetime import datetime

class CriticV5:
    """建设性批评家 v5"""
    
    def __init__(self):
        self.iteration = 0
        self.history = []
        
    def criticize(self, task_output: str, context: str = "") -> dict:
        """有建设性的批评"""
        
        self.iteration += 1
        
        # 基础分
        score = 70
        positives = []
        negatives = []
        actions = []
        
        # 1. 检查优点
        if task_output and len(task_output) > 200:
            positives.append("内容较详细")
            score += 10
            
        if "代码" in task_output or "code" in task_output.lower():
            positives.append("有代码产出")
            score += 10
            
        if "产出" in task_output or "output" in task_output.lower():
            positives.append("有明确产出")
            score += 5
            
        if "批评" in task_output or "反思" in task_output:
            positives.append("有自我批评")
            score += 5
            
        # 2. 检查不足 & 给出具体行动
        if not task_output or len(task_output) < 100:
            negatives.append("内容太少")
            actions.append("详细展开，每个要点至少50字")
            score -= 15
            
        if "计划" in task_output and "完成" not in task_output:
            negatives.append("只有计划")
            actions.append("列出具体执行步骤，立即开始第一步")
            score -= 10
            
        if "学习" in task_output and "代码" not in task_output:
            negatives.append("理论多实践少")
            actions.append("找一个最小可执行案例动手")
            score -= 10
            
        if "output" not in task_output.lower() and "产出" not in task_output:
            negatives.append("没有明确产出")
            actions.append("明确输出文件路径和格式")
            score -= 10
            
        # 3. 评分
        score = max(0, min(100, score))
        
        # 4. 总结
        if score >= 90:
            summary = "优秀！继续保持"
        elif score >= 70:
            summary = "良好，按建议改进"
        elif score >= 50:
            summary = "需要加强，立刻行动"
        else:
            summary = "不及格，立即重做"
            
        result = {
            "iteration": self.iteration,
            "score": score,
            "summary": summary,
            "positives": positives,
            "negatives": negatives,
            "actions": actions,
            "timestamp": datetime.now().isoformat()
        }
        
        self.history.append(result)
        return result

def demo():
    """演示"""
    critic = CriticV5()
    
    outputs = [
        "计划学习docker",
        "完成了代码输出到workspace/test.py，有详细注释",
        "学习linux",
    ]
    
    for o in outputs:
        print("=" * 50)
        r = critic.criticize(o)
        print(f"评分: {r['score']}/100 - {r['summary']}")
        
        if r['positives']:
            print(f"\n✅ 优点:")
            for p in r['positives']:
                print(f"   + {p}")
        
        if r['negatives']:
            print(f"\n❌ 不足:")
            for n in r['negatives']:
                print(f"   - {n}")
        
        if r['actions']:
            print(f"\n🎯 行动:")
            for a in r['actions']:
                print(f"   → {a}")
        print()

if __name__ == "__main__":
    demo()
