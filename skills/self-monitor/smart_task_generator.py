#!/usr/bin/env python3
"""
Lisa 智能任务生成系统 - 从循环到进化
根据目标动态生成有意义的任务
每次循环：知识库/skill/复现/默写
"""

import random
from datetime import datetime
from pathlib import Path
import json

class SmartTaskGenerator:
    """智能任务生成器"""
    
    def __init__(self):
        # 核心技能缺口（需要学习的）
        self.skill_gaps = [
            "docker", "vllm", "ascendc", "linux",
            "network", "security", "kernel"
        ]
        
        # 任务输出类型
        self.output_types = [
            "knowledge_base",  # 知识库积累
            "create_skill",    # 输出新skill
            "improve_skill",  # 完善已有skill
            "replicate_code", # 复现代码
            "memorize_code", # 默写代码
        ]
        
        # 任务状态
        self.task_state = {
            "current": None,
            "stuck_count": 0,
            "stuck_threshold": 3,
            "paused": [],
            "completed": []
        }
        
    def generate_task(self) -> dict:
        """生成有意义的任务"""
        
        # 1. 选择输出类型
        output_type = random.choice(self.output_types)
        
        # 2. 选择学习方向
        focus = random.choice(self.skill_gaps)
        
        # 3. 根据输出类型生成任务
        task_templates = {
            "knowledge_base": {
                "name": f"积累 {focus} 知识库",
                "actions": [
                    f"搜索 {focus} 相关资料",
                    "阅读核心概念",
                    "整理成笔记",
                    "保存到 memory/"
                ],
                "output": "memory/{focus}-notes.md",
                "duration": 20,
                "example": "docker-notes.md, vllm-architecture.md"
            },
            "create_skill": {
                "name": f"创建 {focus} Skill",
                "actions": [
                    f"搜索 ClawHub {focus} 相关技能",
                    "理解技能意图",
                    "独立复现实现",
                    "测试运行"
                ],
                "output": "skills/{focus}/",
                "duration": 35,
                "example": "参考 ClawHub → 独立复现 → skills/docker-manager/"
            },
            "improve_skill": {
                "name": f"完善 {focus} Skill",
                "actions": [
                    f"检查现有 {focus} Skill",
                    "识别不足",
                    "添加新功能",
                    "更新文档"
                ],
                "output": "skills/{focus}/ 改进版",
                "duration": 25,
                "example": "更新 self-monitor, 增强 risk-manager"
            },
            "replicate_code": {
                "name": f"复现 {focus} 代码",
                "actions": [
                    f"搜索 {focus} 开源项目",
                    "阅读源码逻辑",
                    "自己动手实现",
                    "对照源码改进"
                ],
                "output": "workspace/{focus}-demo/",
                "duration": 35,
                "example": "复现 Qbot 回测, 复现 vLLM 推理"
            },
            "memorize_code": {
                "name": f"默写 {focus} 核心代码",
                "actions": [
                    f"学习 {focus} 示例代码",
                    "关闭源码凭记忆写",
                    "打开源码对照",
                    "修正错误"
                ],
                "output": "workspace/{focus}-memo.py",
                "duration": 25,
                "example": "默写 Docker API, 默写 PyTorch tensor操作"
            },
        }
        
        task_template = task_templates.get(output_type, task_templates["knowledge_base"])
        
        # 4. 生成任务
        task = {
            "output_type": output_type,
            "focus": focus,
            "name": task_template["name"],
            "actions": task_template["actions"],
            "output": task_template["output"].format(focus=focus),
            "output_example": task_template["example"],
            "duration": task_template["duration"],
            "generated_at": datetime.now().isoformat(),
            "purpose": f"输出类型: {output_type}, 填补 {focus} 技能缺口"
        }
        
        self.task_state["current"] = task
        
        return task
    
    def mark_stuck(self):
        """标记任务卡住"""
        self.task_state["stuck_count"] += 1
        print(f"⚠️ 任务卡住！已尝试 {self.task_state['stuck_count']} 次")
        print(f"   达到 {self.task_state['stuck_threshold']} 次将自动切换")
    
    def mark_success(self):
        """标记任务完成"""
        if self.task_state["current"]:
            self.task_state["completed"].append({
                "task": self.task_state["current"],
                "completed_at": datetime.now().isoformat()
            })
        self.task_state["stuck_count"] = 0
        self.task_state["current"] = None
    
    def get_paused_tasks(self):
        """获取搁置的任务"""
        return self.task_state["paused"]
    
    def resume_task(self, task_index):
        """恢复搁置的任务"""
        if 0 <= task_index < len(self.task_state["paused"]):
            task = self.task_state["paused"].pop(task_index)["task"]
            self.task_state["current"] = task
            self.task_state["stuck_count"] = 0
            return task
        return None

def demo():
    """演示"""
    generator = SmartTaskGenerator()
    
    print("=" * 60)
    print("🧠 Lisa 智能任务生成系统")
    print("=" * 60)
    
    # 生成当前任务
    task = generator.generate_task()
    
    print(f"\n🎯 当前任务: {task['name']}")
    print(f"📌 聚焦: {task['focus']}")
    print(f"⏱️ 时长: {task['duration']}分钟")
    print(f"📤 输出类型: {task['output_type']}")
    print(f"📤 输出示例: {task['output_example']}")
    print(f"💡 目的: {task['purpose']}")
    
    print(f"\n📋 执行步骤:")
    for i, action in enumerate(task['actions'], 1):
        print(f"   {i}. {action}")

if __name__ == "__main__":
    demo()
