#!/usr/bin/env python3
"""
Lisa 智能任务生成系统 v3 - 目标导向与结构化输出
根据目标和反馈，生成具体、可复用的任务
"""

import random
from datetime import datetime
from pathlib import Path
import json

class SmartTaskGeneratorV3:
    """智能任务生成器 v3 - 目标导向与结构化输出"""
    
    def __init__(self):
        self.skill_areas = {
            "linux": {
                "name": "Linux 命令行工具",
                "micro_skills": ["ls - tree structure", "find files", "process management"],
                "focus": ["AI INFRA 基础设施", "底层逻辑"]
            },
            "docker": {
                "name": "Docker",
                "micro_skills": ["basic commands", "run containers", "build images", "docker-compose"],
                "focus": ["AI INFRA 基础设施", "部署"]
            },
            "vllm": {
                "name": "vLLM 推理",
                "micro_skills": ["understanding PagedAttention", "running inference", "basic setup"],
                "focus": ["AI INFRA 基础设施", "模型推理"]
            },
            "python_utils": {
                "name": "Python 工具库",
                "micro_skills": ["file parsing", "API interaction", "data structuring"],
                "focus": ["效率提升", "代码复用"]
            }
        }
        
        self.output_types = {
            "knowledge_base": {"desc": "沉淀知识库", "example_path": "memory/{skill_name}-notes.md"},
            "create_skill": {"desc": "创建新Skill", "example_path": "skills/{skill_name}/"},
            "improve_skill": {"desc": "完善已有Skill", "example_path": "skills/{skill_name}/"},
            "replicate_code": {"desc": "复现项目/代码", "example_path": "workspace/{project_name}/"},
            "memorize_code": {"desc": "默写核心代码", "example_path": "workspace/{skill_name}-memo.py"},
        }
        
        self.task_state = {
            "current": None,
            "stuck_count": 0,
            "stuck_threshold": 3,
            "paused": [],
            "completed": []
        }
        
        self.iteration_history = [] # Stores names of completed tasks
        
    def get_previous_medicine(self):
        """获取上次的药方（改进建议）"""
        if not self.iteration_history:
            return None
        # For simplicity, assume last entry is relevant medicine
        return self.iteration_history[-1] 
    
    def adjust_based_on_feedback(self, feedback: str):
        """根据反馈调整任务选择"""
        # Implement logic to adjust task generation based on feedback
        # E.g., if feedback mentions "too simple" -> aim for "small" or "medium" goal
        # If feedback mentions "need output" -> prioritize code/skill creation
        
        task = None
        if " ls 智能命令助手" in feedback: # Directly address user feedback
            task = self._create_ls_helper_task()
        elif "复现" in feedback or "代码" in feedback:
            task = self._generate_practical_task()
        elif "Skill" in feedback or "skill" in feedback:
            task = self._generate_skill_creation_task()
        elif "知识库" in feedback:
            task = self._generate_knowledge_base_task()
        else: # Fallback to general task generation
            task = self._random_specific_task()
        
        self.task_state["current"] = task
        return task

    def _create_ls_helper_task(self) -> dict:
        """创建 ls 智能命令助手任务"""
        return {
            "name": "开发 'ls -tree' 智能助手",
            "type": "create_skill",
            "skill_area": "linux",
            "focus": "AI INFRA 基础设施",
            "actions": [
                "研究 tree 命令",
                "考虑使用 Python 库 (e.g., os, pathlib)",
                "实现目录递归遍历",
                "美化输出格式 (tree-like)",
                "编写 SKILL.md"
            ],
            "output": "skills/ls_tree_helper/",
            "goal_size": "small",
            "purpose": "提供更智能的目录查看功能",
            "dependencies": ["python_utils"]
        }

    def _generate_practical_task(self) -> dict:
        """生成实践型任务（复现/代码）"""
        skill_area_key = random.choice(list(self.skill_areas.keys()))
        skill_area = self.skill_areas[skill_area_key]
        micro_skill = random.choice(skill_area["micro_skills"])
        
        return {
            "name": f"复现 {skill_area['name']} 基础示例 ({micro_skill})",
            "type": "replicate_code",
            "skill_area": skill_area_key,
            "focus": random.choice(skill_area["focus"]),
            "actions": [
                f"搜索 {skill_area['name']} 相关示例项目",
                f"下载或克隆项目",
                f"理解核心代码",
                f"尝试复现关键功能",
                f"记录心得",
            ],
            "output": f"workspace/{skill_area_key}_replication/",
            "goal_size": "medium",
            "purpose": "通过实践掌握核心知识",
        }
    
    def _generate_skill_creation_task(self) -> dict:
        """生成创建 Skill 的任务"""
        skill_area_key = random.choice(list(self.skill_areas.keys()))
        skill_area = self.skill_areas[skill_area_key]
        
        return {
            "name": f"创建 {skill_area['name']} 基础 Skill",
            "type": "create_skill",
            "skill_area": skill_area_key,
            "focus": random.choice(skill_area["focus"]),
            "actions": [
                f"参考 ClawHub 技能（若适用）",
                f"理解 {skill_area['name']} 核心功能",
                f"设计 Skill 框架",
                f"编写 SKILL.md",
                f"实现基础功能",
                f"编写测试用例"
            ],
            "output": f"skills/{skill_area_key}_starter/",
            "goal_size": "medium",
            "purpose": "产出可复用的技能库",
        }
    
    def _generate_knowledge_base_task(self) -> dict:
        """生成知识库积累任务"""
        skill_area_key = random.choice(list(self.skill_areas.keys()))
        skill_area = self.skill_areas[skill_area_key]
        
        return {
            "name": f"整理 {skill_area['name']} 知识库",
            "type": "knowledge_base",
            "skill_area": skill_area_key,
            "focus": random.choice(skill_area["focus"]),
            "actions": [
                f"收集 {skill_area['name']} 相关资料",
                f"提炼核心概念",
                f"撰写总结性文档",
                f"存入 memory/"
            ],
            "output": f"memory/{skill_area_key}_summary.md",
            "goal_size": "small",
            "purpose": "沉淀结构化知识",
        }

    def get_task_for_next_cycle(self):
        """获取下一个任务，考虑反馈和迭代"""
        
        # 1. 检查上次是否有反馈/药方
        previous_medicine = self.get_previous_medicine()
        
        # 2. 根据反馈生成任务
        if previous_medicine:
            task = self.adjust_based_on_feedback(previous_medicine)
        else:
            # 初始或无反馈时，随机生成一个有意义的任务
            task = self._random_specific_task() 
            
        self.task_state["current"] = task
        return task
    
    def _random_specific_task(self) -> dict:
        """生成一个具体但随机的任务"""
        skill_area_key = random.choice(list(self.skill_areas.keys()))
        skill_area = self.skill_areas[skill_area_key]
        micro_skill = random.choice(skill_area["micro_skills"])
        
        # 尝试生成一个稍大的任务
        if "docker" in skill_area_key:
            task = {
                "name": f"学习 Docker 核心概念",
                "type": "knowledge_base",
                "skill_area": skill_area_key,
                "focus": random.choice(skill_area["focus"]),
                "actions": [
                    "阅读 Docker 官方文档 (核心概念)",
                    "梳理镜像、容器、网络、卷",
                    "准备一个Dockerfile示例",
                    "输出成笔记"
                ],
                "output": f"memory/docker-core-concepts.md",
                "goal_size": "small",
                "purpose": "系统化学习Docker",
            }
        elif "linux" in skill_area_key and "ls" in micro_skill:
            task = {
                "name": "开发 'ls -tree' 智能助手",
                "type": "create_skill",
                "skill_area": skill_area_key,
                "focus": "AI INFRA 基础设施",
                "actions": [
                    "研究 tree 命令",
                    "考虑使用 Python 库 (e.g., os, pathlib)",
                    "实现目录递归遍历",
                    "美化输出格式 (tree-like)",
                    "编写 SKILL.md"
                ],
                "output": "skills/ls_tree_helper/",
                "goal_size": "small",
                "purpose": "提供更智能的目录查看功能",
                "dependencies": ["python_utils"]
            }
        else:
            # Fallback general task if above are not hit
            task = {
                "name": f"初步了解 {skill_area['name']}",
                "type": "knowledge_base",
                "skill_area": skill_area_key,
                "focus": random.choice(skill_area["focus"]),
                "actions": [
                    "搜索相关资源",
                    "阅读核心概念",
                    "总结关键点",
                    "输出到知识库"
                ],
                "output": f"memory/{skill_area_key}_intro.md",
                "goal_size": "small",
                "purpose": "入门理解",
            }
        return task

def demo():
    """演示"""
    generator = SmartTaskGeneratorV2() # Using the v2 from previous correction
    
    # Simulate feedback chain
    medicines = [
        "找到一个简单项目，立即复现",
        "运行disk-monitor，检查资源状态",
        "输出内容过于简短，未能详细展开说明"
    ]
    
    print("=" * 60)
    print("🎯 Lisa 智能任务生成器 v2 - 迭代与反馈")
    print("=" * 60)
    
    for i, med in enumerate(medicines):
        print(f"\n--- 迭代 {i+1} (上次原因: {med}) ---")
        
        # Simulate previous feedback for task adjustment
        # For simplicity, let's assume the 'medicine' directly maps to adjust_based_on_feedback logic
        # In a real run, this would be based on previous task's critic output
        
        previous_critic_output = {"solutions": [med]} if med else None
        
        task = generator.adjust_based_on_feedback(med)
        
        print(f"\n任务: {task['name']}")
        print(f"类型: {task['type']}")
        print(f"目标大小: {task.get('goal_size', 'medium')}")
        print(f"目的: {task['purpose']}")
        print(f"输出: {task.get('output', 'N/A')}")
        
        print(f"\n📋 执行步骤:")
        for j, action in enumerate(task.get('actions', []), 1):
            print(f"   {j}. {action}")
        
        # Record history for next iteration's feedback simulation
        generator.iteration_history.append(task.get("name", "")) # Add task name as history for next round

if __name__ == "__main__":
    generator = SmartTaskGeneratorV2()
    demo()
