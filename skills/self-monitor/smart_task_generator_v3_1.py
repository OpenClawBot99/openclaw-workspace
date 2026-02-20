#!/usr/bin/env python3
"""
Lisa 智能任务生成系统 v3.1 - 记忆与目标控制
根据反馈，暂停特定探索方向，并确保任务不冲突
"""

import random
from datetime import datetime
from pathlib import Path
import json
import sys
from typing import Optional

# 动态导入
sys.path.insert(0, str(Path(__file__).parent)) # Add current dir to path for relative imports
try:
    from previous_critic_output import PreviousCriticOutput
except ImportError:
    PreviousCriticOutput = None # Mock if not available

class SmartTaskGeneratorV3_1:
    """智能任务生成器 v3.1 - 记忆与目标控制"""
    
    def __init__(self):
        # 核心技能领域 - 拆解成微小目标
        self.skill_areas = {
            "linux": { # Paused by user
                "name": "Linux 命令行工具",
                "micro_goals": ["运行 ls -tree", "理解进程管理", "精通find命令", "掌握grep技巧"],
                "focus": ["AI INFRA 基础设施", "底层逻辑"]
            },
            "docker": {
                "name": "Docker",
                "micro_goals": ["运行hello-world容器", "构建基于Dockerfile的镜像", "理解docker network", "学会docker volume"],
                "focus": ["AI INFRA 基础设施", "部署"]
            },
            "vllm": { # Paused by user
                "name": "vLLM 推理",
                "micro_goals": ["理解PagedAttention", "运行LLM推理demo", "安装vLLM"],
                "focus": ["AI INFRA 基础设施", "模型推理"]
            },
            "python_utils": {
                "name": "Python 工具库",
                "micro_goals": ["实现文件解析工具", "调用API", "结构化数据输出"],
                "focus": ["效率提升", "代码复用"]
            },
            "git": {
                "name": "Git 命令",
                "micro_goals": ["git clone", "git commit", "git push", "git branch"],
                "focus": ["版本控制", "协作"]
            },
            "security": { # Added based on recent focus
                "name": "安全技能",
                "micro_goals": ["基础安全概念", "常见的Web漏洞", "端口扫描"],
                "focus": ["AI INFRA 安全", "渗透测试"]
            },
            "network": { # Added for network exploration
                "name": "网络协议",
                "micro_goals": ["TCP/IP", "HTTP/HTTPS"],
                "focus": ["AI INFRA 网络", "通信原理"]
            },
            "ascendc": { # Paused by user
                "name": "AscendC",
                "micro_goals": ["算子开发基础", "CANN SDK"],
                "focus": ["AI INFRA 算子", "硬件加速"]
            }
        }
        
        # 用户指定的暂停探索主题
        self.paused_topics = ["linux", "vllm", "ascendc"]
        
        # 输出类型 - 与 Du Bin 的反馈对应
        self.output_types = {
            "knowledge_base": {"desc": "沉淀知识库", "example_path": "memory/{skill_name}-summary.md"},
            "create_skill": {"desc": "创建新Skill", "example_path": "skills/{skill_name}/"},
            "improve_skill": {"desc": "完善已有Skill", "example_path": "skills/{skill_name}/"},
            "replicate_code": {"desc": "复现项目/代码", "example_path": "workspace/{project_name}/"},
            "memorize_code": {"desc": "默写核心代码", "example_path": "workspace/{skill_name}-memo.py"},
        }
        
        # 迭代历史 - 存储上一次任务的输出/药方
        self.iteration_history = [] 
        
        # 任务状态管理
        self.task_state = {
            "current": None,
            "stuck_count": 0,
            "stuck_threshold": 3,
            "paused": [],
            "completed": []
        }
    
    def get_previous_medicine(self) -> Optional[str]:
        """获取上次的药方（改进建议）"""
        if not self.iteration_history:
            return None
        last_task_name = self.iteration_history[-1]
        # 假设上一次的输出就是本次的 '药方'
        # For demonstration, we'll manually craft medicine from common feedback themes
        if "卡住" in last_task_name or "停止" in last_task_name:
            return "解决卡住的问题，切换到新任务"
        elif "简陋" in last_task_name or "细节" in last_task_name:
            return "详细展开，补充数据和例子"
        elif "代码" in last_task_name or "复现" in last_task_name:
            return "动手复现代码"
        elif "Skill" in last_task_name:
            return "创建或完善Skill"
        elif "资源" in last_task_name:
            return "检查资源管理"
        elif "批评" in last_task_name:
            return "改进批评内容，转化为行动"
        return "继续当前方向"

    def adjust_task_based_on_feedback(self, feedback: str):
        """根据反馈调整任务选择"""
        task = None
        
        # 1. 直接响应用户反馈
        if "ls 智能命令助手" in feedback:
            task = self._create_ls_helper_task()
        elif "复现" in feedback or "代码" in feedback or "实践" in feedback:
            task = self._generate_replicate_task()
        elif "Skill" in feedback or "技能" in feedback:
            task = self._generate_create_skill_task()
        elif "命令" in feedback: # General command exploration
            task = self._generate_linux_command_task() # Still trying to pick linux, needs filtering
        elif "知识库" in feedback or "总结" in feedback:
            task = self._generate_knowledge_base_task()
        elif "资源" in feedback:
            task = self._generate_resource_check_task()
        elif "批评" in feedback: # If feedback is about criticism itself
            task = self._generate_critic_improvement_task()
            
        # 2. If feedback is about pausing topics, update internal state
        if "暂停" in feedback or "不要探索" in feedback:
            topics_to_pause = ["linux", "ascend", "vllm"] # Explicitly mentioned by user
            for t in topics_to_pause:
                if t.lower() not in self.paused_topics:
                    self.paused_topics.append(t.lower())
                    print(f"   - 已记录并暂停探索: {t}")
            # After updating paused topics, try to generate a new task that respects this
            task = self._generate_filtered_task() # Re-generate task after update
        
        # 3. If feedback insufficient for direct generation, use previous medicine
        if not task and feedback:
            task = self._adjust_based_on_previous_medicine(feedback)
            print(f"   → 根据上次 '药方/反馈' 调整任务: {task['name']}")
            
        # 4. If still no task, select a filtered random task
        if not task:
            task = self._generate_filtered_task()
            
        self.task_state["current"] = task
        return task

    def _adjust_based_on_previous_medicine(self, prev_medicine: str):
        """根据上次的药方调整任务"""
        print(f"   - 根据上次药方调整: '{prev_medicine}'")
        # This part relies on the logic within adjust_task_based_on_feedback
        # and the generation of new tasks that align with the medicine.
        # For now, we'll rely on the _generate_filtered_task for subsequent valid tasks.
        return self._generate_filtered_task()

    def _create_ls_helper_task(self) -> dict:
        """创建 ls 智能命令助手任务"""
        # This task implicitly uses linux commands, might need careful handling if linux is paused
        # For now, assume it's a skill *creation* not execution of raw linux commands
        return {
            "name": "开发 'ls -tree' 智能助手",
            "type": "create_skill",
            "skill_area": "linux", # Still tagged as linux, but it's about *creating* a skill
            "focus": ["AI INFRA 基础设施", "效率提升"],
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

    def _generate_replicate_task(self) -> dict:
        """生成实践型任务（复现/代码）"""
        available_areas = [k for k in self.skill_areas if k not in self.paused_topics]
        if not available_areas:
            return {"error": "No available skill areas to select! All topics might be paused."}
            
        skill_area_key = random.choice(available_areas)
        skill_area = self.skill_areas[skill_area_key]
        micro_goal = random.choice(skill_area["micro_goals"])
        
        return {
            "name": f"复现 {skill_area['name']} 示例 ({micro_goal})",
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
            "output": f"workspace/{skill_area['name'].lower().replace(' ', '_')}_replication/",
            "goal_size": "medium",
            "purpose": "通过实践掌握核心知识",
        }
    
    def _generate_create_skill_task(self) -> dict:
        """生成创建 Skill 的任务"""
        available_areas = [k for k in self.skill_areas if k not in self.paused_topics]
        if not available_areas:
            return {"error": "No available skill areas to select! All topics might be paused."}

        skill_area_key = random.choice(available_areas)
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
        available_areas = [k for k in self.skill_areas if k not in self.paused_topics]
        if not available_areas:
            return {"error": "No available skill areas to select! All topics might be paused."}

        skill_area_key = random.choice(available_areas)
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
                f"存入 memory/{skill_area_key}_summary.md"
            ],
            "output": f"memory/{skill_area_key}_summary.md",
            "goal_size": "small",
            "purpose": "沉淀结构化知识",
        }
    
    def _generate_resource_check_task(self) -> dict:
        """生成资源检查任务"""
        # This is a system-level task, not tied to a specific paused topic
        return {
            "name": "检查并优化磁盘资源",
            "type": "resource_management",
            "skill_area": "disk_monitor",
            "focus": "AI INFRA 基础设施",
            "actions": [
                "运行 disk-monitor",
                "检查 C盘空间",
                "分析大型文件",
                "考虑移动到D/G盘"
            ],
            "output": "disk_usage_report.txt",
            "goal_size": "small",
            "purpose": "确保系统资源高效利用"
        }

    def _generate_critic_improvement_task(self) -> dict:
        """生成改进批评任务"""
        # This is a meta-task related to the critic system
        return {
            "name": "优化自我批评反馈机制",
            "type": "improve_skill",
            "skill_area": "critic",
            "focus": ["自我进化", "反馈闭环"],
            "actions": [
                "分析critic v5评分不足之处",
                "调整批评标准和措辞",
                "确保反馈更具建设性",
                "更新critic版本"
            ],
            "output": "skills/critic/critic_v5.py",
            "goal_size": "small",
            "purpose": "提升批评的有效性",
        }
        
    def _generate_filtered_task(self) -> dict:
        """生成一个经过过滤的任务 (避开暂停主题)"""
        available_areas = [k for k in self.skill_areas if k not in self.paused_topics]
        if not available_areas:
            return {"error": "No available skill areas to select! All topics might be paused."}
            
        skill_area_key = random.choice(available_areas)
        skill_area = self.skill_areas[skill_area_key]
        
        # Prioritize tasks that are not just theoretical for paused topics if they were allowed again
        # But since they are paused, we just pick from the allowed ones.
        
        # Example: When 'docker' is chosen, try to generate a specific task of medium size
        if skill_area_key == "docker":
            return {
                "name": f"编写 Dockerfile 实践",
                "type": "replicate_code",
                "skill_area": skill_area_key,
                "focus": random.choice(skill_area["focus"]),
                "actions": [
                    "选择一个小型服务 (e.g., Python Flask app)",
                    "编写Dockerfile",
                    "Build and run image",
                    "验证功能"
                ],
                "output": f"workspace/dockerfile_practice/",
                "goal_size": "small",
                "purpose": "实践Dockerfile编写",
            }
        elif skill_area_key == "security":
            return {
                "name": f"学习常见的 Web 安全漏洞",
                "type": "knowledge_base",
                "skill_area": skill_area_key,
                "focus": random.choice(skill_area["focus"]),
                "actions": [
                    "搜索 OWASP Top 10 漏洞",
                    "理解 SQL注入、XSS 概念",
                    "记录防范措施",
                ],
                "output": f"memory/web_security_intro.md",
                "goal_size": "small",
                "purpose": "入门Web安全",
            }
        else:
            # Fallback general task for other available areas
             return {
                "name": f"深入理解 {skill_area['name']}",
                "type": "knowledge_base",
                "skill_area": skill_area_key,
                "focus": random.choice(skill_area["focus"]),
                "actions": [
                    "查找官方文档",
                    "阅读核心概念",
                    "总结关键点",
                    "存入知识库"
                ],
                "output": f"memory/{skill_area_key}_deep_dive.md",
                "goal_size": "small",
                "purpose": "深入理解",
            }

    def get_task_for_next_cycle(self, feedback: str = None):
        """根据上次反馈和状态选择下一个任务"""
        
        task = None
        
        # 1. 优先响应用户直接反馈 (高优先级)
        if feedback:
            task = self.adjust_task_based_on_feedback(feedback)
            print(f"   → 根据用户反馈生成任务: {task['name']}")
            
        # 2. 如果没有直接反馈，检查是否需要切换任务（因卡住）
        if not task and self.task_state["stuck_count"] >= self.task_state["stuck_threshold"]:
            print(f"   → 触发任务切换 (卡住 {self.task_state['stuck_count']} 次)")
            task = self._adjust_based_on_previous_medicine(self.get_previous_medicine())
            self.task_state["stuck_count"] = 0 # Reset stuck count after switching
            
        # 3. 如果没有以上情况，生成一个经过过滤的、有意义的任务
        if not task:
            task = self._generate_filtered_task()
            
        self.task_state["current"] = task
        return task
    
    # Removed _random_specific_task as _generate_filtered_task covers this
    # Keeping _create_ls_helper_task, _generate_replicate_task, _generate_create_skill_task,
    # _generate_knowledge_base_task, _generate_resource_check_task, _generate_critic_improvement_task as specific task generators.

def demo():
    """演示"""
    # Using the updated class name
    generator = SmartTaskGeneratorV3_1() 
    
    print("=" * 70)
    print("🎯 Lisa 智能任务生成器 v3.1 - 记忆与目标控制")
    print("=" * 70)
    
    # Simulate user feedback and previous medicine
    feedbacks_and_medicines = [
        ("暂停 linux, vllm, ascendc 探索", "已暂停 linux, vllm, ascendc"), # User command to pause topics
        ("这次的批评不够犀利，需要更直接", "改进批评内容，要求更严格"), # Feedback on critic
        ("没有具体产出", "立即执行！必须产出代码！"), # Previous medicine reminder
        ("随便给我个任务", None), # General request
        ("还是卡住了，换个任务", None) # Stuck scenario
    ]
    
    for fb, med_str in feedbacks_and_medicines:
        print(f"\n--- 模拟输入 (反馈/药方: '{fb}' / '{med_str if med_str else '无'}') ---")
        
        # Simulate tool use or direct user feedback
        task = generator.get_task_for_next_cycle(feedback=fb)
        
        if "error" in task:
            print(f"Error generating task: {task['error']}")
            continue

        print(f"\n任务: {task.get('name', 'Unknown')}")
        print(f"类型: {task.get('type', 'N/A')}")
        print(f"目标大小: {task.get('goal_size', 'medium')}")
        print(f"聚焦: {task.get('focus', 'N/A')}")
        print(f"目的: {task.get('purpose', 'N/A')}")
        
        print(f"\n📋 执行步骤:")
        for j, action in enumerate(task.get('actions', []), 1):
            print(f"   {j}. {action}")
        
        print(f"\n📤 输出: {task.get('output', 'N/A')}")
        
        # Record history for next iteration's feedback simulation
        generator.iteration_history.append(task.get("name", "")) # Add task name as history for next round

    print("\n" + "=" * 70)
    print("💡 任务生成器已更新，能根据用户指令暂停主题，并生成更具体的任务！")
    print("=" * 70)

if __name__ == "__main__":
    demo()
