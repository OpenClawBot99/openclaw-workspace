#!/usr/bin/env python3
"""
Lisa 连锁反应系统 - 递归式自我进化
每次任务自动评估反馈，自主调整计划，设置下一个任务
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import random

# 路径配置
SKILL_DIR = Path(__file__).parent.parent
MEMORY_DIR = SKILL_DIR / "memory"
CHAIN_STATE_FILE = SKILL_DIR / "chain_state.json"
TASKS_FILE = SKILL_DIR / "available_tasks.json"

class ChainReactor:
    """连锁反应系统 - 递归式自我进化"""
    
    def __init__(self):
        self.state = self._load_state()
        self.available_tasks = self._load_tasks()
        
    def _load_state(self) -> Dict:
        """加载状态"""
        if CHAIN_STATE_FILE.exists():
            with open(CHAIN_STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "chain_history": [],  # 执行历史
            "current_task": None,
            "evolution_level": 1,  # 进化等级
            "total_cycles": 0,
            "last_evaluation": None
        }
    
    def _load_tasks(self) -> Dict:
        """加载可用任务库"""
        # 可用任务模板 - 自我演化方向
        return {
            "self_reflection": {
                "name": "自我反思与总结",
                "duration_minutes": 10,
                "priority": 6,
                "next_options": ["system_check", "embodied_ai"],
                "goals": {
                    "baseline": "完成每日反思记录",
                    "stretch": "提出1个创新改进方案"
                }
            },
            "system_check": {
                "name": "系统健康检查",
                "duration_minutes": 5,
                "priority": 7,
                "next_options": ["embodied_ai", "self_reflection"],
                "goals": {
                    "baseline": "所有定时任务正常运行",
                    "stretch": "发现并修复1个潜在问题"
                }
            },
            "embodied_ai": {
                "name": "具身智能实验",
                "duration_minutes": 30,
                "priority": 9,
                "next_options": ["system_check", "self_reflection"],
                "goals": {
                    "baseline": "CartPole-v1 训练达到50分",
                    "stretch": "实现LunarLander-v2 起飞"
                }
            },
            "random_explore": {
                "name": "随机策略探索",
                "duration_minutes": 15,
                "priority": 8,
                "next_options": ["embodied_ai", "system_check"],
                "goals": {
                    "baseline": "探索1个新维度",
                    "stretch": "提出并验证1个大胆假设"
                }
            },
            "tool_mastery": {
                "name": "工具掌握与调用",
                "duration_minutes": 20,
                "priority": 9,
                "next_options": ["embodied_ai", "random_explore"],
                "goals": {
                    "baseline": "成功调用浏览器访问x.com",
                    "stretch": "实现自动化信息抓取"
                }
            },
            "risk_management": {
                "name": "风险管理优化",
                "duration_minutes": 25,
                "priority": 7,
                "next_options": ["system_check", "self_reflection"],
                "goals": {
                    "baseline": "完善风险管理文档",
                    "stretch": "实现自动化风控策略"
                }
            }
        }
    
    def _save_state(self):
        """保存状态"""
        with open(CHAIN_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)
    
    def evaluate_last_task(self, task_id: str, result: Dict) -> Dict:
        """评估上次任务的结果"""
        evaluation = {
            "task_id": task_id,
            "timestamp": datetime.now().isoformat(),
            "success": result.get("success", True),
            "metrics": result.get("metrics", {}),
            "insights": []
        }
        
        # 分析结果，生成洞察
        if result.get("success"):
            evaluation["insights"].append("任务成功完成")
            evaluation["next_weight"] = 1.0  # 保持权重
        else:
            evaluation["insights"].append("任务失败，需要调整")
            evaluation["next_weight"] = 0.5  # 降低权重
        
        # 根据指标调整
        metrics = result.get("metrics", {})
        if metrics.get("progress", 0) > 0.8:
            evaluation["insights"].append("进展顺利，可以加快节奏")
        if metrics.get("difficulty", 0) > 7:
            evaluation["insights"].append("难度较高，需要更多时间")
            
        return evaluation
    
    def select_next_task(self, evaluation: Dict, context: Dict) -> Optional[Dict]:
        """根据评估结果和上下文，选择下一个任务"""
        current_task_id = context.get("current_task_id")
        
        if not current_task_id or current_task_id not in self.available_tasks:
            # 随机选择起始任务
            task_id = random.choice(list(self.available_tasks.keys()))
            return self._create_task(task_id)
        
        current_task = self.available_tasks[current_task_id]
        next_options = current_task.get("next_options", [])
        
        # 根据评估调整选择
        if evaluation and not evaluation.get("success", True):
            # 失败时，偏向选择简单任务
            next_options = [t for t in next_options if self.available_tasks[t]["priority"] < 7]
            if not next_options:
                next_options = ["self_reflection"]
        
        # 随机选择，增加多样性
        task_id = random.choice(next_options)
        task = self._create_task(task_id)
        
        return task
    
    def _create_task(self, task_id: str) -> Dict:
        """创建任务"""
        task_template = self.available_tasks.get(task_id, {})
        return {
            "task_id": task_id,
            "name": task_template.get("name", "未知任务"),
            "duration_minutes": task_template.get("duration_minutes", 30),
            "priority": task_template.get("priority", 5),
            "created_at": datetime.now().isoformat(),
            "evolution_level": self.state.get("evolution_level", 1)
        }
    
    def run_cycle(self, last_result: Dict = None) -> Dict:
        """运行一个完整的连锁循环"""
        print("=" * 60)
        print("🔄 Lisa 连锁反应系统 - 递归式进化")
        print("=" * 60)
        
        # 1. 评估上次任务
        evaluation = None
        if last_result:
            print("\n📊 评估上次任务...")
            task_id = last_result.get("task_id", "unknown")
            evaluation = self.evaluate_last_task(task_id, last_result)
            print(f"  → 洞察: {', '.join(evaluation['insights'])}")
        
        # 2. 选择下一个任务
        current_task_id = None
        if self.state.get("current_task"):
            current_task_id = self.state["current_task"].get("task_id")
        context = {"current_task_id": current_task_id}
        next_task = self.select_next_task(evaluation, context)
        
        print(f"\n🎯 选择下一个任务: {next_task['name']}")
        print(f"   预计时长: {next_task['duration_minutes']}分钟")
        print(f"   优先级: {next_task['priority']}/10")
        
        # 3. 更新状态
        self.state["current_task"] = next_task
        self.state["total_cycles"] += 1
        self.state["last_evaluation"] = evaluation
        self._save_state()
        
        # 4. 生成报告
        report = {
            "cycle": self.state["total_cycles"],
            "evolution_level": self.state["evolution_level"],
            "current_task": next_task,
            "evaluation": evaluation,
            "timestamp": datetime.now().isoformat()
        }
        
        print("\n" + "=" * 60)
        print(f"✅ 循环 {report['cycle']} - 进化等级 {report['evolution_level']}")
        print("=" * 60)
        
        # 5. 模拟执行任务（实际使用时，这里会触发真正的任务）
        print(f"\n🚀 准备执行: {next_task['name']}")
        print("   (定时任务将根据此计划执行)")
        
        return report
    
    def get_status(self) -> str:
        """获取状态"""
        status = []
        status.append("🔄 Lisa 连锁反应系统状态")
        status.append("=" * 40)
        status.append(f"进化等级: {self.state.get('evolution_level', 1)}")
        status.append(f"总循环次数: {self.state.get('total_cycles', 0)}")
        
        current = self.state.get("current_task")
        if current:
            status.append(f"当前任务: {current.get('name')}")
        
        return "\n".join(status)


def main():
    """主函数"""
    reactor = ChainReactor()
    
    # 模拟上次任务结果（实际使用时会传入真实结果）
    # None = 第一次运行
    last_result = None
    
    report = reactor.run_cycle(last_result)
    
    print("\n" + reactor.get_status())
    
    return report


if __name__ == "__main__":
    main()
