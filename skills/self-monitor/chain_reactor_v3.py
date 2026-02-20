#!/usr/bin/env python3
"""
Lisa 连锁反应系统 v3 - 智能闭环进化版
每次循环：执行任务 → 调用批评 → 资源检查 → 模型路由
"""

import json
import random
from datetime import datetime
from pathlib import Path
import subprocess
import sys

# 路径配置
SKILL_DIR = Path(__file__).parent.parent
MONITOR_DIR = SKILL_DIR / "self_monitor"
CRITIC_DIR = SKILL_DIR / "critic"

sys.path.insert(0, str(MONITOR_DIR))
sys.path.insert(0, str(CRITIC_DIR))

class ChainReactorV3:
    """连锁反应系统 v3 - 智能闭环"""
    
    def __init__(self):
        # 动态导入
        try:
            from smart_task_generator import SmartTaskGenerator
            self.task_gen = SmartTaskGenerator()
        except:
            self.task_gen = None
            
        self.state = self._load_state()
        self.last_critic_result = None
        
    def _load_state(self):
        """加载状态"""
        state_file = Path(__file__).parent / "chain_state_v3.json"
        if state_file.exists():
            with open(state_file, 'r') as f:
                return json.load(f)
        return {
            "cycle": 0,
            "consecutive_errors": 0,
            "current_task": None,
            "model_switch_count": 0
        }
    
    def _save_state(self):
        """保存状态"""
        state_file = Path(__file__).parent / "chain_state_v3.json"
        with open(state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def check_disk(self):
        """检查磁盘资源"""
        try:
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "size,freespace,caption"],
                capture_output=True,
                text=True
            )
            return {"status": "OK", "raw": result.stdout}
        except Exception as e:
            return {"status": f"Error: {e}"}
    
    def run_critic(self, task_info):
        """调用批评家"""
        try:
            result = subprocess.run(
                ["python", str(CRITIC_DIR / "critic_v2.py")],
                capture_output=True,
                text=True,
                timeout=30
            )
            return {"output": result.stdout, "status": "OK"}
        except Exception as e:
            return {"output": "", "status": f"Error: {e}"}
    
    def run_cycle(self) -> dict:
        """运行一个循环"""
        self.state["cycle"] += 1
        cycle = self.state["cycle"]
        
        print("=" * 70)
        print(f"🔄 Lisa 连锁反应系统 v3 - 循环 {cycle}")
        print("=" * 70)
        
        # 步骤1：生成任务
        print("\n📋 步骤1：生成任务...")
        if self.task_gen:
            task = self.task_gen.generate_task()
        else:
            task = {"name": "模拟任务", "focus": "general"}
        
        self.state["current_task"] = task
        print(f"   任务: {task.get('name', 'Unknown')}")
        
        # 步骤2：执行任务
        print("\n🚀 步骤2：执行任务...")
        print("   (任务执行中...)")
        
        # 步骤3：资源检查
        print("\n💾 步骤3：资源检查...")
        disk_result = self.check_disk()
        print(f"   磁盘: {disk_result.get('status', 'OK')}")
        
        # 步骤4：自我批评
        print("\n🔍 步骤4：自我批评...")
        critic_result = self.run_critic(str(task))
        print(f"   批评: {critic_result.get('status', 'OK')}")
        
        # 步骤5：检查模型
        print("\n🔄 步骤5：检查模型...")
        need_switch = self.state.get("consecutive_errors", 0) >= 3
        if need_switch:
            print("   ⚠️ 建议切换模型")
        else:
            print("   ✅ 模型状态正常")
        
        # 保存状态
        self._save_state()
        
        return {
            "cycle": cycle,
            "task": task,
            "need_model_switch": need_switch
        }
    
    def get_status(self) -> str:
        """获取状态"""
        return f"""
🔄 连锁反应 v3 状态
========================
循环次数: {self.state['cycle']}
模型切换: {self.state.get('model_switch_count', 0)}次
连续低分: {self.state.get('consecutive_errors', 0)}次
"""

def demo():
    """演示"""
    reactor = ChainReactorV3()
    result = reactor.run_cycle()
    print(reactor.get_status())
    return result

if __name__ == "__main__":
    demo()
