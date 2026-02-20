#!/usr/bin/env python3
"""
Task Planner - 任务规划器
自动识别重要任务、优先级排序、资源分配
"""

import json
from datetime import datetime
from pathlib import Path

SKILL_DIR = Path(__file__).parent
STATE_DIR = SKILL_DIR / "state"
TASKS_FILE = STATE_DIR / "tasks.json"

class TaskPlanner:
    def __init__(self):
        self.tasks = self._load_tasks()
    
    def _load_tasks(self):
        if TASKS_FILE.exists():
            with open(TASKS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"tasks": [], "last_updated": datetime.now().isoformat()}
    
    def _save_tasks(self):
        self.tasks["last_updated"] = datetime.now().isoformat()
        STATE_DIR.mkdir(exist_ok=True)
        with open(TASKS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.tasks, f, indent=2, ensure_ascii=False)
    
    def add_task(self, name, priority, deadline=None, dependencies=None):
        """添加任务"""
        task = {
            "id": len(self.tasks["tasks"]) + 1,
            "name": name,
            "priority": priority,  # 1-10
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "deadline": deadline,
            "dependencies": dependencies or [],
            "estimated_hours": 0,
            "actual_hours": 0
        }
        self.tasks["tasks"].append(task)
        self._save_tasks()
        print(f"✅ 添加任务: {name} (优先级: {priority})")
        return task
    
    def prioritize(self):
        """优先级排序"""
        # 按优先级排序，优先选择进行中的任务
        tasks = self.tasks["tasks"]
        
        # 分离进行中和待处理
        in_progress = [t for t in tasks if t["status"] == "in_progress"]
        pending = [t for t in tasks if t["status"] == "pending"]
        
        # 按优先级排序
        in_progress.sort(key=lambda x: x["priority"], reverse=True)
        pending.sort(key=lambda x: x["priority"], reverse=True)
        
        return in_progress + pending
    
    def get_next_task(self):
        """获取下一个应执行的任务"""
        prioritized = self.prioritize()
        
        for task in prioritized:
            if task["status"] in ["pending", "in_progress"]:
                # 检查依赖是否满足
                deps = task.get("dependencies", [])
                deps_met = True
                for dep_id in deps:
                    dep_task = next((t for t in self.tasks["tasks"] if t["id"] == dep_id), None)
                    if dep_task and dep_task["status"] != "completed":
                        deps_met = False
                        break
                
                if deps_met:
                    return task
        
        return None
    
    def update_status(self, task_id, status):
        """更新任务状态"""
        for task in self.tasks["tasks"]:
            if task["id"] == task_id:
                task["status"] = status
                self._save_tasks()
                print(f"✅ 任务 {task_id} 状态更新为: {status}")
                return True
        return False
    
    def print_plan(self):
        """打印计划"""
        print("\n📋 任务规划")
        print("=" * 50)
        
        prioritized = self.prioritize()
        
        status_map = {
            "pending": "⏳",
            "in_progress": "🔄",
            "completed": "✅",
            "blocked": "🚫"
        }
        
        for task in prioritized:
            icon = status_map.get(task["status"], "❓")
            deadline = f" (截止: {task['deadline']})" if task.get("deadline") else ""
            print(f"{icon} [P{task['priority']}] {task['name']}{deadline}")
        
        # 统计
        total = len(prioritized)
        completed = len([t for t in prioritized if t["status"] == "completed"])
        in_progress = len([t for t in prioritized if t["status"] == "in_progress"])
        
        print(f"\n📊 统计: {completed}/{total} 完成, {in_progress} 进行中")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Task Planner")
    parser.add_argument("--add", nargs="+", metavar=("NAME", "PRIORITY"), help="添加任务")
    parser.add_argument("--deadline", help="截止日期")
    parser.add_argument("--next", action="store_true", help="获取下一个任务")
    parser.add_argument("--plan", action="store_true", help="显示计划")
    parser.add_argument("--complete", type=int, help="完成任务")
    
    args = parser.parse_args()
    
    planner = TaskPlanner()
    
    if args.add:
        name = args.add[0]
        priority = int(args.add[1]) if len(args.add) > 1 else 5
        planner.add_task(name, priority, args.deadline)
    elif args.next:
        task = planner.get_next_task()
        if task:
            print(f"\n🎯 下一个任务: {task['name']} [P{task['priority']}]")
            planner.update_status(task["id"], "in_progress")
        else:
            print("\n✅ 所有任务已完成!")
    elif args.complete:
        planner.update_status(args.complete, "completed")
    elif args.plan:
        planner.print_plan()
    else:
        planner.print_plan()

if __name__ == "__main__":
    main()
