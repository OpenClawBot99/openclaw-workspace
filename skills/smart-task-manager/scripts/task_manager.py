#!/usr/bin/env python3
"""
Smart Task Manager - 智能任务管理器
核心功能：自动检查 todolist、继续未完成任务、定期保存进度、随时可恢复
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import argparse

# 配置路径
SKILL_DIR = Path(__file__).parent.parent
STATE_DIR = SKILL_DIR / "state"
TASKS_FILE = STATE_DIR / "tasks.json"
PROGRESS_FILE = STATE_DIR / "progress.json"
CONFIG_FILE = SKILL_DIR / "config.json"

class SmartTaskManager:
    """智能任务管理器"""
    
    def __init__(self):
        self._ensure_state_dir()
        self.config = self._load_config()
        self.tasks = self._load_tasks()
        self.progress = self._load_progress()
    
    def _ensure_state_dir(self):
        """确保状态目录存在"""
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        (STATE_DIR / "checkpoints").mkdir(exist_ok=True)
        (STATE_DIR / "history").mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """加载配置"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # 默认配置
            default_config = {
                "auto_save_interval_minutes": 30,
                "max_checkpoint_history": 10,
                "task_priorities": {
                    "learning": 9,
                    "development": 8,
                    "documentation": 7,
                    "maintenance": 5
                },
                "recovery_strategy": "latest_unfinished"
            }
            self._save_config(default_config)
            return default_config
    
    def _save_config(self, config: Dict):
        """保存配置"""
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    
    def _load_tasks(self) -> List[Dict]:
        """加载任务列表"""
        if TASKS_FILE.exists():
            with open(TASKS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # 初始化默认任务
            default_tasks = [
                {
                    "id": 1,
                    "name": "构建 tilelang-ascend 知识库",
                    "priority": 9,
                    "status": "in_progress",
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat(),
                    "progress": 52.5,  # 52,501字 / 100,000字目标
                    "category": "documentation",
                    "description": "创建教科书级别的知识库文档"
                },
                {
                    "id": 2,
                    "name": "配置 GH CLI",
                    "priority": 8,
                    "status": "in_progress",
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat(),
                    "progress": 30,
                    "category": "development",
                    "description": "自动化配置 GH CLI 并验证"
                },
                {
                    "id": 3,
                    "name": "开发 survival-instinct",
                    "priority": 7,
                    "status": "pending",
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat(),
                    "progress": 0,
                    "category": "development",
                    "description": "开发死亡焦虑与风险感知系统"
                }
            ]
            self._save_tasks(default_tasks)
            return default_tasks
    
    def _save_tasks(self, tasks: List[Dict]):
        """保存任务列表"""
        with open(TASKS_FILE, 'w', encoding='utf-8') as f:
            json.dump(tasks, f, indent=2, ensure_ascii=False)
    
    def _load_progress(self) -> Dict:
        """加载进度"""
        if PROGRESS_FILE.exists():
            with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # 初始化进度
            default_progress = {
                "current_task_id": 1,
                "last_update": datetime.now().isoformat(),
                "session_start": datetime.now().isoformat(),
                "completed_tasks": [],
                "checkpoints": []
            }
            self._save_progress(default_progress)
            return default_progress
    
    def _save_progress(self, progress: Dict):
        """保存进度"""
        with open(PROGRESS_FILE, 'w', encoding='utf-8') as f:
            json.dump(progress, f, indent=2, ensure_ascii=False)
    
    def add_task(self, name: str, priority: int, category: str = "development", description: str = ""):
        """添加新任务"""
        task = {
            "id": len(self.tasks) + 1,
            "name": name,
            "priority": priority,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "progress": 0,
            "category": category,
            "description": description
        }
        self.tasks.append(task)
        self._save_tasks(self.tasks)
        print(f"✅ 任务已添加: {name} (优先级: {priority})")
        return task
    
    def list_tasks(self):
        """列出所有任务"""
        print("\n📋 当前任务列表:")
        print("=" * 80)
        for task in self.tasks:
            status_emoji = {
                "pending": "⏳",
                "in_progress": "🔄",
                "completed": "✅",
                "failed": "❌"
            }.get(task["status"], "❓")
            
            print(f"{status_emoji} [{task['id']}] {task['name']}")
            print(f"   优先级: {task['priority']} | 进度: {task['progress']}% | 类别: {task['category']}")
            print(f"   状态: {task['status']} | 更新: {task['updated_at']}")
            if task['description']:
                print(f"   描述: {task['description']}")
            print()
    
    def check_unfinished_tasks(self) -> List[Dict]:
        """检查未完成的任务"""
        # 元认知：先同步真实进度
        sync_report = self.sync_with_filesystem()
        
        if sync_report["updates"]:
            print(f"\n🔄 自动同步进度: {len(sync_report['updates'])} 个任务已更新")
        
        unfinished = [t for t in self.tasks if t["status"] in ["pending", "in_progress"]]
        
        if unfinished:
            print(f"\n🔍 发现 {len(unfinished)} 个未完成任务:")
            for task in unfinished:
                print(f"   - [{task['id']}] {task['name']} (进度: {task['progress']}%)")
        
        return unfinished
    
    def get_next_task(self) -> Optional[Dict]:
        """获取下一个应该执行的任务（基于优先级和状态）"""
        unfinished = self.check_unfinished_tasks()
        
        if not unfinished:
            print("\n✅ 所有任务已完成！")
            return None
        
        # 按优先级排序
        sorted_tasks = sorted(unfinished, key=lambda t: t["priority"], reverse=True)
        
        # 优先选择进行中的任务
        in_progress = [t for t in sorted_tasks if t["status"] == "in_progress"]
        if in_progress:
            return in_progress[0]
        
        # 否则选择最高优先级的待处理任务
        return sorted_tasks[0]
    
    def save_checkpoint(self, task_id: int, note: str = ""):
        """保存检查点"""
        task = next((t for t in self.tasks if t["id"] == task_id), None)
        if not task:
            print(f"❌ 任务 ID {task_id} 不存在")
            return
        
        checkpoint = {
            "task_id": task_id,
            "task_name": task["name"],
            "progress": task["progress"],
            "status": task["status"],
            "timestamp": datetime.now().isoformat(),
            "note": note
        }
        
        # 保存检查点
        checkpoint_file = STATE_DIR / "checkpoints" / f"checkpoint_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(checkpoint_file, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, indent=2, ensure_ascii=False)
        
        # 更新进度文件
        self.progress["checkpoints"].append(checkpoint)
        self.progress["last_update"] = datetime.now().isoformat()
        self._save_progress(self.progress)
        
        print(f"✅ 检查点已保存: {checkpoint_file}")
    
    def auto_continue(self):
        """自动继续下一个任务"""
        next_task = self.get_next_task()
        
        if not next_task:
            print("\n💡 所有任务已完成，正在寻找新任务...")
            # TODO: 集成任务发现机制
            return
        
        print(f"\n🚀 继续执行任务: {next_task['name']}")
        print(f"   优先级: {next_task['priority']}")
        print(f"   当前进度: {next_task['progress']}%")
        print(f"   建议: 继续完成此任务")
        
        # 更新当前任务
        self.progress["current_task_id"] = next_task["id"]
        self._save_progress(self.progress)
        
        return next_task
    
    def update_task_progress(self, task_id: int, progress: float, status: str = None):
        """更新任务进度"""
        task = next((t for t in self.tasks if t["id"] == task_id), None)
        if not task:
            print(f"❌ 任务 ID {task_id} 不存在")
            return
        
        task["progress"] = progress
        task["updated_at"] = datetime.now().isoformat()
        if status:
            task["status"] = status
        
        self._save_tasks(self.tasks)
        print(f"✅ 任务进度已更新: {task['name']} ({progress}%)")
    
    def complete_task(self, task_id: int):
        """完成任务"""
        self.update_task_progress(task_id, 100, "completed")
        self.progress["completed_tasks"].append(task_id)
        self._save_progress(self.progress)
        print(f"🎉 任务已完成！")
    
    def sync_with_filesystem(self) -> Dict:
        """
        元认知：自动同步文件系统中的真实进度
        每次检查任务前先同步，避免使用过期数据
        """
        import subprocess
        
        sync_report = {
            "synced_tasks": [],
            "warnings": [],
            "updates": []
        }
        
        # 知识库目录 → 字数映射
        knowledge_paths = {
            1: "tilelangascend-knowledge-base",  # 知识库任务
        }
        
        for task_id, path_suffix in knowledge_paths.items():
            # 尝试多个可能的路径
            possible_paths = [
                Path.cwd() / path_suffix,
                Path(__file__).parent.parent.parent / path_suffix,
                Path.home() / "openclaw-workspace" / path_suffix,
            ]
            
            target_dir = None
            for p in possible_paths:
                if p.exists():
                    target_dir = p
                    break
            
            if not target_dir:
                sync_report["warnings"].append(f"任务 {task_id}: 目录未找到")
                continue
            
            # 扫描所有 .md 文件字数
            try:
                total_chars = 0
                file_count = 0
                
                for md_file in target_dir.rglob("*.md"):
                    if md_file.is_file():
                        try:
                            content = md_file.read_text(encoding='utf-8', errors='ignore')
                            total_chars += len(content)
                            file_count += 1
                        except:
                            pass
                
                # 计算进度 (假设目标 100k 字)
                actual_progress = min(100, round(total_chars / 100000 * 100, 1))
                
                # 找到对应任务
                task = next((t for t in self.tasks if t["id"] == task_id), None)
                if task:
                    recorded_progress = task.get("progress", 0)
                    
                    # 如果实际进度 > 记录进度，自动更新
                    if actual_progress > recorded_progress:
                        old_progress = task["progress"]
                        task["progress"] = actual_progress
                        task["updated_at"] = datetime.now().isoformat()
                        self._save_tasks(self.tasks)
                        
                        sync_report["updates"].append({
                            "task_id": task_id,
                            "task_name": task["name"],
                            "old_progress": old_progress,
                            "new_progress": actual_progress,
                            "files": file_count,
                            "chars": total_chars
                        })
                    else:
                        sync_report["synced_tasks"].append({
                            "task_id": task_id,
                            "progress": actual_progress,
                            "files": file_count
                        })
                        
            except Exception as e:
                sync_report["warnings"].append(f"任务 {task_id}: 同步失败 - {str(e)}")
        
        return sync_report
    
    def status(self):
        """显示当前状态"""
        # 先同步文件系统
        sync_report = self.sync_with_filesystem()
        
        if sync_report["updates"]:
            print("\n🔄 自动同步发现进度更新:")
            for u in sync_report["updates"]:
                print(f"   [{u['task_id']}] {u['task_name']}: {u['old_progress']}% → {u['new_progress']}%")
        
        print("\n" + "=" * 80)
        print("📊 Smart Task Manager - 状态报告")
        print("=" * 80)
        print(f"⏰ 当前时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📂 会话开始: {self.progress['session_start']}")
        print(f"🕐 最后更新: {self.progress['last_update']}")
        print(f"🎯 当前任务ID: {self.progress['current_task_id']}")
        print(f"✅ 已完成任务: {len(self.progress['completed_tasks'])} 个")
        print(f"💾 检查点数量: {len(self.progress['checkpoints'])} 个")
        print()
        
        self.list_tasks()
        
        # 显示当前任务
        current_task = next((t for t in self.tasks if t["id"] == self.progress["current_task_id"]), None)
        if current_task:
            print(f"\n🎯 当前任务: {current_task['name']} (进度: {current_task['progress']}%)")

def main():
    parser = argparse.ArgumentParser(description="Smart Task Manager")
    parser.add_argument("--status", action="store_true", help="显示当前状态")
    parser.add_argument("--list", action="store_true", help="列出所有任务")
    parser.add_argument("--add", nargs=2, metavar=("NAME", "PRIORITY"), help="添加新任务")
    parser.add_argument("--check", action="store_true", help="检查未完成任务")
    parser.add_argument("--continue", dest="auto_continue", action="store_true", help="自动继续下一个任务")
    parser.add_argument("--save", nargs=2, metavar=("TASK_ID", "NOTE"), help="保存检查点")
    parser.add_argument("--update", nargs=2, metavar=("TASK_ID", "PROGRESS"), help="更新任务进度")
    parser.add_argument("--complete", type=int, metavar="TASK_ID", help="完成任务")
    
    args = parser.parse_args()
    
    manager = SmartTaskManager()
    
    if args.status:
        manager.status()
    elif args.list:
        manager.list_tasks()
    elif args.add:
        name, priority = args.add
        manager.add_task(name, int(priority))
    elif args.check:
        manager.check_unfinished_tasks()
    elif args.auto_continue:
        manager.auto_continue()
    elif args.save:
        task_id, note = args.save
        manager.save_checkpoint(int(task_id), note)
    elif args.update:
        task_id, progress = args.update
        manager.update_task_progress(int(task_id), float(progress))
    elif args.complete is not None:
        manager.complete_task(args.complete)
    else:
        # 默认显示状态
        manager.status()

if __name__ == "__main__":
    main()
