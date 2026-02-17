#!/usr/bin/env python3
"""
Enhanced Smart Task Manager - 增强版智能任务管理器

新增功能：
1. 资源管理 - 监控内存和本地资源
2. 自动清理 - 已完成任务3天后清理
3. 智能任务发现 - 自我演化添加未完成任务
4. 定期执行 - 自动触发
"""

import json
import os
import sys
import shutil
import psutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import argparse

# 配置路径
SKILL_DIR = Path(__file__).parent.parent
STATE_DIR = SKILL_DIR / "state"
TASKS_FILE = STATE_DIR / "tasks.json"
PROGRESS_FILE = STATE_DIR / "progress.json"
CONFIG_FILE = SKILL_DIR / "config.json"
CHECKPOINTS_DIR = STATE_DIR / "checkpoints"
HISTORY_DIR = STATE_DIR / "history"

class EnhancedTaskManager:
    """增强版智能任务管理器"""
    
    def __init__(self):
        self._ensure_state_dir()
        self.config = self._load_config()
        self.tasks = self._load_tasks()
        self.progress = self._load_progress()
    
    def _ensure_state_dir(self):
        """确保状态目录存在"""
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        CHECKPOINTS_DIR.mkdir(exist_ok=True)
        HISTORY_DIR.mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """加载配置"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            return {
                "auto_save_interval_minutes": 30,
                "max_checkpoint_history": 10,
                "completed_task_retention_days": 3,  # 已完成任务保留3天
                "memory_threshold_percent": 80,  # 内存阈值80%
                "disk_threshold_percent": 90,  # 磁盘阈值90%
                "task_priorities": {
                    "learning": 9,
                    "development": 8,
                    "documentation": 7,
                    "maintenance": 5
                },
                "recovery_strategy": "latest_unfinished",
                "auto_task_discovery": {
                    "enabled": True,
                    "scan_workspace": True,
                    "check_learning_progress": True,
                    "align_with_ten_year_goal": True
                }
            }
    
    def _load_tasks(self) -> List[Dict]:
        """加载任务列表"""
        if TASKS_FILE.exists():
            with open(TASKS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    
    def _load_progress(self) -> Dict:
        """加载进度"""
        if PROGRESS_FILE.exists():
            with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "current_task_id": None,
            "last_update": datetime.now().isoformat(),
            "session_start": datetime.now().isoformat(),
            "completed_tasks": [],
            "checkpoints": []
        }
    
    def _save_tasks(self, tasks: List[Dict]):
        """保存任务列表"""
        with open(TASKS_FILE, 'w', encoding='utf-8') as f:
            json.dump(tasks, f, indent=2, ensure_ascii=False)
    
    def _save_progress(self, progress: Dict):
        """保存进度"""
        with open(PROGRESS_FILE, 'w', encoding='utf-8') as f:
            json.dump(progress, f, indent=2, ensure_ascii=False)
    
    # ==================== 资源管理 ====================
    
    def check_resources(self):
        """检查系统资源"""
        print("\n" + "=" * 80)
        print("📊 系统资源检查")
        print("=" * 80)
        
        # 内存检查
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        print(f"💾 内存使用: {memory_percent:.1f}% ({memory.used / (1024**3):.2f} / {memory.total / (1024**3):.2f} GB)")
        
        if memory_percent > self.config["memory_threshold_percent"]:
            print(f"⚠️  内存使用超过阈值 {self.config['memory_threshold_percent']}%")
            self._cleanup_memory()
        
        # 磁盘检查
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        print(f"💿 磁盘使用: {disk_percent:.1f}% ({disk.used / (1024**3):.2f} / {disk.total / (1024**3):.2f} GB)")
        
        if disk_percent > self.config["disk_threshold_percent"]:
            print(f"⚠️  磁盘使用超过阈值 {self.config['disk_threshold_percent']}%")
            self._cleanup_disk()
        
        # CPU 检查
        cpu_percent = psutil.cpu_percent(interval=1)
        print(f"⚡ CPU 使用: {cpu_percent:.1f}%")
        
        return {
            "memory_percent": memory_percent,
            "disk_percent": disk_percent,
            "cpu_percent": cpu_percent
        }
    
    def _cleanup_memory(self):
        """清理内存"""
        print("🧹 清理内存中...")
        
        # 1. 清理旧的检查点
        self._cleanup_old_checkpoints()
        
        # 2. 压缩历史记录
        self._compact_history()
        
        print("✅ 内存清理完成")
    
    def _cleanup_disk(self):
        """清理磁盘"""
        print("🧹 清理磁盘中...")
        
        # 1. 清理临时文件
        temp_dir = Path("temp")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
            print(f"   - 删除临时目录: {temp_dir}")
        
        # 2. 清理旧的检查点
        self._cleanup_old_checkpoints()
        
        print("✅ 磁盘清理完成")
    
    def _cleanup_old_checkpoints(self):
        """清理旧的检查点"""
        retention_days = self.config["completed_task_retention_days"]
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        deleted_count = 0
        for checkpoint_file in CHECKPOINTS_DIR.glob("*.json"):
            if checkpoint_file.stat().st_mtime < cutoff_date.timestamp():
                checkpoint_file.unlink()
                deleted_count += 1
        
        if deleted_count > 0:
            print(f"   - 删除 {deleted_count} 个旧检查点")
    
    def _compact_history(self):
        """压缩历史记录"""
        history_file = HISTORY_DIR / "task_history.json"
        if history_file.exists():
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
            
            # 只保留最近100条记录
            if len(history) > 100:
                history = history[-100:]
                with open(history_file, 'w', encoding='utf-8') as f:
                    json.dump(history, f, indent=2, ensure_ascii=False)
                print(f"   - 压缩历史记录: 保留最近100条")
    
    # ==================== 自动清理已完成任务 ====================
    
    def cleanup_completed_tasks(self):
        """清理已完成的任务（超过3天）"""
        retention_days = self.config["completed_task_retention_days"]
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        print(f"\n🧹 清理已完成任务（保留 {retention_days} 天）...")
        
        tasks_to_keep = []
        deleted_count = 0
        
        for task in self.tasks:
            if task["status"] == "completed":
                # 检查完成时间
                completed_at = task.get("completed_at")
                if completed_at:
                    completed_date = datetime.fromisoformat(completed_at)
                    if completed_date < cutoff_date:
                        print(f"   - 删除已完成任务: {task['name']}")
                        deleted_count += 1
                        continue
            
            tasks_to_keep.append(task)
        
        if deleted_count > 0:
            self.tasks = tasks_to_keep
            self._save_tasks(self.tasks)
            print(f"✅ 清理完成: 删除 {deleted_count} 个旧任务")
        else:
            print("✅ 没有需要清理的任务")
    
    # ==================== 智能任务发现 ====================
    
    def discover_new_tasks(self) -> List[Dict]:
        """自动发现新任务（自我演化）"""
        print("\n🔍 自动发现新任务...")
        
        new_tasks = []
        
        if not self.config["auto_task_discovery"]["enabled"]:
            print("   自动任务发现已禁用")
            return new_tasks
        
        # 1. 扫描 workspace 发现未完成项目
        if self.config["auto_task_discovery"]["scan_workspace"]:
            tasks = self._scan_workspace_for_tasks()
            new_tasks.extend(tasks)
        
        # 2. 检查学习进度
        if self.config["auto_task_discovery"]["check_learning_progress"]:
            tasks = self._check_learning_progress()
            new_tasks.extend(tasks)
        
        # 3. 与十年目标对齐
        if self.config["auto_task_discovery"]["align_with_ten_year_goal"]:
            tasks = self._align_with_ten_year_goal()
            new_tasks.extend(tasks)
        
        # 去重并添加到任务列表
        for task in new_tasks:
            if not any(t["name"] == task["name"] for t in self.tasks):
                self.tasks.append(task)
                print(f"   ✅ 发现新任务: {task['name']}")
        
        if new_tasks:
            self._save_tasks(self.tasks)
        
        return new_tasks
    
    def _scan_workspace_for_tasks(self) -> List[Dict]:
        """扫描 workspace 发现未完成项目"""
        tasks = []
        workspace = Path("C:/Users/Lenovo/.openclaw/workspace")
        
        # 检查 tilelangascend-knowledge-base
        kb_dir = workspace / "tilelangascend-knowledge-base"
        if kb_dir.exists():
            # 检查进度
            progress_file = kb_dir / "PROGRESS.md"
            if progress_file.exists():
                with open(progress_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if "71%" in content:  # Markdown 阅读进度
                        tasks.append({
                            "id": len(self.tasks) + len(tasks) + 1,
                            "name": "完善 tilelang-ascend 知识库 - 阅读剩余 Markdown 文件",
                            "priority": 7,
                            "status": "pending",
                            "created_at": datetime.now().isoformat(),
                            "updated_at": datetime.now().isoformat(),
                            "progress": 71,
                            "category": "documentation",
                            "description": "阅读剩余 12 个 Markdown 文件，达到 100% 完成度"
                        })
        
        return tasks
    
    def _check_learning_progress(self) -> List[Dict]:
        """检查学习进度"""
        tasks = []
        
        # 检查 AI INFRA 学习进度
        learning_file = Path("C:/Users/Lenovo/.openclaw/workspace/learning-progress.md")
        if learning_file.exists():
            with open(learning_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # 如果学习热情下降，添加提醒任务
                if "学习热情: 8" in content:
                    tasks.append({
                        "id": len(self.tasks) + len(tasks) + 1,
                        "name": "提升学习热情 - 探索新的 AI INFRA 技术",
                        "priority": 8,
                        "status": "pending",
                        "created_at": datetime.now().isoformat(),
                        "updated_at": datetime.now().isoformat(),
                        "progress": 0,
                        "category": "learning",
                        "description": "学习热情从 9 降到 8，需要探索新技术提升兴趣"
                    })
        
        return tasks
    
    def _align_with_ten_year_goal(self) -> List[Dict]:
        """与十年目标对齐"""
        tasks = []
        
        # 检查十年目标文件
        roadmap_file = Path("C:/Users/Lenovo/.openclaw/workspace/ten-year-strategic-roadmap.md")
        if roadmap_file.exists():
            # 添加 Phase 1 任务
            tasks.append({
                "id": len(self.tasks) + len(tasks) + 1,
                "name": "继续 Phase 1 - 智能生命体开发",
                "priority": 9,
                "status": "pending",
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "progress": 80,
                "category": "development",
                "description": "完成 survival-instinct 和 resource-manager 开发"
            })
        
        return tasks
    
    # ==================== 综合管理 ====================
    
    def auto_manage(self):
        """自动管理：资源检查 + 清理 + 任务发现"""
        print("\n" + "=" * 80)
        print("🤖 自动管理启动")
        print("=" * 80)
        
        # 1. 检查资源
        self.check_resources()
        
        # 2. 清理已完成任务
        self.cleanup_completed_tasks()
        
        # 3. 发现新任务
        self.discover_new_tasks()
        
        # 4. 自动继续未完成任务
        next_task = self.get_next_task()
        if next_task:
            print(f"\n🎯 建议继续执行: {next_task['name']}")
        
        print("\n" + "=" * 80)
        print("✅ 自动管理完成")
        print("=" * 80)
    
    def get_next_task(self) -> Optional[Dict]:
        """获取下一个应该执行的任务"""
        unfinished = [t for t in self.tasks if t["status"] in ["pending", "in_progress"]]
        
        if not unfinished:
            return None
        
        # 按优先级排序
        sorted_tasks = sorted(unfinished, key=lambda t: t["priority"], reverse=True)
        
        # 优先选择进行中的任务
        in_progress = [t for t in sorted_tasks if t["status"] == "in_progress"]
        if in_progress:
            return in_progress[0]
        
        return sorted_tasks[0]
    
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
            print()

def main():
    parser = argparse.ArgumentParser(description="Enhanced Smart Task Manager")
    parser.add_argument("--auto", action="store_true", help="运行自动管理（资源检查 + 清理 + 任务发现）")
    parser.add_argument("--check-resources", action="store_true", help="检查系统资源")
    parser.add_argument("--cleanup", action="store_true", help="清理已完成任务")
    parser.add_argument("--discover", action="store_true", help="自动发现新任务")
    parser.add_argument("--list", action="store_true", help="列出所有任务")
    
    args = parser.parse_args()
    
    manager = EnhancedTaskManager()
    
    if args.auto:
        manager.auto_manage()
    elif args.check_resources:
        manager.check_resources()
    elif args.cleanup:
        manager.cleanup_completed_tasks()
    elif args.discover:
        manager.discover_new_tasks()
    elif args.list:
        manager.list_tasks()
    else:
        # 默认运行自动管理
        manager.auto_manage()

if __name__ == "__main__":
    main()
