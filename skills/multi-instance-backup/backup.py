#!/usr/bin/env python3
"""
Multi-Instance Backup System
多实例部署与备份，确保数据永不丢失
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path

BACKUP_DIR = Path("C:\\Users\\Lenovo\\.openclaw\\workspace\\backups")

def full_backup():
    """全量备份"""
    source = Path("C:\\Users\\Lenovo\\.openclaw\\workspace")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"full_backup_{timestamp}"
    
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    # 备份关键文件
    key_files = [
        "MEMORY.md",
        "SOUL.md",
        "AGENTS.md",
        "USER.md",
        "intelligent-life-roadmap.md",
        "ten-year-strategic-roadmap.md",
    ]
    
    backup_path.mkdir(exist_ok=True)
    
    for file in key_files:
        src = source / file
        if src.exists():
            dst = backup_path / file
            shutil.copy2(src, dst)
            print(f"✅ 已备份: {file}")
    
    # 备份 memory 目录
    memory_src = source / "memory"
    if memory_src.exists():
        memory_dst = backup_path / "memory"
        shutil.copytree(memory_src, memory_dst)
        print(f"✅ 已备份: memory/")
    
    # 备份 skills 目录结构
    skills_src = source / "skills"
    if skills_src.exists():
        skills_dst = backup_path / "skills"
        # 只备份 SKILL.md 文件
        skills_dst.mkdir(exist_ok=True)
        for skill_dir in skills_src.iterdir():
            if skill_dir.is_dir():
                skill_backup = skills_dst / skill_dir.name
                skill_backup.mkdir(exist_ok=True)
                for f in skill_dir.glob("*.md"):
                    shutil.copy2(f, skill_backup / f.name)
        print(f"✅ 已备份: skills/")
    
    # 保存备份元数据
    metadata = {
        "backup_time": datetime.now().isoformat(),
        "backup_type": "full",
        "files_backed_up": len(key_files),
        "backup_path": str(backup_path)
    }
    
    with open(backup_path / "metadata.json", 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 全量备份完成: {backup_path}")
    return backup_path

def list_backups():
    """列出所有备份"""
    if not BACKUP_DIR.exists():
        print("❌ 暂无备份")
        return []
    
    backups = sorted(BACKUP_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)
    
    print("\n📦 可用备份:")
    print("=" * 50)
    
    for backup in backups:
        metadata_file = backup / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            print(f"📁 {backup.name}")
            print(f"   时间: {meta.get('backup_time', 'N/A')}")
            print(f"   类型: {meta.get('backup_type', 'N/A')}")
        else:
            print(f"📁 {backup.name}")
    
    return backups

def quick_restore(backup_name=None):
    """快速恢复"""
    if backup_name is None:
        # 默认恢复最新的
        backups = sorted(BACKUP_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)
        if not backups:
            print("❌ 暂无备份可恢复")
            return
        backup_name = backups[0].name
    
    backup_path = BACKUP_DIR / backup_name
    if not backup_path.exists():
        print(f"❌ 备份不存在: {backup_name}")
        return
    
    target = Path("C:\\Users\\Lenovo\\.openclaw\\workspace")
    
    # 恢复文件
    for f in backup_path.rglob("*.md"):
        rel_path = f.relative_to(backup_path)
        target_file = target / rel_path
        
        target_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target_file)
        print(f"✅ 已恢复: {rel_path}")
    
    print(f"\n✅ 恢复完成: {backup_name}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-Instance Backup System")
    parser.add_argument("--backup", action="store_true", help="执行全量备份")
    parser.add_argument("--list", action="store_true", help="列出所有备份")
    parser.add_argument("--restore", nargs="?", const="latest", help="恢复备份")
    
    args = parser.parse_args()
    
    if args.backup:
        full_backup()
    elif args.list:
        list_backups()
    elif args.restore:
        quick_restore(args.restore)
    else:
        print("🔧 Multi-Instance Backup System")
        print("  --backup    执行全量备份")
        print("  --list      列出所有备份")
        print("  --restore   恢复备份")

if __name__ == "__main__":
    main()
