#!/usr/bin/env python3
"""
tilelangascend 知识库同步工具
将知识库同步到桌面，并提供插件接口
"""
import os
import shutil
import json
from pathlib import Path
from datetime import datetime


class KnowledgeBaseSync:
    def __init__(self):
        self.source_dir = Path(__file__).parent.resolve()
        self.knowledge_base_name = "tilelangascend-knowledge-base"
        
    def get_desktop_path(self):
        """获取桌面路径"""
        home = Path.home()
        
        # Windows
        if os.name == 'nt':
            desktop = home / "Desktop"
        # macOS
        elif os.name == 'darwin':
            desktop = home / "Desktop"
        # Linux
        else:
            desktop = home / "Desktop"
            
        return desktop
    
    def sync_to_desktop(self):
        """同步知识库到桌面"""
        desktop = self.get_desktop_path()
        target_dir = desktop / self.knowledge_base_name
        
        print(f"源目录: {self.source_dir}")
        print(f"目标目录: {target_dir}")
        
        # 如果目标目录存在，先删除
        if target_dir.exists():
            print(f"删除已有目录: {target_dir}")
            shutil.rmtree(target_dir)
        
        # 复制整个目录
        print(f"正在复制到桌面...")
        shutil.copytree(self.source_dir, target_dir)
        
        print(f"✅ 知识库已同步到: {target_dir}")
        return target_dir
    
    def verify_structure(self):
        """验证知识库结构"""
        expected_dirs = [
            '01-api-reference',
            '02-best-practices', 
            '03-templates',
            '04-techniques',
            '05-examples',
            '06-faq',
            'plugins'
        ]
        
        print("\n📁 知识库结构验证:")
        for dir_name in expected_dirs:
            dir_path = self.source_dir / dir_name
            if dir_path.exists():
                files = list(dir_path.glob('*'))
                print(f"  ✅ {dir_name}/ ({len(files)} 个文件)")
            else:
                print(f"  ❌ {dir_name}/ (缺失)")
        
        # 检查关键文件
        print("\n📄 关键文件检查:")
        for filename in ['README.md', 'index.json', 'metadata.json']:
            filepath = self.source_dir / filename
            if filepath.exists():
                print(f"  ✅ {filename}")
            else:
                print(f"  ❌ {filename}")
    
    def update_timestamp(self):
        """更新时间戳"""
        metadata_file = self.source_dir / 'metadata.json'
        
        if metadata_file.exists():
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            metadata['updated'] = datetime.now().isoformat()
            
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            print("✅ 时间戳已更新")


def main():
    kb = KnowledgeBaseSync()
    
    print("=" * 50)
    print("📚 tilelangascend 知识库同步工具")
    print("=" * 50)
    
    # 验证结构
    kb.verify_structure()
    
    # 同步到桌面
    print("\n🚀 开始同步到桌面...")
    target = kb.sync_to_desktop()
    
    # 更新时间戳
    kb.update_timestamp()
    
    print("\n" + "=" * 50)
    print("✅ 同步完成！")
    print(f"📍 知识库位置: {target}")
    print("=" * 50)


if __name__ == '__main__':
    main()
