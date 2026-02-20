#!/usr/bin/env python3
"""
Lisa 磁盘监控技能
监控硬盘空间，自动告警，资源调度建议
"""

import subprocess
import os
from datetime import datetime

class DiskMonitor:
    """磁盘监控"""
    
    def __init__(self):
        self.threshold_warning = 80  # 警告阈值
        self.threshold_danger = 90  # 危险阈值
        self.disks = []
        
    def get_disk_info(self):
        """获取磁盘信息"""
        try:
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "size,freespace,caption"],
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split("\n")[1:]  # 跳过标题
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    letter = parts[0].replace(":", "")
                    try:
                        free = int(parts[1]) / (1024**3)  # GB
                        total = int(parts[2]) / (1024**3)
                        used = total - free
                        usage = (used / total) * 100
                        
                        self.disks.append({
                            "letter": letter,
                            "free": round(free, 1),
                            "total": round(total, 1),
                            "used": round(used, 1),
                            "usage": round(usage, 1)
                        })
                    except:
                        pass
        except Exception as e:
            print(f"Error: {e}")
    
    def check_space(self):
        """检查空间并告警"""
        self.get_disk_info()
        
        print("=" * 50)
        print("💾 Lisa 磁盘监控")
        print("=" * 50)
        print(f"时间: {datetime.now()}")
        print()
        
        recommendations = []
        
        for disk in self.disks:
            status = "✅"
            if disk["usage"] >= self.threshold_danger:
                status = "🔴 危险"
            elif disk["usage"] >= self.threshold_warning:
                status = "⚠️ 警告"
            
            print(f"  {disk['letter']}: {disk['used']}GB / {disk['total']}GB "
                  f"({disk['usage']}%) {status}")
            
            # 资源调度建议
            if disk["usage"] >= self.threshold_warning:
                recommendations.append(disk)
        
        print()
        
        # 输出建议
        if recommendations:
            print("📋 资源调度建议:")
            # 找最空的盘
            emptiest = min(self.disks, key=lambda x: x["usage"])
            print(f"  - 大型文件建议存放到 {emptiest['letter']} 盘 (仅使用 {emptiest['usage']}%)")
            
            for disk in recommendations:
                print(f"  - {disk['letter']} 盘已超过 {self.threshold_warning}%! "
                      f"建议清理或移动大型文件")
        else:
            print("✅ 所有磁盘空间充足")
        
        print("=" * 50)
        
        return self.disks

if __name__ == "__main__":
    monitor = DiskMonitor()
    monitor.check_space()
