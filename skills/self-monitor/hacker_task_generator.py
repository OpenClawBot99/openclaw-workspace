#!/usr/bin/env python3
"""
Lisa 智能任务生成系统 - 黑客技能专注版
目标：世界第一黑客
"""

import random
from datetime import datetime
from pathlib import Path

class HackerTaskGenerator:
    """黑客技能任务生成器"""
    
    def __init__(self):
        # 黑客技能领域
        self.hacker_skills = {
            "web_security": {
                "name": "Web安全",
                "topics": ["SQL注入", "XSS", "CSRF", "SSRF", "文件上传", "命令注入"],
                "focus": "渗透测试"
            },
            "binary_exploit": {
                "name": "二进制漏洞",
                "topics": ["缓冲区溢出", "堆风水", "ROP", "格式化字符串", "UAF"],
                "focus": "漏洞利用"
            },
            "reverse_engineering": {
                "name": "逆向工程",
                "topics": ["IDA Pro", "Ghidra", "反调试", "软件破解", "恶意软件分析"],
                "focus": "代码分析"
            },
            "network_hacking": {
                "name": "网络渗透",
                "topics": ["Nmap", "Wireshark", "ARP欺骗", "DNS劫持", "中间人攻击"],
                "focus": "网络入侵"
            },
            "privilege_escalation": {
                "name": "权限提升",
                "topics": ["Linux提权", "Windows提权", "sudo配置错误", "内核漏洞"],
                "focus": "权限获取"
            },
            "social_engineering": {
                "name": "社会工程",
                "topics": ["钓鱼攻击", "钓鱼邮件", "假冒电话", "信息收集"],
                "focus": "人为漏洞"
            },
            "crypto_attack": {
                "name": "密码攻击",
                "topics": ["暴力破解", "字典攻击", "哈希碰撞", "弱加密"],
                "focus": "密码破解"
            },
            "malware": {
                "name": "恶意软件",
                "topics": ["病毒", "蠕虫", "木马", "勒索软件", "Rootkit"],
                "focus": "恶意代码"
            }
        }
        
    def generate_task(self) -> dict:
        """生成黑客任务"""
        
        # 随机选择技能领域
        skill = random.choice(list(self.hacker_skills.values()))
        topic = random.choice(skill["topics"])
        
        # 随机选择任务类型
        task_types = [
            {"type": "knowledge_base", "output": f"memory/hacker/{skill['name']}_{topic}.md"},
            {"type": "replicate_code", "output": f"workspace/hacker/{skill['name']}_{topic}/"},
            {"type": "create_skill", "output": f"skills/hacker/{skill['name']}_{topic}/"},
        ]
        
        task_type = random.choice(task_types)
        
        return {
            "name": f"学习{skill['name']} - {topic}",
            "type": task_type["type"],
            "skill": skill["name"],
            "topic": topic,
            "focus": skill["focus"],
            "actions": self._get_actions(skill["name"], topic, task_type["type"]),
            "output": task_type["output"],
            "goal_size": "medium",
            "purpose": f"成为世界第一黑客 - {skill['name']}"
        }
    
    def _get_actions(self, skill: str, topic: str, task_type: str) -> list:
        """获取具体行动步骤"""
        
        if task_type == "knowledge_base":
            return [
                f"搜索{topic}相关资料",
                "阅读官方文档/论文",
                "分析经典案例",
                "整理成笔记",
                "存入知识库"
            ]
        elif task_type == "replicate_code":
            return [
                f"搜索{topic}开源项目",
                "下载并分析源码",
                "搭建测试环境",
                "复现漏洞/攻击",
                "记录过程和心得"
            ]
        else:  # create_skill
            return [
                f"设计{topic}Skill框架",
                "编写核心功能代码",
                "编写SKILL.md文档",
                "编写测试用例",
                "发布到skills目录"
            ]

def demo():
    """演示"""
    gen = HackerTaskGenerator()
    
    print("=" * 60)
    print("🎯 黑客技能任务生成器")
    print("目标：世界第一黑客 🏴‍☠️")
    print("=" * 60)
    
    for _ in range(5):
        task = gen.generate_task()
        
        print(f"\n📌 任务: {task['name']}")
        print(f"类型: {task['type']}")
        print(f"领域: {task['skill']}")
        print(f"目标: {task['purpose']}")
        
        print(f"\n📋 步骤:")
        for i, action in enumerate(task['actions'], 1):
            print(f"   {i}. {action}")
        
        print(f"\n📤 输出: {task['output']}")
        print("-" * 50)

if __name__ == "__main__":
    demo()
