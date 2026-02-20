#!/usr/bin/env python3
"""
黑客技能任务生成器 v4
加入知乎调研环节，独立思考创建新技能
"""

import random

# 技能领域
DOMAINS = {
    "web": ["SQL注入", "XSS", "CSRF", "文件上传", "SSRF", "命令注入"],
    "binary": ["缓冲区溢出", "堆溢出", "格式化字符串", "UAF", "ROP"],
    "network": ["ARP欺骗", "DNS劫持", "中间人攻击", "Nmap"],
    "privilege": ["Linux提权", "Windows提权", "内核漏洞", "Sudo配置错误"],
    "malware": ["勒索软件", "木马", "蠕虫", "Rootkit", "病毒"],
    "reverse": ["软件破解", "恶意软件分析", "IDA Pro", "Ghidra"],
    "password": ["暴力破解", "字典攻击", "哈希碰撞"],
    "social": ["钓鱼攻击", "假冒电话", "信息收集"],
}

# 知乎热门安全话题（用于调研）
ZHIHU_TOPICS = [
    "网络安全", "黑客", "渗透测试", "Web安全", "二进制安全",
    "CTF", "漏洞分析", "逆向工程", "恶意软件", "数据安全"
]

# 任务类型
TASK_TYPES = [
    {"type": "knowledge_base", "weight": 3, "desc": "知识库"},
    {"type": "create_skill", "weight": 2, "desc": "创建Skill"},
    {"type": "replicate_code", "weight": 2, "desc": "复现代码"},
    {"type": "research", "weight": 2, "desc": "知乎调研+独立思考"},
]

def generate_research_task():
    """生成知乎调研任务"""
    topic = random.choice(ZHIHU_TOPICS)
    return {
        "task": f"知乎调研{topic}技术 - 独立思考创建新技能",
        "type": "research",
        "domain": "research",
        "steps": [
            f"1. 访问知乎/安全网站搜索'{topic}'相关问题",
            "2. 阅读高赞回答和技术文章",
            "3. 总结最新攻击技术和趋势",
            "4. 独立思考：结合已有知识创建新想法",
            "5. 整理成笔记或创建新Skill"
        ],
        "output": f"memory/hacker/知乎_{topic}_调研.md",
        "note": "必须包含独立思考部分，不能照搬"
    }

def generate_task():
    """生成一个随机任务"""
    # 20%概率生成调研任务
    if random.random() < 0.2:
        return generate_research_task()
    
    # 选择任务类型
    task_type = random.choices(
        [t["type"] for t in TASK_TYPES],
        weights=[t["weight"] for t in TASK_TYPES]
    )[0]
    
    # 选择领域
    domain = random.choice(list(DOMAINS.keys()))
    skill = random.choice(DOMAINS[domain])
    
    task_info = {
        "task": f"学习{skill}",
        "type": task_type,
        "domain": domain,
        "skill": skill,
    }
    
    if task_type == "knowledge_base":
        task_info["steps"] = [
            f"1. 知乎调研{skill}相关资料",
            "2. 阅读官方文档/论文",
            "3. 分析经典案例",
            "4. 整理成笔记",
            "5. 存入知识库"
        ]
        task_info["output"] = f"memory/hacker/{skill}.md"
        
    elif task_type == "create_skill":
        task_info["steps"] = [
            f"1. 知乎调研{skill}最新技术",
            "2. 设计Skill框架（加入独立思考）",
            "3. 编写核心功能代码",
            "4. 编写SKILL.md文档",
            "5. 编写测试用例"
        ]
        task_info["output"] = f"skills/hacker/{skill}/"
        
    elif task_type == "replicate_code":
        task_info["steps"] = [
            f"1. 知乎调研{skill}开源项目",
            "2. 下载并分析源码",
            "3. 搭建测试环境",
            "4. 复现漏洞/攻击",
            "5. 记录过程和心得"
        ]
        task_info["output"] = f"workspace/hacker/{skill}/"
    
    return task_info

def main():
    print("=" * 60)
    print("🎯 黑客技能任务生成器 v4")
    print("=" * 60)
    print(f"📌 目标: 世界第一黑客 🏴☠️")
    print("-" * 60)
    
    # 生成5个任务
    tasks = []
    for i in range(5):
        task = generate_task()
        tasks.append(task)
        
        print(f"\n📌 任务: {task['task']}")
        print(f"类型: {task['type']} | 领域: {task['domain']}")
        print("📋 步骤:")
        for step in task.get("steps", []):
            print(f"   {step}")
        print(f"📤 输出: {task.get('output', 'N/A')}")
        if "note" in task:
            print(f"⚠️ 注意: {task['note']}")
        print("-" * 60)

if __name__ == "__main__":
    main()
