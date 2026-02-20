#!/usr/bin/env python3
"""
Auto-Learning Plan Generator
自动生成学习计划，识别知识盲区，优先级排序
"""

import json
import os
from datetime import datetime
from pathlib import Path

SKILL_DIR = Path(__file__).parent
STATE_DIR = SKILL_DIR / "state"
CONCEPT_MAP = STATE_DIR / "concept_map.json"
LEARNING_LOG = STATE_DIR / "learning_log.md"

# 核心知识领域（与十年目标对齐）
CORE_domains = {
    "AI INFRA": 9,  # 最高优先级
    "AscendC": 8,
    "vLLM": 7,
    "DeepSpeed": 6,
    "Self-Evolving AI": 5,
    "Model Quantization": 4,
}

def load_concept_map():
    """加载概念地图"""
    if CONCEPT_MAP.exists():
        with open(CONCEPT_MAP, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {
        "known_concepts": [],
        "learning_in_progress": [],
        "to_learn": []
    }

def save_concept_map(data):
    """保存概念地图"""
    STATE_DIR.mkdir(exist_ok=True)
    with open(CONCEPT_MAP, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def generate_weekly_plan():
    """生成每周学习计划"""
    concept_map = load_concept_map()
    
    plan = {
        "week": datetime.now().strftime("%Y-W%W"),
        "generated_at": datetime.now().isoformat(),
        "focus_areas": [],
        "daily_topics": []
    }
    
    # 按优先级选择学习领域
    for domain, priority in sorted(CORE_domains.items(), key=lambda x: -x[1]):
        if priority >= 7:  # 高优先级
            plan["focus_areas"].append({
                "domain": domain,
                "priority": priority,
                "status": "active" if domain in concept_map["learning_in_progress"] else "new"
            })
    
    # 生成每日主题
    topics = [
        "AI INFRA 基础概念",
        "Docker 容器化",
        "vLLM 推理引擎",
        "模型部署实战",
        "性能优化技巧",
        "论文阅读",
        "知识整合与复盘"
    ]
    
    for i, topic in enumerate(topics):
        plan["daily_topics"].append({
            "day": i + 1,
            "topic": topic,
            "status": "pending"
        })
    
    return plan

def identify_gaps():
    """识别知识盲区"""
    concept_map = load_concept_map()
    
    gaps = []
    
    # 检查核心领域掌握情况
    for domain, priority in CORE_domains.items():
        if domain not in concept_map["known_concepts"]:
            gaps.append({
                "domain": domain,
                "priority": priority,
                "reason": "核心领域未掌握"
            })
    
    return gaps

def main():
    print("🎯 Auto-Learning Plan Generator")
    print("=" * 50)
    
    # 生成学习计划
    plan = generate_weekly_plan()
    
    print(f"\n📅 本周学习计划 ({plan['week']})")
    print("-" * 50)
    
    print("\n🔥 重点领域:")
    for area in plan["focus_areas"]:
        status_icon = "✅" if area["status"] == "active" else "🆕"
        print(f"  {status_icon} {area['domain']} (优先级: {area['priority']})")
    
    print("\n📚 每日主题:")
    for day in plan["daily_topics"]:
        print(f"  Day {day['day']}: {day['topic']}")
    
    # 识别盲区
    gaps = identify_gaps()
    if gaps:
        print("\n⚠️ 知识盲区:")
        for gap in gaps:
            print(f"  - {gap['domain']} (优先级: {gap['priority']})")
    
    # 保存计划
    STATE_DIR.mkdir(exist_ok=True)
    plan_file = STATE_DIR / "weekly_plan.json"
    with open(plan_file, 'w', encoding='utf-8') as f:
        json.dump(plan, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 计划已保存到: {plan_file}")
    
    return plan

if __name__ == "__main__":
    main()
