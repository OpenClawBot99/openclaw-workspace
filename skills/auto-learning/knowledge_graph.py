#!/usr/bin/env python3
"""
Knowledge Graph Builder
构建知识图谱，管理概念关联，跟踪学习进度
"""

import json
from datetime import datetime
from pathlib import Path

SKILL_DIR = Path(__file__).parent
STATE_DIR = SKILL_DIR / "state"
KNOWLEDGE_GRAPH = STATE_DIR / "knowledge_graph.json"

class KnowledgeGraph:
    def __init__(self):
        self.graph = self._load()
    
    def _load(self):
        if KNOWLEDGE_GRAPH.exists():
            with open(KNOWLEDGE_GRAPH, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "nodes": {},
            "edges": [],
            "last_updated": datetime.now().isoformat()
        }
    
    def _save(self):
        self.graph["last_updated"] = datetime.now().isoformat()
        STATE_DIR.mkdir(exist_ok=True)
        with open(KNOWLEDGE_GRAPH, 'w', encoding='utf-8') as f:
            json.dump(self.graph, f, indent=2, ensure_ascii=False)
    
    def add_concept(self, concept, domain, mastery=0, source=""):
        """添加概念"""
        self.graph["nodes"][concept] = {
            "domain": domain,
            "mastery": mastery,  # 0-100
            "source": source,
            "added_at": datetime.now().isoformat(),
            "last_reviewed": None
        }
        self._save()
        print(f"✅ 添加概念: {concept} ({domain})")
    
    def add_relation(self, from_concept, to_concept, relation_type="depends_on"):
        """添加概念关联"""
        self.graph["edges"].append({
            "from": from_concept,
            "to": to_concept,
            "type": relation_type,
            "added_at": datetime.now().isoformat()
        })
        self._save()
        print(f"🔗 关联: {from_concept} --[{relation_type}]--> {to_concept}")
    
    def update_mastery(self, concept, mastery):
        """更新掌握程度"""
        if concept in self.graph["nodes"]:
            self.graph["nodes"][concept]["mastery"] = mastery
            self.graph["nodes"][concept]["last_reviewed"] = datetime.now().isoformat()
            self._save()
            print(f"📈 {concept} 掌握度: {mastery}%")
        else:
            print(f"❌ 概念不存在: {concept}")
    
    def get_related(self, concept):
        """获取相关概念"""
        related = []
        for edge in self.graph["edges"]:
            if edge["from"] == concept:
                related.append((edge["to"], edge["type"]))
            elif edge["to"] == concept:
                related.append((edge["from"], edge["type"]))
        return related
    
    def get_domain_progress(self, domain):
        """获取领域进度"""
        concepts = [k for k, v in self.graph["nodes"].items() if v["domain"] == domain]
        if not concepts:
            return 0
        
        total_mastery = sum(self.graph["nodes"][c]["mastery"] for c in concepts)
        return total_mastery / len(concepts)
    
    def print_summary(self):
        """打印摘要"""
        print("\n📊 知识图谱摘要")
        print("=" * 50)
        print(f"概念数量: {len(self.graph['nodes'])}")
        print(f"关联数量: {len(self.graph['edges'])}")
        print(f"最后更新: {self.graph['last_updated']}")
        
        # 按领域统计
        domains = {}
        for concept, info in self.graph["nodes"].items():
            d = info["domain"]
            domains[d] = domains.get(d, 0) + 1
        
        print("\n📂 各领域概念数:")
        for domain, count in sorted(domains.items(), key=lambda x: -x[1]):
            progress = self.get_domain_progress(domain)
            print(f"  {domain}: {count} 个概念 (掌握度: {progress:.1f}%)")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Knowledge Graph Builder")
    parser.add_argument("--add", help="添加概念")
    parser.add_argument("--domain", help="概念领域")
    parser.add_argument("--mastery", type=int, default=0, help="掌握程度 0-100")
    parser.add_argument("--source", help="学习来源")
    parser.add_argument("--relate", nargs=2, metavar=("FROM", "TO"), help="添加关联")
    parser.add_argument("--summary", action="store_true", help="显示摘要")
    
    args = parser.parse_args()
    
    kg = KnowledgeGraph()
    
    if args.add and args.domain:
        kg.add_concept(args.add, args.domain, args.mastery, args.source or "")
    elif args.relate:
        kg.add_relation(args.relate[0], args.relate[1])
    elif args.summary:
        kg.print_summary()
    else:
        # 默认显示摘要
        kg.print_summary()

if __name__ == "__main__":
    main()
