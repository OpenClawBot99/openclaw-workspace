# plugins - 插件系统

本目录用于存放 TileLangAscend 知识库的插件系统。

## 目录结构

```
plugins/
├── README.md
├── plugin-interface.md           # 插件接口定义
├── search-plugin.md             # 搜索插件
├── code-generator-plugin.md     # 代码生成插件
└── knowledge-updater-plugin.md # 知识更新插件
```

## 插件系统设计

### 插件接口

```python
class KnowledgeBasePlugin:
    def __init__(self, config):
        self.config = config
    
    def initialize(self, kb_path):
        """初始化插件"""
        pass
    
    def execute(self, *args, **kwargs):
        """执行插件功能"""
        pass
    
    def cleanup(self):
        """清理资源"""
        pass
```

### 内置插件

1. **搜索插件** - 快速检索知识库
2. **代码生成插件** - 根据描述生成代码
3. **知识更新插件** - 自动同步最新知识

### 使用方法

```python
from knowledge_base import KnowledgeBase

# 加载插件
kb = KnowledgeBase('path/to/kb')
kb.load_plugin('search')
kb.load_plugin('code_generator')

# 使用插件
results = kb.search('matrix multiplication')
code = kb.generate_code('create a tensor')
```

## 贡献新插件

欢迎贡献新的插件！请遵循：
1. 实现插件接口
2. 添加单元测试
3. 编写使用文档

---
*最后更新: 2026-02-15*
