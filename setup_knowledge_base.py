import os
import json
from pathlib import Path
from datetime import datetime


def create_directory_structure():
    # 在workspace中创建
    base_dir = Path(r'C:\Users\Lenovo\.openclaw\workspace\tilelangascend-knowledge-base')
    
    subdirs = {
        '01-api-reference': 'API参考',
        '02-best-practices': '最佳实践',
        '03-templates': '代码模板',
        '04-techniques': '调用技巧',
        '05-examples': '完整示例',
        '06-faq': '常见问题',
        'plugins': '插件系统'
    }
    
    base_dir.mkdir(parents=True, exist_ok=True)
    
    for subdir, description in subdirs.items():
        subdir_path = base_dir / subdir
        subdir_path.mkdir(exist_ok=True)
        create_subdir_readme(subdir_path, subdir, description)
    
    create_main_readme(base_dir, subdirs)
    create_index_json(base_dir, subdirs)
    create_metadata_json(base_dir)
    
    print(f'知识库已创建: {base_dir}')
    return base_dir


def create_subdir_readme(path, name, description):
    readme_content = f'''# {name}

## {description}

本目录用于存放{description}相关内容。

## 目录结构

```
{name}/
├── README.md
└── (待添加内容)
```

## 贡献指南

请按照以下规范添加内容：

1. 文件命名使用小写字母和连字符
2. 每个文件应包含清晰的描述
3. 代码示例需要包含注释

---
*最后更新: {datetime.now().strftime('%Y-%m-%d')}*
'''
    readme_path = path / 'README.md'
    readme_path.write_text(readme_content, encoding='utf-8')


def create_main_readme(base_dir, subdirs):
    toc = '\n'.join([f'- [{name}]({name}/) - {desc}' for name, desc in subdirs.items()])
    
    readme_content = f'''# tilelangascend 知识库

TileLangAscend 编程知识库，包含 API 参考、最佳实践、代码模板和示例。

## 目录

{toc}

## 快速开始

1. 浏览 [API 参考](01-api-reference/) 了解核心接口
2. 查看 [最佳实践](02-best-practices/) 学习推荐用法
3. 使用 [代码模板](03-templates/) 快速开始开发

## 知识库结构

| 目录 | 说明 |
|------|------|
| 01-api-reference | API 文档和接口说明 |
| 02-best-practices | 推荐的编程实践 |
| 03-templates | 可复用的代码模板 |
| 04-techniques | 高级调用技巧 |
| 05-examples | 完整的示例项目 |
| 06-faq | 常见问题解答 |
| plugins | 插件开发指南 |

## 贡献

欢迎贡献内容！请遵循以下准则：

- 提交前确保代码可运行
- 添加必要的文档和注释
- 遵循现有的目录结构

## 许可证

MIT License

---
*创建时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
'''
    readme_path = base_dir / 'README.md'
    readme_path.write_text(readme_content, encoding='utf-8')


def create_index_json(base_dir, subdirs):
    index = {
        'name': 'tilelangascend-knowledge-base',
        'version': '1.0.0',
        'sections': [
            {
                'id': name,
                'title': desc,
                'path': f'{name}/',
                'type': 'directory'
            }
            for name, desc in subdirs.items()
        ],
        'files': [
            {
                'path': 'README.md',
                'type': 'markdown',
                'description': '知识库主文档'
            },
            {
                'path': 'index.json',
                'type': 'index',
                'description': '索引文件'
            },
            {
                'path': 'metadata.json',
                'type': 'metadata',
                'description': '元数据文件'
            }
        ]
    }
    
    index_path = base_dir / 'index.json'
    index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding='utf-8')


def create_metadata_json(base_dir):
    metadata = {
        'name': 'tilelangascend-knowledge-base',
        'description': 'TileLangAscend 编程知识库',
        'version': '1.0.0',
        'created': datetime.now().isoformat(),
        'updated': datetime.now().isoformat(),
        'author': '',
        'license': 'MIT',
        'keywords': ['tilelang', 'ascend', 'knowledge-base', 'api', 'templates'],
        'categories': [
            {'id': 'api-reference', 'count': 0},
            {'id': 'best-practices', 'count': 0},
            {'id': 'templates', 'count': 0},
            {'id': 'techniques', 'count': 0},
            {'id': 'examples', 'count': 0},
            {'id': 'faq', 'count': 0},
            {'id': 'plugins', 'count': 0}
        ],
        'stats': {
            'total_files': 0,
            'total_directories': 7
        }
    }
    
    metadata_path = base_dir / 'metadata.json'
    metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding='utf-8')


if __name__ == '__main__':
    create_directory_structure()
