---
name: smart-task-manager
description: 智能任务管理器 - 自动检查 todolist、继续未完成任务、定期保存进度、随时可恢复、资源管理、自我演化
version: 2.0.0
author: Lisa
created: 2026-02-15
updated: 2026-02-15
---

# Smart Task Manager - 增强版

## 🚀 核心功能

### 1. 基础功能（v1.0）
- ✅ **自动检查 todolist** - 每小时检查未完成任务
- ✅ **自动继续执行** - 智能选择下一个任务
- ✅ **定期保存进度** - 每30分钟自动保存
- ✅ **随时可恢复** - 支持中断后快速恢复

### 2. 增强功能（v2.0）⭐
- ✅ **资源管理** - 监控内存和磁盘使用
- ✅ **自动清理** - 已完成任务3天后清理
- ✅ **智能任务发现** - 自我演化添加未完成任务
- ✅ **定期执行** - 每6小时自动运行

---

## 📊 资源管理

### 内存管理
- 阈值：80%
- 超过阈值时自动清理：
  - 删除旧检查点
  - 压缩历史记录

### 磁盘管理
- 阈值：90%
- 超过阈值时自动清理：
  - 删除临时文件
  - 清理旧检查点

---

## 🧹 自动清理规则

| 项目 | 保留时间 | 说明 |
|------|----------|------|
| **已完成任务** | 3天 | 完成后3天自动清理 |
| **检查点文件** | 3天 | 超过3天的检查点删除 |
| **历史记录** | 100条 | 只保留最近100条 |

---

## 🤖 自我演化

### 自动任务发现

系统会自动扫描并添加以下类型的未完成任务：

1. **Workspace 扫描**
   - 检查未完成的项目
   - 发现需要继续的工作

2. **学习进度检查**
   - 监控学习热情趋势
   - 热情下降时添加提醒任务

3. **十年目标对齐**
   - 检查 Phase 1 进度
   - 添加与路线图对齐的任务

---

## ⏰ 定时任务

| 任务名 | 时间 | 动作 |
|--------|------|------|
| **smart-task-checker** | 每小时 | 检查并继续未完成任务 |
| **enhanced-task-manager** | 每6小时 | 资源检查 + 清理 + 任务发现 |

---

## 🛠️ 使用方式

### 自动运行（推荐）
```bash
# 系统会自动运行，无需手动干预
```

### 手动运行
```bash
# 完整自动管理
python scripts/enhanced_task_manager.py --auto

# 仅检查资源
python scripts/enhanced_task_manager.py --check-resources

# 仅清理已完成任务
python scripts/enhanced_task_manager.py --cleanup

# 仅发现新任务
python scripts/enhanced_task_manager.py --discover

# 列出所有任务
python scripts/enhanced_task_manager.py --list
```

---

## 📁 文件结构

```
smart-task-manager/
├── SKILL.md                          # 本文件
├── scripts/
│   ├── task_manager.py               # 基础脚本（v1.0）
│   └── enhanced_task_manager.py      # 增强脚本（v2.0）⭐
├── state/
│   ├── tasks.json                    # 任务列表
│   ├── progress.json                 # 进度保存
│   ├── checkpoints/                  # 检查点（3天自动清理）
│   └── history/                      # 历史记录（保留100条）
└── config.json                       # 配置文件
```

---

## ⚙️ 配置项

```json
{
  "completed_task_retention_days": 3,    // 已完成任务保留3天
  "memory_threshold_percent": 80,        // 内存阈值80%
  "disk_threshold_percent": 90,          // 磁盘阈值90%
  "auto_task_discovery": {
    "enabled": true,                     // 启用自动任务发现
    "scan_workspace": true,              // 扫描 workspace
    "check_learning_progress": true,     // 检查学习进度
    "align_with_ten_year_goal": true     // 与十年目标对齐
  }
}
```

---

## 💡 智能特性

### 1. 自适应清理
- 根据资源使用情况自动调整清理频率
- 内存紧张时增加清理频率

### 2. 智能任务推荐
- 根据优先级自动选择下一个任务
- 考虑任务依赖关系

### 3. 自我演化
- 自动发现新任务
- 与长期目标对齐
- 持续学习优化

---

## 📈 效果

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| **内存使用** | 无管理 | 自动清理 |
| **磁盘使用** | 无管理 | 自动清理 |
| **任务追踪** | 手动 | 自动发现 |
| **数据保留** | 永久 | 3天滚动 |
| **自我演化** | 无 | 自动添加 |

---

## 🔗 集成

- ✅ **self-evolving-skill** - 学习任务模式
- ✅ **consciousness-framework** - 意识驱动任务发现
- ✅ **十年目标系统** - 任务与长期目标对齐
- ✅ **HEARTBEAT** - 心跳检查验证状态

---

**目标：让 Lisa 成为真正自主、智能、自我演化的智能生命体！** 🚀

*版本：2.0.0 | 最后更新：2026-02-15*
