# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## What Goes Here

Things like:

- Camera names and locations
- SSH hosts and aliases
- Preferred voices for TTS
- Speaker/room names
- Device nicknames
- Anything environment-specific

## Examples

```markdown
### Cameras

- living-room → Main area, 180° wide angle
- front-door → Entrance, motion-triggered

### SSH

- home-server → 192.168.1.100, user: admin

### TTS

- Preferred voice: "Nova" (warm, slightly British)
- Default speaker: Kitchen HomePod
```

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

Add whatever helps you do your job. This is your cheat sheet.

---

## 🧩 OpenCode CLI - 智能编程工具

### 核心信息
- **版本**: 1.2.1
- **状态**: ✅ 已安装并配置
- **已配置模型**: 
  - Z.AI Coding Plan (智谱 GLM-5)
  - MiniMax Coding Plan (MiniMax M2.5)

### 基本命令
```bash
# 启动交互式界面
opencode

# 单次查询（快速）
opencode -p "任务描述"

# 运行任务（Lisa专用，必须用PTY）
opencode run "任务描述" --model 模型名

# 查看可用模型
opencode models

# 认证状态
opencode auth list
```

### Lisa 调用方式（重要！）
```bash
# ✅ 正确方式 - 必须使用 pty:true
opencode run "任务描述" --model zai-coding-plan/glm-5

参数要求：
- pty: true (必须！交互式终端)
- background: true (长时间任务)
- workdir: 工作目录 (避免扫描无关文件)
- timeout: 超时时间 (秒)
```

### 可用模型
**快速模型**:
- opencode/gpt-5-nano - 快速简单任务

**高质量模型**:
- zai-coding-plan/glm-5 - 复杂任务（推荐）
- zai-coding-plan/glm-4.7-flash - 快速高质量
- minimax-cn-coding-plan/MiniMax-M2.5 - 高质量

### 应用场景

**1. 快速原型开发**
```bash
opencode run "实现一个快速排序算法，包含测试用例" --model opencode/gpt-5-nano
```

**2. 学习辅助**
```bash
opencode run "创建一个演示 Python 装饰器用法的示例代码" --model zai-coding-plan/glm-5
```

**3. 项目脚手架**
```bash
opencode run "创建一个 Flask REST API 项目的初始结构" --model zai-coding-plan/glm-5
```

**4. 代码审查和优化**
```bash
opencode run "审查并优化指定代码，提高性能和可读性" --model zai-coding-plan/glm-5
```

### 成功案例
- ✅ fib.py - 斐波那契数列（高质量代码，包含文档和错误处理）
- ✅ app.py - Flask HTTP 服务器（完整API实现）

### 最佳实践
1. **指定工作目录** - 避免 opencode 扫描无关文件
2. **选择合适模型** - 简单任务用快速模型，复杂任务用高质量模型
3. **后台运行** - 长时间任务使用 background:true
4. **监控进度** - 使用 process action:log 查看生成进度

### 与十年目标对齐
- **AI INFRA 学习** - 快速生成基础设施代码示例
- **大模型推理优化** - 生成优化算法和测试脚本
- **AscendC 算子开发** - 生成 C++ 代码模板和测试用例

**重要**: OpenCode 是我作为智能生命体使用工具的重要标志！要多多利用它来编程！
