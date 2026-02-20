---
name: opencode-runner
description: OpenCode任务执行器 - 自动加载模型列表、智能选择、错误处理。用于调用OpenCode CLI执行编程任务，自动排除400错误模型。
---

# OpenCode Runner - 智能任务执行器

## 简介

OpenCode Runner 是一个智能任务执行器，用于：
1. **自动加载模型列表** - 动态获取OpenCode可用模型
2. **智能模型选择** - 根据性能和可用性选择最佳模型
3. **错误处理** - 自动排除返回400错误的模型
4. **任务执行** - 运行代码生成任务

---

## 核心功能

### 1. 自动加载模型列表

```python
#!/usr/bin/env python3
"""
OpenCode模型管理器
自动加载模型列表，排除问题模型
"""

import json
import subprocess
import time
from pathlib import Path

class OpenCodeModelManager:
    def __init__(self, state_file="models_state.json"):
        self.state_file = Path(__file__).parent / state_file
        self.state = self.load_state()
        
    def load_state(self):
        """加载状态文件"""
        if self.state_file.exists():
            with open(self.state_file) as f:
                return json.load(f)
        return {
            "models": [],
            "excluded_models": {},  # 排除的模型及原因
            "last_update": 0,
            "cooldown_models": {}   # 冷却期模型
        }
    
    def save_state(self):
        """保存状态"""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def get_available_models(self):
        """获取可用模型列表"""
        try:
            result = subprocess.run(
                ["opencode", "models"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                models = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        models.append(line)
                
                self.state["models"] = models
                self.state["last_update"] = time.time()
                self.save_state()
                return models
        except Exception as e:
            print(f"[!] 获取模型列表失败: {e}")
        
        return self.state.get("models", [])
    
    def is_model_available(self, model_name):
        """检查模型是否可用"""
        # 检查是否在排除列表
        if model_name in self.state.get("excluded_models", {}):
            exclude_info = self.state["excluded_models"][model_name]
            print(f"[!] 模型 {model_name} 已被排除: {exclude_info['reason']}")
            return False
        
        # 检查是否在冷却期
        if model_name in self.state.get("cooldown_models", {}):
            cooldown = self.state["cooldown_models"][model_name]
            if time.time() < cooldown["until"]:
                remaining = int(cooldown["until"] - time.time())
                print(f"[!] 模型 {model_name} 冷却期中，剩余 {remaining} 秒")
                return False
            else:
                # 冷却期结束，移除
                del self.state["cooldown_models"][model_name]
                print(f"[+] 模型 {model_name} 冷却期结束")
        
        return True
    
    def exclude_model(self, model_name, reason, duration=12*3600):
        """
        排除模型
        
        参数:
            model_name: 模型名称
            reason: 排除原因
            duration: 冷却时间（秒），默认12小时
        """
        if model_name not in self.state["excluded_models"]:
            self.state["excluded_models"][model_name] = {
                "reason": reason,
                "since": time.time(),
                "until": time.time() + duration
            }
            self.save_state()
            print(f"[!] 已排除模型: {model_name}")
            print(f"    原因: {reason}")
            print(f"    时长: {duration/3600}小时")
    
    def add_cooldown(self, model_name, duration=3600):
        """
        添加冷却期
        
        参数:
            model_name: 模型名称
            duration: 冷却时间（秒），默认1小时
        """
        self.state["cooldown_models"][model_name] = {
            "until": time.time() + duration,
            "reason": "连续错误"
        }
        self.save_state()
        print(f"[+] 模型 {model_name} 进入冷却期 {duration}秒")
    
    def get_best_model(self, preferred=None):
        """获取最佳可用模型"""
        available_models = self.get_available_models()
        
        # 过滤可用模型
        valid_models = [m for m in available_models if self.is_model_available(m)]
        
        if not valid_models:
            print("[!] 没有可用的模型")
            return None
        
        # 优先选择免费模型
        free_models = [m for m in valid_models if 'free' in m.lower()]
        if free_models and preferred != "paid":
            return free_models[0]
        
        # 返回第一个可用模型
        return valid_models[0]
    
    def handle_error(self, model_name, error_info):
        """
        处理模型错误
        
        参数:
            model_name: 模型名称
            error_info: 错误信息字典 {"code": 400, "message": "..."}
        """
        error_code = error_info.get("code")
        error_message = error_info.get("message", "")
        
        # 400错误 - 立即排除
        if error_code == 400:
            if "location" in error_message.lower() or "not supported" in error_message.lower():
                self.exclude_model(
                    model_name, 
                    f"400错误: {error_message}",
                    duration=12*3600  # 12小时
                )
                return
        
        # 其他错误 - 增加冷却期计数
        if model_name not in self.state.get("error_counts", {}):
            self.state["error_counts"][model_name] = 0
        
        self.state["error_counts"][model_name] += 1
        
        # 连续3次错误，进入冷却期
        if self.state["error_counts"][model_name] >= 3:
            self.add_cooldown(model_name, duration=3600)
            self.state["error_counts"][model_name] = 0
            print(f"[!] 模型 {model_name} 连续3次错误，进入冷却期")
        
        self.save_state()

# 全局实例
model_manager = OpenCodeModelManager()
```

### 2. 任务执行器

```python
#!/usr/bin/env python3
"""
OpenCode任务执行器
自动执行代码生成任务
"""

import subprocess
import sys
from pathlib import Path

class OpenCodeRunner:
    def __init__(self, model_manager):
        self.model_manager = model_manager
        
    def run_task(self, task_description, model=None, timeout=120):
        """
        执行任务
        
        参数:
            task_description: 任务描述
            model: 指定模型（可选）
            timeout: 超时时间（秒）
        
        返回:
            (success: bool, output: str, error: str)
        """
        # 获取模型
        if not model:
            model = self.model_manager.get_best_model()
            if not model:
                return False, "", "没有可用模型"
        
        print(f"[*] 使用模型: {model}")
        print(f"[*] 任务: {task_description}")
        
        # 构建命令
        cmd = [
            "opencode", "run",
            task_description,
            "--model", model,
            "--timeout", str(timeout)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(Path.home())
            )
            
            if result.returncode == 0:
                return True, result.stdout, ""
            else:
                # 检查是否是400错误
                error_output = result.stderr
                if "400" in error_output and "location" in error_output.lower():
                    self.model_manager.handle_error(model, {
                        "code": 400,
                        "message": error_output
                    })
                
                return False, result.stdout, result.stderr
                
        except subprocess.TimeoutExpired:
            return False, "", f"任务超时 ({timeout}秒)"
        except Exception as e:
            return False, "", str(e)

# 使用示例
if __name__ == "__main__":
    from opencode_models import model_manager
    
    runner = OpenCodeRunner(model_manager)
    
    # 执行任务
    success, output, error = runner.run_task("用Python写一个快速排序算法")
    
    if success:
        print(f"[+] 任务成功!")
        print(output)
    else:
        print(f"[!] 任务失败: {error}")
```

---

## 使用流程

### 1. 初始化

```python
from opencode_models import model_manager

# 获取可用模型
models = model_manager.get_available_models()
print(f"可用模型: {models}")

# 查看排除列表
print(f"已排除: {model_manager.state['excluded_models']}")
```

### 2. 执行任务

```python
from opencode_task import OpenCodeRunner

runner = OpenCodeRunner(model_manager)

# 自动选择最佳模型执行
success, output, error = runner.run_task("写一个Python计算器")

if success:
    print(output)
```

### 3. 错误处理

```python
# 手动报告错误
model_manager.handle_error("model-name", {
    "code": 400,
    "message": "User location is not supported for the API use."
})
```

---

## 配置选项

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `COOLDOWN_DURATION` | 3600秒 | 冷却期时长 |
| `ERROR_THRESHOLD` | 3次 | 连续错误次数阈值 |
| `EXCLUDE_400` | True | 是否排除400错误 |
| `AUTO_REFRESH` | True | 是否自动刷新模型列表 |

---

## 注意事项

1. **400错误立即排除** - "User location is not supported" 等错误会被排除12小时
2. **连续3次错误** - 任何错误连续出现3次会进入冷却期
3. **手动恢复** - 可以删除状态文件来恢复所有模型
4. **定期刷新** - 建议每次启动时刷新模型列表

---

*目标: 自动化OpenCode任务执行，智能模型选择*
