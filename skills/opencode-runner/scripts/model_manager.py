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
        self.state_file = Path(__file__).parent / "state" / state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
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
            "cooldown_models": {},   # 冷却期模型
            "error_counts": {}       # 错误计数
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
                    if line and not line.startswith('#') and not line.startswith('=='):
                        # 清理模型名称
                        model = line.split()[0] if line.split() else line
                        models.append(model)
                
                self.state["models"] = models
                self.state["last_update"] = time.time()
                self.save_state()
                print(f"[+] 获取到 {len(models)} 个模型")
                return models
            else:
                print(f"[!] 获取模型失败: {result.stderr}")
        except Exception as e:
            print(f"[!] 获取模型列表失败: {e}")
        
        return self.state.get("models", [])
    
    def is_model_available(self, model_name):
        """检查模型是否可用"""
        # 检查是否在排除列表
        excluded = self.state.get("excluded_models", {})
        if model_name in excluded:
            exclude_info = excluded[model_name]
            # 检查是否过期
            if time.time() < exclude_info.get("until", 0):
                print(f"[!] 模型 {model_name} 已被排除: {exclude_info['reason']}")
                return False
            else:
                # 过期，移除
                del self.state["excluded_models"][model_name]
                self.save_state()
        
        # 检查是否在冷却期
        cooldown = self.state.get("cooldown_models", {})
        if model_name in cooldown:
            if time.time() < cooldown[model_name]["until"]:
                remaining = int(cooldown[model_name]["until"] - time.time())
                print(f"[!] 模型 {model_name} 冷却期中，剩余 {remaining} 秒")
                return False
            else:
                # 冷却期结束，移除
                del self.state["cooldown_models"][model_name]
                print(f"[+] 模型 {model_name} 冷却期结束")
                self.save_state()
        
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
    
    def get_best_model(self, preferred="free"):
        """获取最佳可用模型"""
        available_models = self.get_available_models()
        
        # 过滤可用模型
        valid_models = [m for m in available_models if self.is_model_available(m)]
        
        if not valid_models:
            print("[!] 没有可用的模型")
            return None
        
        # 优先选择免费模型
        if preferred == "free":
            free_models = [m for m in valid_models if 'free' in m.lower()]
            if free_models:
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
        
        # 400错误 - 立即排除 (12小时)
        if error_code == 400:
            if "location" in error_message.lower() or "not supported" in error_message.lower():
                self.exclude_model(
                    model_name, 
                    f"400错误: {error_message}",
                    duration=12*3600  # 12小时
                )
                return True  # 已处理
        
        # 其他错误 - 增加冷却期计数
        if "error_counts" not in self.state:
            self.state["error_counts"] = {}
        
        if model_name not in self.state["error_counts"]:
            self.state["error_counts"][model_name] = 0
        
        self.state["error_counts"][model_name] += 1
        
        # 连续3次错误，进入冷却期
        if self.state["error_counts"][model_name] >= 3:
            self.add_cooldown(model_name, duration=3600)
            self.state["error_counts"][model_name] = 0
            print(f"[!] 模型 {model_name} 连续{3}次错误，进入冷却期")
        
        self.save_state()
        return False  # 需要记录错误
    
    def show_status(self):
        """显示状态"""
        print("\n" + "="*50)
        print("OpenCode 模型状态")
        print("="*50)
        
        available = self.get_available_models()
        print(f"\n可用模型数: {len(available)}")
        
        excluded = self.state.get("excluded_models", {})
        print(f"\n已排除模型 ({len(excluded)}):")
        for model, info in excluded.items():
            remaining = int(info.get("until", 0) - time.time())
            if remaining > 0:
                print(f"  - {model}: {info['reason']} (剩余 {remaining//3600}小时)")
        
        cooldown = self.state.get("cooldown_models", {})
        print(f"\n冷却期模型 ({len(cooldown)}):")
        for model, info in cooldown.items():
            remaining = int(info.get("until", 0) - time.time())
            if remaining > 0:
                print(f"  - {model}: 剩余 {remaining}秒")
        
        print("="*50)


def main():
    import sys
    
    manager = OpenCodeModelManager()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "refresh":
            # 刷新模型列表
            models = manager.get_available_models()
            print(f"获取到 {len(models)} 个模型")
            
        elif command == "status":
            # 显示状态
            manager.show_status()
            
        elif command == "exclude":
            # 排除模型
            if len(sys.argv) > 3:
                model = sys.argv[2]
                reason = sys.argv[3]
                manager.exclude_model(model, reason)
            else:
                print("用法: exclude <模型名> <原因>")
        
        elif command == "test":
            # 测试模型
            model = sys.argv[2] if len(sys.argv) > 2 else None
            if not model:
                model = manager.get_best_model()
            
            print(f"[*] 测试模型: {model}")
            result = subprocess.run(
                ["opencode", "run", "说hello", "--model", model],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                print("[+] 成功!")
            else:
                error = result.stderr
                print(f"[!] 失败: {error[:200]}")
                
                # 检查400错误
                if "400" in error:
                    manager.handle_error(model, {"code": 400, "message": error})
        
        else:
            print("未知命令")
    else:
        # 默认显示状态
        manager.show_status()


if __name__ == "__main__":
    main()
