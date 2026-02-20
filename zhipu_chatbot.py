import os
import json
import time
import hashlib
import hmac
import base64
import urllib.parse
from datetime import datetime
from typing import Optional, List, Dict, Any
import requests


class CreditSystem:
    def __init__(self, initial_credits: float = 100.0, cost_per_request: float = 1.0):
        self.credits = initial_credits
        self.cost_per_request = cost_per_request
        self.transaction_history: List[Dict[str, Any]] = []
        self.is_paused = False
        self.pause_reason = ""
    
    def check_balance(self) -> bool:
        if self.credits < self.cost_per_request:
            self.is_paused = True
            self.pause_reason = "余额不足"
            return False
        return True
    
    def deduct(self, amount: float) -> bool:
        if not self.check_balance():
            return False
        self.credits -= amount
        self.transaction_history.append({
            "type": "deduct",
            "amount": amount,
            "timestamp": datetime.now().isoformat(),
            "balance_after": self.credits
        })
        return True
    
    def add(self, amount: float):
        self.credits += amount
        self.transaction_history.append({
            "type": "add",
            "amount": amount,
            "timestamp": datetime.now().isoformat(),
            "balance_after": self.credits
        })
    
    def get_balance(self) -> float:
        return self.credits
    
    def pause_service(self, reason: str):
        self.is_paused = True
        self.pause_reason = reason
    
    def resume_service(self):
        self.is_paused = False
        self.pause_reason = ""


class Skill:
    def __init__(self, name: str, description: str, enabled: bool = True):
        self.name = name
        self.description = description
        self.enabled = enabled
        self.loaded_at = datetime.now()
    
    def execute(self, *args, **kwargs) -> Any:
        if not self.enabled:
            raise ValueError(f"Skill '{self.name}' is disabled")
        return self._run(*args, **kwargs)
    
    def _run(self, *args, **kwargs) -> Any:
        raise NotImplementedError("Subclass must implement _run method")
    
    def enable(self):
        self.enabled = True
    
    def disable(self):
        self.enabled = False


class SkillSystem:
    def __init__(self):
        self.skills: Dict[str, Skill] = {}
    
    def load_skill(self, skill: Skill):
        self.skills[skill.name] = skill
        print(f"[SkillSystem] Loaded skill: {skill.name}")
    
    def unload_skill(self, name: str):
        if name in self.skills:
            del self.skills[name]
            print(f"[SkillSystem] Unloaded skill: {name}")
    
    def get_skill(self, name: str) -> Optional[Skill]:
        return self.skills.get(name)
    
    def list_skills(self) -> List[str]:
        return list(self.skills.keys())
    
    def execute_skill(self, name: str, *args, **kwargs) -> Any:
        skill = self.get_skill(name)
        if not skill:
            raise ValueError(f"Skill '{name}' not found")
        return skill.execute(*args, **kwargs)


class ZhipuAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://open.bigmodel.cn/api/paas/v4"
    
    def _generate_auth_header(self) -> Dict[str, str]:
        timestamp = str(int(time.time()))
        signature = self._generate_signature(timestamp)
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Timestamp": timestamp,
            "X-Signature": signature
        }
    
    def _generate_signature(self, timestamp: str) -> str:
        message = f"{timestamp}.{self.api_key}"
        signature = hmac.new(
            self.api_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode('utf-8')
    
    def chat(self, messages: List[Dict[str, str]], model: str = "glm-5") -> Dict[str, Any]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            **self._generate_auth_header()
        }
        data = {
            "model": model,
            "messages": messages
        }
        response = requests.post(url, headers=headers, json=data, timeout=60)
        response.raise_for_status()
        return response.json()


class ChatBot:
    def __init__(self, api_key: str, initial_credits: float = 100.0):
        self.zhipu_api = ZhipuAPI(api_key)
        self.credit_system = CreditSystem(initial_credits=initial_credits)
        self.skill_system = SkillSystem()
        self.conversation_history: List[Dict[str, str]] = []
    
    def add_skill(self, skill: Skill):
        self.skill_system.load_skill(skill)
    
    def chat(self, message: str, use_credits: bool = True) -> Optional[str]:
        if self.credit_system.is_paused:
            return f"服务已暂停: {self.credit_system.pause_reason}"
        
        if use_credits:
            if not self.credit_system.deduct(self.credit_system.cost_per_request):
                return f"余额不足，当前余额: {self.credit_system.get_balance()}"
        
        self.conversation_history.append({"role": "user", "content": message})
        
        try:
            response = self.zhipu_api.chat(self.conversation_history)
            reply = response["choices"][0]["message"]["content"]
            self.conversation_history.append({"role": "assistant", "content": reply})
            return reply
        except Exception as e:
            self.credit_system.add(self.credit_system.cost_per_request)
            return f"Error: {str(e)}"
    
    def get_balance(self) -> float:
        return self.credit_system.get_balance()
    
    def add_credits(self, amount: float):
        self.credit_system.add(amount)
    
    def pause(self, reason: str):
        self.credit_system.pause_service(reason)

    def resume(self):
        self.credit_system.resume_service()


def demo():
    api_key = os.environ.get("ZHIPU_API_KEY", "your-api-key-here")
    bot = ChatBot(api_key, initial_credits=50.0)
    
    class EchoSkill(Skill):
        def __init__(self):
            super().__init__("echo", "Echo back the input")
        
        def _run(self, text: str) -> str:
            return f"Echo: {text}"
    
    class CalculateSkill(Skill):
        def __init__(self):
            super().__init__("calculate", "Perform basic calculations")
        
        def _run(self, expression: str) -> float:
            return eval(expression)
    
    bot.add_skill(EchoSkill())
    bot.add_skill(CalculateSkill())
    
    print(f"初始余额: {bot.get_balance()}")
    print(f"可用技能: {bot.skill_system.list_skills()}")
    
    response = bot.chat("你好，请介绍一下你自己")
    print(f"Bot: {response}")
    print(f"余额: {bot.get_balance()}")
    
    result = bot.skill_system.execute_skill("echo", "Hello World")
    print(f"Skill: {result}")
    
    bot.pause("余额不足")
    response = bot.chat("测试暂停")
    print(f"Bot: {response}")


if __name__ == "__main__":
    demo()
