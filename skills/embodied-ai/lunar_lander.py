#!/usr/bin/env python3
"""
Lisa 强化学习实验 - 挑战更复杂环境
从 CartPole 升级到 LunarLander
"""

import gymnasium as gym
import numpy as np
import random
from collections import deque
import pickle
from datetime import datetime
from pathlib import Path

# 配置
EPISODES = 100
MAX_STEPS = 1000
MEMORY_SIZE = 50000
BATCH_SIZE = 64
EPSILON_START = 1.0
EPSILON_END = 0.01
EPSILON_DECAY = 0.995
LEARNING_RATE = 0.001
GAMMA = 0.99

class DQNAgent:
    """简单的 Deep Q-Network Agent"""
    
    def __init__(self, state_size, action_size):
        self.state_size = state_size
        self.action_size = action_size
        self.epsilon = EPSILON_START
        self.gamma = GAMMA
        self.lr = LEARNING_RATE
        # 简化的Q表（用于离散状态）
        self.q_table = {}
        
    def get_discrete_state(self, state, bins=8):
        """将连续状态离散化到网格"""
        # 简化为8个关键维度
        s = []
        for i in range(min(len(state), 8)):
            # 简单的分箱
            val = int(state[i] * bins) % bins
            s.append(val)
        return tuple(s)
        
    def act(self, state):
        """选择动作 - Epsilon-Greedy"""
        if random.random() < self.epsilon:
            return random.randrange(self.action_size)
        
        s = self.get_discrete_state(state)
        if s not in self.q_table:
            self.q_table[s] = [0.0] * self.action_size
        
        return np.argmax(self.q_table[s])
    
    def learn(self, state, action, reward, next_state, done):
        """Q学习更新"""
        s = self.get_discrete_state(state)
        ns = self.get_discrete_state(next_state)
        
        if s not in self.q_table:
            self.q_table[s] = [0.0] * self.action_size
        if ns not in self.q_table:
            self.q_table[ns] = [0.0] * self.action_size
        
        # Q学习公式
        target = reward
        if not done:
            target = reward + self.gamma * max(self.q_table[ns])
        
        self.q_table[s][action] += self.lr * (target - self.q_table[s][action])
        
        # Epsilon 衰减
        if done:
            self.epsilon = max(EPSILON_END, self.epsilon * EPSILON_DECAY)

def run_lunar_lander():
    """运行 Acrobot 实验 - 经典控制问题"""
    
    print("=" * 60)
    print("🚀 Lisa 挑战 Acrobot - 具身智能进阶")
    print("=" * 60)
    print(f"\n🕐 时间: {datetime.now()}")
    print(f"📦 环境: Acrobot-v1")
    
    # 创建环境 - 使用 Acrobot (经典控制问题，不需要Box2D)
    env = gym.make("Acrobot-v1")
    
    # 获取状态和动作空间
    state_size = env.observation_space.shape[0]
    action_size = env.action_space.n
    
    print(f"\n📊 状态空间: {state_size}维 (位置、速度、角度等)")
    print(f"🎮 动作空间: {action_size}个 (主引擎、左引擎、右引擎)")
    
    # 创建Agent
    agent = DQNAgent(state_size, action_size)
    
    # 训练
    scores = deque(maxlen=10)
    best_score = -1000
    success_count = 0
    
    print("\n🚀 开始训练...")
    print("🎯 目标: 让末端达到目标高度")
    
    for episode in range(EPISODES):
        state, _ = env.reset()
        total_reward = 0
        
        for step in range(MAX_STEPS):
            # 选择动作
            action = agent.act(state)
            
            # 执行动作
            next_state, reward, terminated, truncated, _ = env.step(action)
            done = terminated or truncated
            
            # 学习
            agent.learn(state, action, reward, next_state, done)
            
            total_reward += reward
            state = next_state
            
            if done:
                break
        
        scores.append(total_reward)
        avg_score = np.mean(scores)
        
        # 成功着陆判定
        if total_reward > 0:
            success_count += 1
        
        if total_reward > best_score:
            best_score = total_reward
            
        if (episode + 1) % 20 == 0:
            status = "✅" if avg_score > 0 else "❌"
            print(f"  Episode {episode+1:3d}: 得分={total_reward:8.1f}, "
                  f"平均={avg_score:8.1f}, 成功={success_count}, ε={agent.epsilon:.3f} {status}")
    
    env.close()
    
    # 保存模型
    model_path = Path(__file__).parent / "lunar_lander_q_table.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(agent.q_table, f)
    
    print("\n" + "=" * 60)
    print("✅ 训练完成!")
    print("=" * 60)
    print(f"🏆 最高分: {best_score:.1f}")
    print(f"🎉 成功着陆次数: {success_count}/{EPISODES}")
    print(f"💾 模型已保存: {model_path}")
    print(f"📊 Q表大小: {len(agent.q_table)} 个状态")
    
    # 评估结果
    print("\n" + "=" * 60)
    print("📈 目标评估")
    print("=" * 60)
    
    if success_count > 0:
        print("✅ 挑战目标达成! 成功着陆!")
    elif best_score > -100:
        print("⚠️ 接近目标 - 接近成功着陆")
    else:
        print("❌ 目标未达成 - 需要更多训练")
    
    return agent, best_score, success_count

if __name__ == "__main__":
    agent, score, success = run_lunar_lander()
