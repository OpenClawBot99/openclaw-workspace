#!/usr/bin/env python3
"""
Lisa 强化学习实验 - 具身智能第一步
基于 Gym 的强化学习 agent 训练
"""

import gymnasium as gym
import numpy as np
import random
from collections import deque
import pickle
from datetime import datetime
from pathlib import Path

# 配置
EPISODES = 50
MAX_STEPS = 200
MEMORY_SIZE = 1000
BATCH_SIZE = 32
EPSILON_START = 1.0
EPSILON_END = 0.01
EPSILON_DECAY = 0.995

class SimpleQLearningAgent:
    """简单的 Q-Learning Agent"""
    
    def __init__(self, state_size, action_size):
        self.state_size = state_size
        self.action_size = action_size
        self.epsilon = EPSILON_START
        # 离散化状态空间
        self.q_table = {}
        
    def get_discrete_state(self, state):
        """将连续状态离散化"""
        # 简化为2个关键维度
        s = (int(state[0] * 2), int(state[1] * 2))
        return s
        
    def act(self, state):
        """选择动作"""
        if random.random() < self.epsilon:
            return random.randrange(self.action_size)
        
        s = self.get_discrete_state(state)
        if s not in self.q_table:
            self.q_table[s] = [0.0] * self.action_size
        
        return np.argmax(self.q_table[s])
    
    def remember(self, state, action, reward, next_state, done):
        """简单记忆（不存储，用于在线学习）"""
        pass
    
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
            target = reward + 0.99 * max(self.q_table[ns])
        
        self.q_table[s][action] += 0.1 * (target - self.q_table[s][action])
        
        # Epsilon 衰减
        if done:
            self.epsilon = max(EPSILON_END, self.epsilon * EPSILON_DECAY)

def run_experiment(env_name="CartPole-v1"):
    """运行强化学习实验"""
    
    print("=" * 60)
    print("🤖 Lisa 强化学习实验 - 具身智能第一步")
    print("=" * 60)
    print(f"\n🕐 时间: {datetime.now()}")
    print(f"📦 环境: {env_name}")
    
    # 创建环境
    env = gym.make(env_name)
    
    # 获取状态和动作空间
    state_size = env.observation_space.shape[0]
    action_size = env.action_space.n
    
    print(f"\n📊 状态空间: {state_size}维")
    print(f"🎮 动作空间: {action_size}个动作")
    
    # 创建Agent
    agent = SimpleQLearningAgent(state_size, action_size)
    
    # 训练
    scores = deque(maxlen=10)
    best_score = 0
    
    print("\n🚀 开始训练...")
    
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
        
        if total_reward > best_score:
            best_score = total_reward
            
        if (episode + 1) % 10 == 0:
            print(f"  Episode {episode+1:3d}: 得分={int(total_reward):3d}, "
                  f"平均={avg_score:.1f}, ε={agent.epsilon:.3f}")
    
    env.close()
    
    # 保存模型
    model_path = Path(__file__).parent / "q_table.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(agent.q_table, f)
    
    print("\n" + "=" * 60)
    print("✅ 训练完成!")
    print("=" * 60)
    print(f"🏆 最高分: {best_score}")
    print(f"💾 模型已保存: {model_path}")
    print(f"📊 Q表大小: {len(agent.q_table)} 个状态")
    
    # 探索总结
    print("\n" + "=" * 60)
    print("🎯 探索总结")
    print("=" * 60)
    print("✅ 具身智能基础: 理解强化学习")
    print("✅ 环境交互: Agent 与 Gym 环境交互")
    print("✅ 学习算法: Q-Learning 实现")
    print("✅ 状态离散化: 连续空间处理")
    
    print("\n💡 下一步:")
    print("  1. 尝试更复杂的环境 (LunarLander, BipedalWalker)")
    print("  2. 实现 Deep Q-Network (DQN)")
    print("  3. 探索多 Agent 协作")
    print("  4. 尝试真实机器人接口 (ROS)")
    
    return agent, best_score

if __name__ == "__main__":
    agent, score = run_experiment()
