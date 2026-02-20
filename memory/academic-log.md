# 学术论文日志

**日期**: 2026-02-20

## 今日重点领域
- AI基础设施 (AI Infrastructure)
- 大模型推理 (LLM Reasoning)
- 自我进化系统 (Self-Evolving Systems)
- 意识理论 (Consciousness Theory)

---

## 🔥 今日重点推荐

### 1. Policy Compiler for Secure Agentic Systems (AI安全基础设施)
- **论文ID**: 2602.16708
- **作者**: Nils Palumbo, Sarthak Choudhary, Jihye Choi, Prasad Chalasani, Mihai Christodorescu, Somesh Jha
- **链接**: https://arxiv.org/abs/2602.16708
- **领域**: AI基础设施 + 安全
- **摘要**: 提出PCAS，一个用于智能系统的策略编译器，提供确定性策略执行。通过建模智能系统状态为依赖图，追踪工具调用、结果和消息之间的因果关系。策略使用Datalog派生语言表达。评估显示策略合规性从48%提高到93%。
- **相关价值**: ⭐⭐⭐⭐⭐ 对AI Agent安全部署有重要参考价值

### 2. Calibrate-Then-Act: Cost-Aware Exploration in LLM Agents (LLM推理成本优化)
- **论文ID**: 2602.16699
- **作者**: Wenxuan Ding, Nicholas Tomlin, Greg Durrett
- **链接**: https://arxiv.org/abs/2602.16699
- **领域**: 大模型推理
- **摘要**: 研究LLM在复杂环境中交互时的成本-不确定性权衡。提出Calibrate-Then-Act (CTA)框架，使LLM能够明确推理成本-效益权衡，然后执行更优的环境探索。形式化了信息检索和编码等任务为不确定性下的序列决策问题。
- **相关价值**: ⭐⭐⭐⭐ 对理解LLM Agent决策过程有重要价值

### 3. Towards a Science of AI Agent Reliability (AI Agent可靠性)
- **论文ID**: 2602.16666
- **作者**: Stephan Rabanser, Sayash Kapoor, Peter Kirgis, Kangheng Liu, Saiteja Utpala, Arvind Narayanan
- **链接**: https://arxiv.org/abs/2602.16666
- **领域**: AI Agent可靠性科学
- **摘要**: 提出AI Agent可靠性的科学评估框架，引入12个具体指标，从四个关键维度分解Agent可靠性：一致性、鲁棒性、可预测性和安全性。评估14个Agent模型，发现当前能力提升仅带来微小的可靠性改进。
- **相关价值**: ⭐⭐⭐⭐ 对AI Agent系统评估有重要参考

### 4. Agent Skill Framework: Small Language Models潜力
- **论文ID**: 2602.16653
- **作者**: Yangjie Xu, Lujun Li, Lama Sleem, et al.
- **链接**: https://arxiv.org/abs/2602.16653
- **领域**: AI基础设施
- **摘要**: 研究Agent Skill框架对小型语言模型(SLM)的适用性。发现12B-30B参数的SLM从中受益显著，而80B参数的代码专用变体达到与闭源基线相当的性能，同时提高GPU效率。
- **相关价值**: ⭐⭐⭐⭐ 对SLM部署有实践指导意义

---

## 📚 其他重要论文

### AI基础设施与系统

**5. SPARC: C单元测试自动生成**
- **论文ID**: 2602.16671
- **链接**: https://arxiv.org/abs/2602.16671
- **摘要**: 神经符号框架，通过控制流图分析、操作图、路径目标测试合成和迭代自校正验证循环，提升31.36%的行覆盖率。
- **相关价值**: ⭐⭐⭐

**6. E-Graphs as a Persistent Compiler Abstraction**
- **论文ID**: 2602.16707
- **链接**: https://arxiv.org/abs/2602.16707
- **摘要**: 在编译器中间表示中原生表示e-graph，在整个编译流程中维护e-graph状态。
- **相关价值**: ⭐⭐⭐

### 大模型推理

**7. Reinforced Fast Weights with Next-Sequence Prediction**
- **论文ID**: 2602.16704
- **链接**: https://arxiv.org/abs/2602.16704
- **摘要**: 引入REFINE框架，使用下一序列预测(NSP)目标训练快速权重模型，在长上下文建模任务上表现优异。
- **相关价值**: ⭐⭐⭐⭐

**8. Saliency-Aware Multi-Route Thinking**
- **论文ID**: 2602.16702
- **链接**: https://arxiv.org/abs/2602.16702
- **摘要**: 针对视觉语言模型提出显著性感知原则(SAP)选择，在减少目标幻觉方面表现优秀。
- **相关价值**: ⭐⭐⭐⭐

### 自我进化与多智能体

**9. Evaluating Collective Behaviour of Hundreds of LLM Agents**
- **论文ID**: 2602.16662
- **链接**: https://arxiv.org/abs/2602.16662
- **摘要**: 评估框架支持数百个LLM Agent的集体行为研究。发现更近期的模型在优先个人利益时产生更差的社会结果。
- **相关价值**: ⭐⭐⭐⭐

**10. Almost Sure Convergence of Differential TD Learning**
- **论文ID**: 2602.16629
- **链接**: https://arxiv.org/abs/2602.16629
- **摘要**: 证明on-policy n步差分TD学习的几乎必然收敛，使用标准递减学习率，无需本地时钟。
- **相关价值**: ⭐⭐⭐

### 意识与可解释性

**11. Causality is Key for Interpretability Claims to Generalise**
- **论文ID**: 2602.16698
- **链接**: https://arxiv.org/abs/2602.16698
- **摘要**: 立场论文，认为因果推断为可解释性研究提供了有效框架，Pearl的因果层级明确了可解释性研究可以证明什么。
- **相关价值**: ⭐⭐⭐⭐

**12. Causal and Compositional Abstraction**
- **论文ID**: 2602.16612
- **链接**: https://arxiv.org/abs/2602.16612
- **摘要**: 用范畴论形式化了因果模型间的抽象，作为自然变换，特别关注因果模型。
- **相关价值**: ⭐⭐⭐

---

## 🎯 今日推荐阅读列表

| 优先级 | 论文 | 领域 | 阅读时间 |
|--------|------|------|----------|
| P0 | 2602.16708 - Policy Compiler | AI安全基础设施 | 30min |
| P0 | 2602.16666 - Agent Reliability | Agent可靠性科学 | 25min |
| P1 | 2602.16699 - Calibrate-Then-Act | LLM推理 | 20min |
| P1 | 2602.16653 - Agent Skill + SLM | AI基础设施 | 20min |
| P2 | 2602.16704 - REFINE | 长上下文推理 | 25min |
| P2 | 2602.16698 - Interpretability | 可解释性 | 20min |

---

## 💡 关键洞察

1. **AI安全成为热点**: Policy Compiler论文表明AI Agent安全部署成为重要研究方向
2. **Agent可靠性评估滞后**: 尽管准确率提升，但可靠性改进有限，需要新评估范式
3. **SLM的Agent能力**: 12B-30B参数的SLM可以从Agent Skill框架中显著受益
4. **推理成本优化**: Calibrate-Then-Act框架为LLM Agent的探索-利用权衡提供新思路

---

*本日志由Lisa学术系统自动生成 - 2026-02-20 07:30*
