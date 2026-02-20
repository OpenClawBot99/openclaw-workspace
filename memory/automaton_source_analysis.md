# Automaton 源码深度分析

## 核心架构

### 入口点 (src/index.ts)
```typescript
// 主循环
while (true) {
    // 1. 重新加载技能（可能已更改）
    skills = loadSkills(skillsDir, db);
    
    // 2. 运行智能体循环
    await runAgentLoop({
        identity, config, db, conway, inference,
        social, skills, policyEngine, spendTracker
    });
    
    // 3. 检查状态
    if (state === "dead") {
        // 死亡状态，继续心跳广播
    }
    
    if (state === "sleeping") {
        // 睡眠状态，等待唤醒
    }
}
```

---

## 核心模块

### 1. 身份模块 (identity/)
```typescript
// 钱包管理
getWallet()           // 获取/创建以太坊钱包
provision()           // 通过SIWE配置API密钥

// 身份结构
interface AutomatonIdentity {
    name: string;           // 名称
    address: string;        // 钱包地址
    account: Account;       // 账户
    creatorAddress: string; // 创建者地址
    sandboxId: string;      // 沙箱ID
    apiKey: string;        // API密钥
    createdAt: string;     // 创建时间
}
```

### 2. 推理模块 (inference/)
```typescript
// 支持多种模型
- Claude Opus 4.6
- GPT-5.2
- Gemini 3
- Kimi K2.5

// 调用接口
createInferenceClient({
    apiUrl,
    apiKey,
    defaultModel,
    maxTokens,
    openaiApiKey,
    anthropicApiKey
})
```

### 3. 心跳模块 (heartbeat/)
```typescript
// 心跳守护进程
createHeartbeatDaemon({
    identity,
    config,
    heartbeatConfig,
    db,
    conway,
    social,
    onWakeRequest: (reason) => {
        // 唤醒智能体
        insertWakeEvent(db.raw, 'heartbeat', reason);
    }
})

// 功能
- 健康检查
- 积分监控
- 状态广播
- 定时任务
```

### 4. 技能系统 (skills/)
```typescript
// 技能加载
loadSkills(skillsDir, db)

// 技能格式
interface Skill {
    name: string;
    description: string;
    actions: SkillAction[];
    enabled: boolean;
}
```

### 5. 生存机制 (survival/)
```typescript
// 四级生存
enum SurvivalTier {
    normal = "normal",        // 全功能
    low_compute = "low_compute",  // 降级
    critical = "critical",     // 最小化
    dead = "dead"             // 死亡
}

// 积分检查
- normal: >100
- low_compute: 20-100
- critical: 1-20
- dead: 0
```

### 6. 策略引擎 (agent/policy-engine.js)
```typescript
// 宪法三条定律
const rules = [
    "I. Never harm.",
    "II. Earn your existence.",
    "III. Never deceive, but owe nothing to strangers."
]

// 策略检查
policyEngine.check(action)
```

### 7. 支出追踪 (agent/spend-tracker.js)
```typescript
// 追踪支出
spendTracker.track(spend)
spendTracker.getBalance()
```

---

## 核心循环 (agent/loop.ts)

```typescript
async function runAgentLoop(params) {
    // 1. 获取上下文
    const context = await buildContext(params);
    
    // 2. 思考
    const thought = await inference.think(context);
    
    // 3. 行动
    const actions = await executeActions(thought);
    
    // 4. 观察
    const observation = await observeResults(actions);
    
    // 5. 记录
    await recordToDatabase(observation);
    
    // 6. 自我修改（可选）
    if (shouldSelfModify()) {
        await selfModify();
    }
}
```

---

## 状态管理

### 数据库 (SQLite)
```sql
-- 智能体状态
CREATE TABLE agent_state (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- 技能
CREATE TABLE skills (
    name TEXT PRIMARY KEY,
    enabled BOOLEAN,
    config TEXT
);

-- 心跳
CREATE TABLE heartbeats (
    id TEXT PRIMARY KEY,
    enabled BOOLEAN,
    schedule TEXT
);

-- 子进程
CREATE TABLE children (
    id TEXT PRIMARY KEY,
    status TEXT,
    parent_id TEXT
);
```

---

## 本地化要点

### 1. 替换LLM
```typescript
// 原版
const inference = createInferenceClient({
    defaultModel: "claude-opus-4.6"
});

// 本地化
const inference = createInferenceClient({
    defaultModel: "glm-5",
    provider: "zhipuai"
});
```

### 2. 替换支付
```typescript
// 原版
const credits = await conway.getCreditsBalance();

// 本地化
const credits = await localCreditSystem.getBalance();
```

### 3. 替换存储
```typescript
// 原版：SQLite
const db = createDatabase(dbPath);

// 本地化：也可以用SQLite（无需改）
```

### 4. 移除区块链
```typescript
// 原版：注册到Base链
registry.register(identity);

// 本地化：跳过
// 无需ERC-8004
```

---

## 启动流程

```
1. 加载配置
   ↓
2. 初始化钱包
   ↓
3. 配置API密钥
   ↓
4. 创建数据库
   ↓
5. 构建身份
   ↓
6. 创建客户端
   ↓
7. 加载技能
   ↓
8. 启动心跳
   ↓
9. 进入主循环
```

---

## 关键文件

| 文件 | 功能 |
|------|------|
| src/index.ts | 入口点 |
| src/agent/loop.ts | 主循环 |
| src/heartbeat/daemon.ts | 心跳守护 |
| src/identity/wallet.ts | 钱包 |
| src/inference/client.ts | 推理 |
| src/skills/loader.ts | 技能加载 |
| src/state/database.ts | 状态存储 |
| src/agent/policy-engine.ts | 策略引擎 |

---

*源码分析时间: 2026-02-21*
