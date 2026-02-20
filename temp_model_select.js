const fs = require('fs');
const path = require('path');

const AVAILABLE_MODELS = [
    'zai/glm-5',
    'zai/glm-4.7',
    'minimax-portal/MiniMax-M2.5',
    'minimax-portal/MiniMax-M2.1'
];

const workspaceDir = 'C:\\Users\\Lenovo\\.openclaw\\workspace';
const STATE_FILE = path.join(workspaceDir, 'skills/smart-model-router/state/model_metrics.json');
const METADATA_FILE = path.join(workspaceDir, 'skills/smart-model-router/state/metadata.json');

let state = {};
let metadata = { total_uses: 0 };

try {
    if (fs.existsSync(STATE_FILE)) {
        state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
    }
    if (fs.existsSync(METADATA_FILE)) {
        metadata = JSON.parse(fs.readFileSync(METADATA_FILE, 'utf-8'));
    }
} catch (e) {
    console.error('Error loading state:', e);
}

console.log('='.repeat(60));
console.log('当前模型使用情况：');
let totalUses = 0;
for (const model of AVAILABLE_MODELS) {
    const metrics = state[model] || {};
    const uses = metrics.uses || 0;
    const score = metrics.score || 0;
    console.log(`  ${model}: 使用 ${uses} 次, 评分 ${score.toFixed(2)}`);
    totalUses += uses;
}
console.log(`  总使用次数: ${metadata.total_uses || totalUses}`);
console.log('='.repeat(60));

// ε-Greedy 策略
const EPSILON_START = 0.5;
const EPSILON_MIN = 0.1;
const EPSILON_DECAY = 0.001;
const total_uses = metadata.total_uses || 0;
const epsilon = Math.max(EPSILON_MIN, EPSILON_START - total_uses * EPSILON_DECAY);

console.log(`[ε-Greedy] 探索模式 (ε=${epsilon.toFixed(3)}): 随机选择`);

const randomModel = AVAILABLE_MODELS[Math.floor(Math.random() * AVAILABLE_MODELS.length)];
console.log(`\n✅ 推荐使用: ${randomModel}`);
console.log(`\n命令: /model ${randomModel}`);
