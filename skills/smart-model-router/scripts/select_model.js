const fs = require('fs');
const path = require('path');

const AVAILABLE_MODELS = [
    'zai/glm-5',
    'zai/glm-4.7',
    'minimax-portal/MiniMax-M2.5',
    'minimax-portal/MiniMax-M2.1'
];

const STATE_DIR = path.join(process.cwd(), 'skills', 'smart-model-router', 'state');
const STATE_FILE = path.join(STATE_DIR, 'model_metrics.json');
const METADATA_FILE = path.join(STATE_DIR, 'metadata.json');

function loadState() {
    try {
        if (!fs.existsSync(STATE_DIR)) fs.mkdirSync(STATE_DIR, {recursive: true});
        if (!fs.existsSync(STATE_FILE)) return {};
        return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
    } catch { return {}; }
}

function loadMetadata() {
    try {
        if (!fs.existsSync(METADATA_FILE)) return {total_uses: 0};
        return JSON.parse(fs.readFileSync(METADATA_FILE, 'utf-8'));
    } catch { return {total_uses: 0}; }
}

function calculateScore(metrics) {
    if (!metrics || !metrics.uses) return 0;
    const satisfaction = metrics.satisfaction_avg || 3;
    const speed = metrics.speed_avg_ms || 2000;
    const cost = metrics.cost_avg || 0.05;
    const error_rate = metrics.error_rate || 0.1;
    
    const satisfaction_norm = satisfaction / 5;
    const speed_norm = Math.min(1, 3000 / speed);
    const cost_norm = Math.min(1, 0.1 / cost);
    const error_norm = 1 - error_rate;
    
    const score = 0.4 * satisfaction_norm + 0.2 * speed_norm + 0.2 * cost_norm + 0.2 * error_norm;
    return Math.round(score * 5 * 100) / 100;
}

const state = loadState();
const metadata = loadMetadata();

console.log('='.repeat(60));
console.log('当前模型使用情况：');
for (const model of AVAILABLE_MODELS) {
    const metrics = state[model] || {};
    const uses = metrics.uses || 0;
    const score = calculateScore(metrics);
    console.log(`  ${model}: 使用 ${uses} 次, 评分 ${score.toFixed(2)}`);
}
console.log(`  总使用次数: ${metadata.total_uses || 0}`);
console.log('='.repeat(60));

// Auto select - using ε-Greedy for now (data < 20)
const total_uses = metadata.total_uses || 0;
const epsilon = Math.max(0.1, 0.5 - total_uses * 0.001);

if (Math.random() < epsilon) {
    const model = AVAILABLE_MODELS[Math.floor(Math.random() * AVAILABLE_MODELS.length)];
    console.log(`[ε-Greedy] 探索模式 (ε=${epsilon.toFixed(3)}): 随机选择 ${model}`);
    console.log(`\n✅ 推荐使用: ${model}`);
    console.log(`\n命令: /model ${model}`);
} else {
    let bestModel = AVAILABLE_MODELS[0];
    let bestScore = -1;
    for (const model of AVAILABLE_MODELS) {
        const score = calculateScore(state[model] || {});
        if (score > bestScore) {
            bestScore = score;
            bestModel = model;
        }
    }
    console.log(`[ε-Greedy] 利用模式 (ε=${epsilon.toFixed(3)}): 选择最优 ${bestModel} (评分=${bestScore.toFixed(2)})`);
    console.log(`\n✅ 推荐使用: ${bestModel}`);
    console.log(`\n命令: /model ${bestModel}`);
}
