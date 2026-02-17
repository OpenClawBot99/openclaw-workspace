const fs = require('fs');
const path = require('path');

const STATE_DIR = path.join(__dirname, '..', 'state');
const PROGRESS_FILE = path.join(STATE_DIR, 'progress.json');

// 读取当前进度
const progress = JSON.parse(fs.readFileSync(PROGRESS_FILE, 'utf-8'));

// 添加新的检查点
const checkpoint = {
    task_id: 4,
    task_name: "继续 Phase 1 - 智能生命体开发",
    progress: 85,
    status: "in_progress",
    timestamp: new Date().toISOString(),
    note: "每小时自动检查点"
};

progress.checkpoints.push(checkpoint);
progress.last_update = new Date().toISOString();

// 保存
fs.writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2), 'utf-8');

console.log('✅ 检查点已保存');
console.log(JSON.stringify(checkpoint, null, 2));
