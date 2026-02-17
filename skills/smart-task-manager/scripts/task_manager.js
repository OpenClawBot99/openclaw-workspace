#!/usr/bin/env node
/**
 * Smart Task Manager - Node.js 版本
 * 用于 cron 任务的自动检查
 */

const fs = require('fs');
const path = require('path');

const STATE_DIR = path.join(__dirname, '../state');
const TASKS_FILE = path.join(STATE_DIR, 'tasks.json');
const PROGRESS_FILE = path.join(STATE_DIR, 'progress.json');

function loadTasks() {
    if (fs.existsSync(TASKS_FILE)) {
        return JSON.parse(fs.readFileSync(TASKS_FILE, 'utf-8'));
    }
    return [];
}

function loadProgress() {
    if (fs.existsSync(PROGRESS_FILE)) {
        return JSON.parse(fs.readFileSync(PROGRESS_FILE, 'utf-8'));
    }
    return null;
}

function saveProgress(progress) {
    fs.writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2), 'utf-8');
}

function saveCheckpoint(task, note) {
    const checkpointFile = path.join(STATE_DIR, 'checkpoints', 
        `checkpoint_${task.id}_${Date.now()}.json`);
    
    const checkpoint = {
        task_id: task.id,
        task_name: task.name,
        progress: task.progress,
        status: task.status,
        timestamp: new Date().toISOString(),
        note: note
    };
    
    fs.writeFileSync(checkpointFile, JSON.stringify(checkpoint, null, 2), 'utf-8');
    return checkpointFile;
}

function check() {
    const tasks = loadTasks();
    const unfinished = tasks.filter(t => ['pending', 'in_progress'].includes(t.status));
    
    console.log(`🔍 发现 ${unfinished.length} 个未完成任务:`);
    unfinished.forEach(task => {
        console.log(`   - [${task.id}] ${task.name} (进度: ${task.progress}%)`);
    });
    
    return unfinished;
}

function autoContinue() {
    const tasks = loadTasks();
    const unfinished = tasks.filter(t => ['pending', 'in_progress'].includes(t.status));
    
    if (unfinished.length === 0) {
        console.log('✅ 所有任务已完成！');
        return null;
    }
    
    // 按优先级排序
    const sortedTasks = [...unfinished].sort((a, b) => b.priority - a.priority);
    
    // 优先选择进行中的任务
    const inProgress = sortedTasks.filter(t => t.status === 'in_progress');
    const nextTask = inProgress.length > 0 ? inProgress[0] : sortedTasks[0];
    
    console.log(`🚀 继续执行任务: ${nextTask.name}`);
    console.log(`   优先级: ${nextTask.priority}`);
    console.log(`   当前进度: ${nextTask.progress}%`);
    
    return nextTask;
}

function main() {
    const args = process.argv.slice(2);
    const command = args[0];
    
    if (command === '--check') {
        check();
    } else if (command === '--continue') {
        const task = autoContinue();
        if (task) {
            const progress = loadProgress() || { current_task_id: task.id };
            progress.current_task_id = task.id;
            progress.last_update = new Date().toISOString();
            saveProgress(progress);
        }
    } else if (command === '--save') {
        const taskId = parseInt(args[1]);
        const note = args[2] || '';
        
        const tasks = loadTasks();
        const task = tasks.find(t => t.id === taskId);
        
        if (task) {
            const checkpointFile = saveCheckpoint(task, note);
            console.log(`✅ 检查点已保存: ${checkpointFile}`);
            
            const progress = loadProgress() || {};
            progress.checkpoints = progress.checkpoints || [];
            progress.checkpoints.push({
                task_id: task.id,
                task_name: task.name,
                progress: task.progress,
                status: task.status,
                timestamp: new Date().toISOString(),
                note: note
            });
            progress.last_update = new Date().toISOString();
            saveProgress(progress);
        } else {
            console.log(`❌ 任务 ID ${taskId} 不存在`);
        }
    } else {
        console.log('用法: node task_manager.js [--check|--continue|--save <task_id> <note>]');
    }
}

main();
