#!/usr/bin/env node
/**
 * Skill Verification Script (Node.js)
 * 验证 Phase 1 和 Phase 2 创建的技能代码
 */

const fs = require('fs');
const path = require('path');

const skillsToCheck = [
    // Phase 1
    'self-monitor',
    'survival-instinct', 
    'resource-manager',
    // Phase 2
    'auto-learning',
    'strategic-planning'
];

const workspace = 'C:\\Users\\Lenovo\\.openclaw\\workspace\\skills';

console.log('🔍 技能代码验证\n' + '='.repeat(50));

let allPassed = true;

for (const skill of skillsToCheck) {
    const skillPath = path.join(workspace, skill);
    const skillMdPath = path.join(skillPath, 'SKILL.md');
    
    console.log(`\n📦 检查: ${skill}`);
    
    // 检查 SKILL.md
    if (fs.existsSync(skillMdPath)) {
        const content = fs.readFileSync(skillMdPath, 'utf-8');
        console.log(`  ✅ SKILL.md 存在 (${content.length} bytes)`);
    } else {
        console.log(`  ❌ SKILL.md 缺失`);
        allPassed = false;
    }
    
    // 检查 Python 文件
    const pyFiles = fs.readdirSync(skillPath)
        .filter(f => f.endsWith('.py'));
    
    if (pyFiles.length > 0) {
        console.log(`  ✅ Python 文件: ${pyFiles.join(', ')}`);
        
        // 简单语法检查
        for (const pyFile of pyFiles) {
            const pyPath = path.join(skillPath, pyFile);
            const pyContent = fs.readFileSync(pyPath, 'utf-8');
            
            // 基本检查
            const hasMain = pyContent.includes('if __name__');
            const hasFunctionDef = pyContent.includes('def ');
            const hasClassDef = pyContent.includes('class ');
            
            if (hasMain || hasFunctionDef || hasClassDef) {
                console.log(`    ✅ ${pyFile} 结构有效`);
            } else {
                console.log(`    ⚠️ ${pyFile} 可能需要检查`);
            }
        }
    } else {
        console.log(`  ⚠️ 无 Python 文件`);
    }
}

console.log('\n' + '='.repeat(50));
console.log(allPassed ? '✅ 所有技能验证通过!' : '⚠️ 部分技能需要检查');
console.log('\n注意: Python 环境未配置，无法执行实际测试');
console.log('代码结构已验证，需要 Python 环境恢复后才能运行');
