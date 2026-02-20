# tilelang-ascend 知识库分块填充计划

## 📊 当前状态
- 已完成：52,501 字 (52.5%)
- 剩余：47,499 字 (47.5%)
- 目标：100,000 字

## 🎯 分块提纲（每个子任务 2000-3000 字）

### 块1: 内存管理 API (02-api-reference/)
- [ ] 01-memory-management.md (~2500字)
- [ ] 02-kernel-functions.md (~2500字)
- [ ] 03-compilation.md (~2000字)
- [ ] 04-optimization.md (~2000字)

### 块2: 最佳实践 (02-best-practices/)
- [ ] memory-optimization.md (~2500字)
- [ ] parallel-computing.md (~2500字)
- [ ] debugging-tips.md (~2000字)

### 块3: 高级模板 (03-templates/advanced-patterns/)
- [ ] fused-operations.md (~2500字)
- [ ] custom-kernels.md (~2500字)
- [ ] pipeline-optimization.md (~2000字)

### 块4: 常见用例模板 (03-templates/common-use-cases/)
- [ ] conv2d-template.md (~2500字)
- [ ] activation-functions.md (~2000字)

### 块5: 调用技巧 (04-techniques/)
- [ ] tiling-strategies.md (~2500字)
- [ ] memory-layout.md (~2500字)
- [ ] kernel-fusion.md (~2000字)
- [ ] auto-tuning.md (~2000字)

### 块6: 完整示例 (05-examples/)
- [ ] simple-ops/ 系列 (~3000字)
- [ ] medium-projects/ 系列 (~3000字)

### 块7: FAQ (06-faq/)
- [ ] installation-issues.md (~1500字)
- [ ] performance-issues.md (~1500字)
- [ ] debugging-issues.md (~1500字)

## ✅ 执行规则
1. 每次只读取目标文件的当前状态 + 提纲
2. 不读取其他已完成文件
3. 专注于单一子任务
4. 完成后立即保存，不触发全量上下文读取
