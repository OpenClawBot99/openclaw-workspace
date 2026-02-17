# 04-techniques - 调用技巧

本目录用于存放 TileLangAscend 高级调用技巧和优化策略。

## 目录结构

```
04-techniques/
├── README.md
├── tiling-strategies.md     # 分块策略
├── memory-layout.md        # 内存布局
├── kernel-fusion.md        # 算子融合
└── auto-tuning.md          # 自动调优
```

## 技巧分类

### 1. 分块策略
- 自动分块
- 手动分块
- 分块参数调优
- 动态分块

### 2. 内存布局
- NCHW vs NHWC
- 内存对齐
- 缓存友好设计
- 跨平台兼容

### 3. 算子融合
- 融合规则
- 融合策略
- 性能收益分析
- 手动融合

### 4. 自动调优
- 调优参数空间
- 调优算法
- 结果应用
- 最佳实践

---
*最后更新: 2026-02-15*
