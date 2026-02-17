# 03-templates - 代码模板

本目录用于存放可直接使用的 TileLangAscend 代码模板。

## 目录结构

```
03-templates/
├── README.md
├── basic-operations/         # 基础操作模板
│   ├── tensor-init.md
│   ├── matrix-multiply.md
│   ├── element-wise.md
│   ├── reduction.md
│   └── transpose.md
├── advanced-patterns/       # 高级模式
│   ├── fused-operations.md
│   ├── custom-kernels.md
│   └── pipeline-optimization.md
└── common-use-cases/       # 常见用例
    ├── conv2d-template.md
    ├── matmul-template.md
    └── activation-functions.md
```

## 模板分类

### 1. 基础操作模板 (10个)
- 张量初始化
- 矩阵乘法
- 逐元素操作
- 归约操作
- 转置操作
- 切片操作
- 拼接操作
- 类型转换
- 设备迁移
- 形状变换

### 2. 高级模式 (8个)
- 融合操作
- 自定义核函数
- 流水线优化
- 多流并行
- 混合精度计算
- 动态Shape处理
- 梯度计算
- 反向传播

### 3. 常见用例 (6个)
- Conv2D 模板
- MatMul 模板
- 激活函数模板
- 归一化模板
- 池化模板
- 全连接层模板

## 使用方法

每个模板都应包含：
1. 功能说明
2. 完整代码
3. 参数说明
4. 运行结果
5. 扩展建议

---
*最后更新: 2026-02-15*
