# 01-api-reference - API参考

本目录用于存放 TileLangAscend API 参考文档。

## 目录结构

```
01-api-reference/
├── README.md
├── tensor-operations.md    # 张量操作API
├── memory-management.md    # 内存管理API
├── kernel-functions.md     # 核函数API
├── compilation.md          # 编译相关API
└── optimization.md         # 优化相关API
```

## API 分类

### 1. 张量操作 API
- 创建与初始化
- 切片与索引
- 拼接与分割
- 类型转换
- 设备管理

### 2. 内存管理 API
- 内存分配
- 内存释放
- 内存池
- 内存复用

### 3. 核函数 API
- 核函数定义
- 核函数调用
- 并行配置
- 同步机制

### 4. 编译 API
- 编译选项
- 优化级别
- 目标设备
- 链接管理

### 5. 优化 API
- 自动调优
- 性能分析
- 优化提示
- 代码生成

## 贡献指南

每个 API 文档应包含：
1. **功能描述** - API 的作用
2. **参数说明** - 输入参数详细说明
3. **返回值** - 返回值类型和含义
4. **示例代码** - 可运行的示例
5. **注意事项** - 使用时需要注意的点

---
*最后更新: 2026-02-15*
