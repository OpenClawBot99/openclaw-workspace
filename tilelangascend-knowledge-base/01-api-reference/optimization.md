# 优化 API

> TileLang-Ascend 性能优化完整指南

## 概述

TileLang-Ascend 提供了丰富的优化 API，帮助开发者最大化利用 Ascend NPU 的计算能力。本文详细介绍自动调优、性能分析、优化提示等核心 API。

## 优化层级

### 多层级优化架构

```
┌─────────────────────────────────────────────┐
│            算法层优化                        │
│     (数据结构、计算方式选择)                  │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│            调度层优化                        │
│   (循环变换、分块、并行、向量化)              │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│            编译层优化                        │
│     (常量折叠、死代码消除、IR优化)            │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│            目标代码优化                      │
│       (指令调度、寄存器分配)                  │
└─────────────────────────────────────────────┘
```

## 自动调优 API

### `T.tune`

```python
import tilelang as T

@T.prim_func
def matmul_kernel(
    a: T.Buffer((1024, 1024), "float16"),
    b: T.Buffer((1024, 1024), "float16"),
    c: T.Buffer((1024, 1024), "float16")
):
    # 初始实现
    for i, j, k in T.grid(1024, 1024, 1024):
        with T.block("matmul"):
            vi = T.axis.spatial(1024, i)
            vj = T.axis.spatial(1024, j)
            vk = T.axis.reduce(1024, k)
            c[vi, vj] = c[vi, vj] + a[vi, vk] * b[vk, vj]

# 自动调优
best_config = T.tune(
    matmul_kernel,
    target="ascend910",
    n_trial=200,
    timeout=600
)

print(f"Best config: {best_config}")
```

### `TuneConfig`

```python
# 详细调优配置
tune_config = T.tune_config(
    # 参数空间定义
    tile_i=[16, 32, 64, 128],
    tile_j=[16, 32, 64, 128],
    tile_k=[16, 32, 64],
    unroll_depth=[1, 4, 8, 16],
    vectorize_len=[1, 4, 8, 16],
    
    # 调优策略
    tuner="xgb",  # grid, random, xgb, genetic
    n_trial=100,
    early_stopping=20,
    
    # 资源限制
    max_time_per_trial=30,
    max_memory_mb=4096,
    
    # 日志
    log_filename="tune_log.json",
    verbose=1,
)
```

### 调优器对比

| 调优器 | 适用场景 | 优点 | 缺点 |
|--------|---------|------|------|
| Grid Search | 小参数空间 | 全面覆盖 | 耗时长 |
| Random | 大参数空间 | 快速探索 | 不保证最优 |
| XGBoost | 中等空间 | 效果好 | 需要训练数据 |
| Genetic | 复杂空间 | 全局搜索 | 实现复杂 |

## 性能分析 API

### `T.profile`

```python
# 编译并启用性能分析
mod = T.compile(kernel_func, profile=True)

# 准备输入数据
input_a = T.randn((1024, 1024), dtype="float16")
input_b = T.randn((1024, 1024), dtype="float16")
output_c = T.zeros((1024, 1024), dtype="float16")

# 执行性能分析
profile_result = mod.profile(
    input_a, input_b, output_c
)

print(profile_result)
```

### `T.analyze`

```python
# 性能瓶颈分析
analysis = mod.analyze()

# 详细指标
print(f"计算强度: {analysis.flops / 1e9} GFLOPS")
print(f"内存带宽: {analysis.memory_bandwidth / 1e9} GB/s")
print(f"算术强度: {analysis.arith_intensity} FLOPs/Byte")

# 瓶颈类型
print(f"瓶颈类型: {analysis.bottleneck}")
# compute_bound, memory_bound, bandwidth_bound
```

### `T.trace`

```python
# 执行追踪
with T.trace(enabled=True) as trace:
    result = mod(input_a, input_b)

# 查看追踪结果
print(trace.timeline)
print(trace.memory_access)
print(trace.compute_pattern)
```

## 优化提示 API

### `T.pragma`

```python
@T.prim_func
def optimized_kernel(a, b, c):
    for i in T.serial(128):
        with T.block("compute"):
            # 提示编译器展开循环
            T.pragma("unroll", depth=4)
            
            vi = T.axis.spatial(128, i)
            c[vi] = a[vi] + b[vi]
```

### 常用 Pragma

| Pragma | 说明 | 示例 |
|--------|------|------|
| unroll | 循环展开 | `T.pragma("unroll", depth=8)` |
| vectorize | 向量化 | `T.pragma("vectorize", factor=8)` |
| parallel | 并行化 | `T.pragma("parallel")` |
| unroll_explicit | 显式展开 | `T.pragma("unroll_explicit")` |

### `T.tiling_hint`

```python
@T.prim_func
def tiled_kernel(a, b, c):
    # 提示 tiling 策略
    T.tiling_hint(
        tile_i=32,
        tile_j=32,
        tile_k=64,
        unroll_j=True,
        vectorize=True
    )
    
    for i, j, k in T.grid(1024, 1024, 1024):
        with T.block("gemm"):
            # 计算
            pass
```

## 内存优化 API

### `T.memory_optimize`

```python
# 启用内存优化
mod = T.compile(
    kernel_func,
    memory_opt=True
)
```

### `T.buffer_reuse`

```python
@T.prim_func
def reuse_buffer(a, b, c):
    # 提示缓冲区复用
    buf1 = T.alloc_buffer((256, 256), "float16")
    buf2 = T.alloc_buffer((256, 256), "float16")
    
    # 第一阶段使用 buf1
    compute_stage1(a, buf1)
    
    # 第二阶段复用 buf1 作为 buf2
    T.buffer_reuse(buf1, buf2)
    compute_stage2(buf1, c)
```

### `T.memory_planning`

```python
# 内存规划
schedule = T.create_schedule(kernel_func)

# 内存规划阶段
schedule = T.memory_planning(
    schedule,
    # 内存分配策略
    strategy="compact",  # 紧凑分配
    # 内存对齐
    alignment=256,
    # 内存池
    use_memory_pool=True,
    pool_size=1024*1024,
)
```

## 计算优化 API

### `T.compute_at`

```python
# 指定计算位置
s = T.create_schedule(kernel)

# 将 compute 阶段安排在特定位置
s[stage2].compute_at(s[stage1], axis="i")
```

### `T.fuse`

```python
# 融合循环
s = T.create_schedule(kernel)
i, j = s[kernel].op.axis
fused = s[kernel].fuse(i, j)
```

### `T.reorder`

```python
# 重排循环顺序
s = T.create_schedule(kernel)
i, j, k = s[kernel].op.axis
s[kernel].reorder(i, k, j)  # 改变内存访问模式
```

## 并行化 API

### `T.parallel`

```python
@T.prim_func
def parallel_kernel(a, b, c):
    # 自动并行化外层循环
    for i in T.parallel(1024):
        for j in T.serial(1024):
            c[i, j] = a[i, j] + b[i, j]
```

### `T.thread_binding`

```python
# 线程绑定
@T.prim_func
def thread_kernel(a, b, c):
    # 绑定到线程块
    for i in T.thread_binding(64, thread="blockIdx.x"):
        # 绑定到线程
        for j in T.thread_binding(8, thread="threadIdx.x"):
            c[i*8+j] = a[i*8+j] + b[i*8+j]
```

### `T.vectorize`

```python
# 向量化
@T.prim_func
def vector_kernel(a, b, c):
    for i in T.serial(1024):
        # 向量化内层
        c[i] = T.vectorize(8)(a[i] + b[i])
```

## 量化优化

### `T.quantize`

```python
# 量化到 INT8
mod = T.compile(
    kernel_func,
    quantize=True,
    dtype="int8",
    calibration_data=calib_data
)
```

### `T.quantization_scheme`

```python
# 量化方案
scheme = T.quantization_scheme(
    # 对称量化
    mode="symmetric",
    # 量化精度
    dtype="int8",
    # 校准方法
    calibration="min_max",  # min_max, percentile, entropy
    # 校准百分位
    percentile=99.99,
)
```

## 图优化

### `T.graph_optimize`

```python
# 图优化
mod = T.compile(
    kernel_func,
    graph_opt=True,
    # 融合规则
    fuse_ops=["matmul", "relu", "bias_add"],
)
```

### 常用图优化

| 优化 | 说明 |
|------|------|
| Constant Folding | 常量折叠 |
| Fused Ops | 算子融合 |
| Dead Code Elimination | 死代码消除 |
| Layout Transform | 布局转换 |

## 调度优化

### `T.schedule`

```python
# 创建调度并优化
s = T.create_schedule(kernel_func)

# 应用优化调度
i, j = s[kernel_func].op.axis

# 1. 分块
o_i, i = s[kernel_func].split(i, factor=32)
o_j, j = s[kernel_func].split(j, factor=32)

# 2. 重排
s[kernel_func].reorder(o_i, o_j, i, j)

# 3. 展开
s[kernel_func].unroll(i)

# 4. 向量化
s[kernel_func].vectorize(j)

# 5. 并行化
s[kernel_func].parallel(o_i)

# 编译
mod = T.build(s, kernel_func)
```

### 自动调度

```python
# 使用 AutoTVM 自动调度
with T.auto_schedule() as s:
    # 定义计算
    # 编译器自动选择最优调度
    output = compute(a, b)
```

## 最佳实践

### 1. 性能关键路径优化

```python
# 识别热点
profile = mod.profile(input_data)
hotspots = profile.hotspots()

# 优化热点
for stage in hotspots[:3]:
    tuned_config = T.tune(stage)
    mod = T.compile(stage, config=tuned_config)
```

### 2. 逐步优化

```python
# 步骤1: 基础实现
mod = T.compile(func, opt_level=1)

# 步骤2: 添加调度优化
s = T.create_schedule(func)
s = apply_optimizations(s)
mod = T.build(s, func)

# 步骤3: 自动调优
best_config = T.tune(func, n_trial=100)
mod = T.compile(func, config=best_config)
```

### 3. 验证优化效果

```python
# 优化前
mod_before = T.compile(func)
time_before = mod_before.profile(input_data)["time"]

# 优化后
mod_after = T.compile(func, opt_level=3)
time_after = mod_after.profile(input_data)["time"]

print(f"Speedup: {time_before / time_after:.2f}x")
```

### 4. 持续监控

```python
# 生产环境持续监控
while True:
    result = mod.execute(input_data)
    metrics.record(result)
    
    # 如果性能下降，触发重新调优
    if metrics.is_degraded():
        T.tune(mod)
```

---

*本文档是 TileLang-Ascend 知识库的一部分*
*最后更新: 2026-02-18*
