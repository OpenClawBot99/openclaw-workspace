# 编译 API

> TileLang-Ascend 编译系统完整指南

## 概述

TileLang-Ascend 的编译系统将高级 DSL 代码转换为可在 Ascend NPU 上执行的高效机器码。本文详细介绍编译选项、优化级别、目标设备配置等核心 API。

## 编译流程

### 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    TileLang 源码                            │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  解析与语义分析                              │
│  (AST 构建、类型检查、作用域分析)                            │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  高层优化 (HLO)                              │
│  (常量折叠、死代码消除、代数简化)                             │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  调度优化 (Schedule)                         │
│  (循环变换、内存 tiling、并行化)                             │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  代码生成 (Codegen)                          │
│  (TVM ComputeIR → 目标代码)                                │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Ascend NPU 二进制                         │
└─────────────────────────────────────────────────────────────┘
```

## 核心编译 API

### `T.compile`

```python
import tilelang as T

@T.prim_func
def simple_kernel(a, b, c):
    for i in T.serial(128):
        with T.block("compute"):
            vi = T.axis.spatial(128, i)
            c[vi] = a[vi] + b[vi]

# 编译函数
mod = T.compile(simple_kernel)
```

### 编译参数

```python
# 完整编译参数
mod = T.compile(
    func,                    # 要编译的函数
    target="ascend910",       # 目标设备
    opt_level=3,             # 优化级别 (0-3)
    config=compile_config     # 编译配置
)
```

## 目标设备配置

### Ascend NPU

```python
# Ascend 910
mod = T.compile(
    kernel_func,
    target="ascend910",
    target_host="llvm"  # 主机端 LLVM
)

# Ascend 310
mod = T.compile(
    kernel_func,
    target="ascend310"
)
```

### 多目标

```python
# 同时编译多个目标
mod = T.compile(
    kernel_func,
    target={
        "npu": "ascend910",
        "llvm": "llvm -mtriple=aarch64-linux-gnu"
    }
)
```

### 目标配置对象

```python
target = T.target(
    name="ascend910",
    keys=["npu", "cuda", "llvm"],
    max_function_args=64,
    max_num_threads=2048,
    thread_warp_size=32,
    max_shared_memory_per_block=65536,
)
```

## 优化级别

### Level 0: 无优化

```python
# 最小化编译，快速生成
mod = T.compile(func, opt_level=0)
```

### Level 1: 基本优化

```python
# 常量折叠、死代码消除
mod = T.compile(func, opt_level=1)
```

### Level 2: 标准优化

```python
# 循环展开、向量化、基本内存优化
mod = T.compile(func, opt_level=2)
```

### Level 3: 激进优化

```python
# 自动调优、复杂循环变换、深度优化
mod = T.compile(func, opt_level=3)
```

### 指定优化过程

```python
# 分步优化
with T.transform.PassContext(opt_level=2) as ctx:
    # 应用特定优化
    ctx.apply_pass("FoldConstants")
    ctx.apply_pass("SimplifyInference")
    
    mod = T.compile(func)
```

## 编译配置

### `CompileConfig`

```python
config = T.compile_config(
    # 优化配置
    opt_level=3,
    disabled_pass=[],  # 禁用的优化 pass
    enabled_pass=["AutoFoldConst"],  # 启用的优化 pass
    
    # 代码生成配置
    codegen=True,
    generate_hybrid=False,
    
    # 调试配置
    dump_pass_ir=False,
    dump_code=False,
)
```

### 调度配置

```python
schedule_config = T.schedule_config(
    # 循环分块
    tile_c={ "tile_i": 32, "tile_j": 32 },
    
    # 并行化
    parallel_enable=True,
    
    # 向量化
    vectorize_enable=True,
    vectorize_len=8,
    
    # 展开
    unroll_enable=True,
    unroll_depth=8,
)
```

## 调度编译

### `T.create_schedule`

```python
# 创建调度
s = T.create_schedule(kernel_func)

# 应用调度原语
i, j = s[kernel_func].op.axis
r = s[kernel_func].op.reduce_axis

# 分块
o_i, i = s[kernel_func].split(i, factor=32)
o_j, j = s[kernel_func].split(j, factor=32)

# 并行化
s[kernel_func].parallel(o_i)

# 编译
mod = T.build(s, kernel_func)
```

### 调度原语详解

#### Split（分拆）

```python
s = T.create_schedule(func)

# 将循环 i 拆分为外层 i_outer 和内层 i_inner
i_outer, i_inner = s[func].split(i, factor=32)
```

#### Fuse（融合）

```python
# 融合两个循环
fused = s[func].fuse(i, j)
```

#### Reorder（重排）

```python
# 重排循环顺序
s[func].reorder(i, j, k)
```

#### Unroll（展开）

```python
# 展开循环
s[func].unroll(i)
```

#### Vectorize（向量化）

```python
# 向量化内层循环
s[func].vectorize(j)
```

## JIT 编译

### 基础 JIT

```python
@T.jit
def add_kernel(a, b):
    return a + b

# 自动编译
result = add_kernel(input_a, input_b)
```

### 高级 JIT

```python
@T.jit(
    target="ascend910",
    opt_level=3,
    tracing=True  # 记录执行轨迹
)
def traced_kernel(a, b, c):
    # 计算
    c = a + b
    return c
```

### 延迟编译

```python
@T.jit(lazy=False)  # 立即编译
def eager_kernel(a, b):
    return a + b

@T.jit(lazy=True)  # 延迟编译
def lazy_kernel(a, b):
    return a + b
```

## 自动调优

### 基础调优

```python
# 创建调优任务
tune_task = T.tune.create_task(
    kernel_func,
    target="ascend910",
    config=tune_config
)

# 运行调优
best_config = tune_task.tune(
    n_trial=100,  # 尝试次数
    timeout=3600,  # 超时时间（秒）
    tuner="grid",  # 调优器类型
)

# 使用最佳配置编译
mod = T.compile(kernel_func, config=best_config)
```

### 调优器类型

```python
# Grid Search
tune_task.tune(tuner="grid")

# Random Search
tune_task.tune(tuner="random")

# XGBoost
tune_task.tune(tuner="xgb")

# Genetic
tune_task.tune(tuner="genetic")
```

### 调优配置

```python
tune_config = T.tune_config(
    # 参数空间
    tile_i=[16, 32, 64, 128],
    tile_j=[16, 32, 64, 128],
    unroll_depth=[4, 8, 16],
    
    # 约束
    max_memory=1024 * 1024 * 1024,  # 1GB
    max_time=300,  # 5分钟
    
    # 早期停止
    early_stopping=10,
)
```

## 编译产物

### 获取编译结果

```python
mod = T.compile(kernel_func, target="ascend910")

# 获取 C 代码
c_source = mod.get_source("c")

# 获取 LLVM IR
llvm_ir = mod.get_source("llvm")

# 获取设备二进制
device_binary = mod.get_source("device")
```

### 保存编译结果

```python
# 保存到文件
mod.save("kernel.so")

# 加载已编译模块
loaded_mod = T.runtime.load("kernel.so")
```

## 编译错误处理

### 常见编译错误

```python
try:
    mod = T.compile(kernel_func)
except T.CompileError as e:
    # 处理编译错误
    print(f"编译错误: {e}")
    print(f"错误位置: {e.lineno}")
    print(f"源码: {e.source_code}")

# 类型错误
except T.TypeError as e:
    print(f"类型错误: {e}")

# 调度错误
except T.ScheduleError as e:
    print(f"调度错误: {e}")
```

### 详细错误信息

```python
# 启用详细错误输出
mod = T.compile(
    kernel_func,
    verbose=2,  # 详细级别
    show_ir=True,  # 显示 IR
)
```

## 性能分析

### Profiling

```python
# 编译并分析
mod = T.compile(kernel_func, profile=True)

# 执行并收集性能数据
profile_result = mod.profile(input_data)

# 查看结果
print(profile_result)
# 输出:
# {
#     "total_time": 1.23,  // 毫秒
#     "kernel_time": 1.10,
#     "memory_time": 0.13,
#     "flops": 1e12,
#     "memory_bw": 400,  // GB/s
# }
```

### 瓶颈分析

```python
# 分析瓶颈
analysis = mod.analyze_bottleneck()

print(analysis)
# 输出:
# {
#     "compute_bound": 0.6,  // 60% 计算瓶颈
#     "memory_bound": 0.3,    // 30% 内存瓶颈
#     "bandwidth_bound": 0.1,  // 10% 带宽瓶颈
# }
```

## 交叉编译

### ARM 交叉编译

```python
# 为 ARM 设备交叉编译
mod = T.compile(
    kernel_func,
    target="llvm -mtriple=aarch64-linux-gnu",
    target_host="llvm"
)
```

### 多架构支持

```python
# x86_64
mod_x86 = T.compile(func, target="llvm")

# ARM64
mod_arm = T.compile(func, target="llvm -mtriple=aarch64-linux-gnu")

# Ascend NPU
mod_npu = T.compile(func, target="ascend910")
```

## 最佳实践

### 1. 选择合适的优化级别

```python
# 开发阶段
mod = T.compile(func, opt_level=0)  # 快速编译

# 生产阶段
mod = T.compile(func, opt_level=3)  # 深度优化
```

### 2. 使用调优获得最佳性能

```python
# 对于性能关键的内核，进行调优
best_config = tune_gemm_kernel()
mod = T.compile(gemm_kernel, config=best_config)
```

### 3. 启用详细日志进行调试

```python
mod = T.compile(
    kernel_func,
    verbose=1,
    dump_ir=True,
)
```

### 4. 缓存编译结果

```python
# 缓存编译产物
with T.cache(mod_file="kernel_cache.so"):
    mod = T.compile(kernel_func)
```

---

*本文档是 TileLang-Ascend 知识库的一部分*
*最后更新: 2026-02-18*
