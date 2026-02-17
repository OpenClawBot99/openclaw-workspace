# TileLang-Ascend 性能调优指南

> 基于官方文档和最佳实践整理
> 最后更新：2026-02-15

---

## 目录

1. [性能调优概述](#1-性能调优概述)
2. [自动调优（Auto-Tuning）](#2-自动调优auto-tuning)
3. [手动调优技巧](#3-手动调优技巧)
4. [性能分析工具](#4-性能分析工具)
5. [常见性能瓶颈](#5-常见性能瓶颈)
6. [调优案例研究](#6-调优案例研究)

---

## 1. 性能调优概述

### 1.1 性能优化目标

| 指标 | 目标 | 说明 |
|------|------|------|
| **内存带宽利用率** | >80% | 接近硬件理论峰值 |
| **计算吞吐量** | >90% | 充分利用计算单元 |
| **延迟** | 最小化 | 减少kernel执行时间 |
| **功耗** | 优化 | 在性能和功耗间平衡 |

### 1.2 性能优化维度

```
┌─────────────────────────────────────────────────────┐
│                  性能优化维度                          │
└─────────────────────────────────────────────────────┘

1. 算法层面
   - 选择合适的算法
   - 减少计算复杂度

2. 内存层面
   - 优化内存访问模式
   - 减少内存带宽压力

3. 计算层面
   - 充分利用计算单元
   - 流水线和并行优化

4. 系统层面
   - 减少kernel启动开销
   - 优化数据传输
```

---

## 2. 自动调优（Auto-Tuning）

### 2.1 调优流程

TileLang 提供了强大的自动调优功能：

```python
# Step 1: 实现带参数的 kernel
def kernel(block_M=None, block_N=None, block_K=None, num_stages=None):
    @T.prim_func
    def main(A: T.Buffer((M, K), dtype), B: T.Buffer((N, K), dtype), C: T.Buffer((M, N), dtype)):
        # kernel 实现
        pass
    return main

# Step 2: 定义搜索空间
configs = [
    {"block_M": 128, "block_N": 128, "block_K": 64, "num_stages": 2},
    {"block_M": 64, "block_N": 256, "block_K": 32, "num_stages": 3},
    # 更多配置...
]

# Step 3: 自动调优
autotuner = AutoTuner.from_kernel(kernel=kernel, configs=configs)
result = autotuner.run(warmup=3, rep=20)

# Step 4: 使用最优配置
best_kernel = result.kernel
output = best_kernel(a, b)
```

### 2.2 使用 Carver 自动生成配置

Carver 可以自动生成高效的配置：

```python
from tilelang.carver import MatmulTemplate
from tilelang.carver.arch import CUDA

# 配置模板
arch = CUDA("cuda")
carve_template = MatmulTemplate(
    M=M, N=N, K=K,
    in_dtype="float16",
    out_dtype="float16",
    accum_dtype="float",
).with_arch(arch)

# 生成 top-k 优化提示（推荐 topk=10）
roller_hints = carve_template.recommend_hints(topk=10)

# 提取配置
configs = []
for hint in roller_hints:
    config = {
        "block_M": hint.block_m,
        "block_N": hint.block_n,
        "block_K": hint.rstep[0],
        "num_stages": hint.pipeline_stage,
        "thread_num": hint.thread_num,
        "enable_rasterization": hint.rasterization_plan is not None
    }
    configs.append(config)
```

### 2.3 调优参数说明

| 参数 | 说明 | 典型范围 |
|------|------|----------|
| `block_M` | M维度分块大小 | 32-256 |
| `block_N` | N维度分块大小 | 32-256 |
| `block_K` | K维度分块大小 | 32-128 |
| `num_stages` | 流水线级数 | 0-4 |
| `thread_num` | 线程数 | 32-256 |
| `enable_rasterization` | 是否启用光栅化 | True/False |

---

## 3. 手动调优技巧

### 3.1 内存访问优化

#### 3.1.1 合并访问（Coalesced Access）

```python
# ❌ 错误：非合并访问
for i in T.serial(N):
    for j in T.serial(K):
        C[i, j] = A[i, j] + B[i, j]

# ✅ 正确：合并访问
for i, j in T.Parallel(N, K):
    C[i, j] = A[i, j] + B[i, j]
```

#### 3.1.2 向量化加载

```python
# 使用向量化加载提高带宽利用率
MAX_TRANSACTION_SIZE = 128  # bits
TILE_K = MAX_TRANSACTION_SIZE // DataType(dtype).bits

for k in T.vectorized(TILE_K):
    A_local[k] = A[offset + k]
```

#### 3.1.3 共享内存优化

```python
# 使用共享内存缓存重复访问的数据
A_shared = T.alloc_shared((block_M, block_K), dtype)
B_shared = T.alloc_shared((block_K, block_N), dtype)

# 一次性加载到共享内存
T.copy(A[src], A_shared)
T.copy(B[src], B_shared)

# 多次从共享内存读取
for i in range(iterations):
    compute(A_shared, B_shared)
```

### 3.2 计算优化

#### 3.2.1 流水线并行

```python
# 使用流水线隐藏内存延迟
for ko in T.Pipelined(T.ceildiv(K, block_K), num_stages=3):
    # Stage 1: 加载数据
    T.copy(A[ko * block_K], A_shared)
    T.copy(B[ko * block_K], B_shared)
    
    # Stage 2: 计算
    T.gemm(A_shared, B_shared, C_local)
```

#### 3.2.2 双缓冲（Double Buffering）

```python
# 使用双缓冲重叠计算和数据传输
A_buffer = [T.alloc_shared(...) for _ in range(2)]
B_buffer = [T.alloc_shared(...) for _ in range(2)]

for ko in T.serial(loop_k):
    # 加载下一块数据
    T.copy(A[(ko+1) * block_K], A_buffer[(ko+1) % 2])
    
    # 计算当前块
    T.gemm(A_buffer[ko % 2], B_buffer[ko % 2], C_local)
```

### 3.3 同步优化

#### 3.3.1 减少同步次数

```python
# ❌ 错误：过多的同步
for k in T.serial(loop_k):
    T.copy(A[k], A_shared)
    T.barrier_all()  # 不必要的同步
    T.gemm(A_shared, B, C)

# ✅ 正确：最小化同步
for k in T.serial(loop_k):
    T.copy(A[k], A_shared)
    # 仅在必要时同步
    if need_sync:
        T.barrier_all()
    T.gemm(A_shared, B, C)
```

---

## 4. 性能分析工具

### 4.1 内置 Profiler

```python
from tilelang.profiler import Profiler

# 创建 profiler
profiler = Profiler(kernel)

# 运行 benchmark
latency = profiler.do_bench(warmup=10, rep=100)
print(f"平均延迟: {latency:.3f} ms")

# 详细性能数据
perf_data = profiler.profile(a, b)
print(f"内存带宽: {perf_data.bandwidth:.2f} GB/s")
print(f"计算吞吐量: {perf_data.throughput:.2f} TFLOPS")
```

### 4.2 查看生成的代码

```python
# 获取生成的 CUDA/AscendC 代码
kernel_source = kernel.get_kernel_source()
print(kernel_source)

# 保存到文件
with open("kernel.cu", "w") as f:
    f.write(kernel_source)
```

### 4.3 调试工具

```python
# 在 kernel 中添加打印
T.printf("Value at %d: %f\n", i, A[i])

# Dump 张量数据
T.dump_tensor(A_shared, "A_shared.bin")
```

---

## 5. 常见性能瓶颈

### 5.1 内存带宽瓶颈

**症状**：
- 内存带宽利用率低
- kernel 执行时间长

**解决方案**：
- 使用向量化加载
- 优化内存访问模式
- 使用共享内存缓存

### 5.2 计算瓶颈

**症状**：
- 计算单元利用率低
- 流水线停顿

**解决方案**：
- 增加流水线级数
- 使用 Tensor Core
- 优化计算强度

### 5.3 同步瓶颈

**症状**：
- 线程等待时间长
- 并行度低

**解决方案**：
- 减少同步次数
- 使用异步操作
- 优化线程块大小

---

## 6. 调优案例研究

### 6.1 GEMV 优化案例

| 优化版本 | 延迟 | 加速比 |
|----------|------|--------|
| naive_gemv | 0.166 ms | 1.0x |
| splitk_gemv | 0.024 ms | 6.9x |
| splitk_gemv_vectorized | 0.008 ms | 20.8x |
| splitk_gemv_vectorized_tvm | 0.007 ms | 23.7x |

**关键优化**：
1. ✅ K维度并行（splitk）
2. ✅ 向量化加载（vectorized）
3. ✅ 高效归约（tvm_thread_allreduce）

### 6.2 矩阵乘法优化案例

| 优化技术 | 性能提升 | 说明 |
|----------|----------|------|
| 分块优化 | 2-3x | 合适的 block_M/N/K |
| 流水线 | 1.5-2x | num_stages=2-3 |
| 向量化 | 1.2-1.5x | 向量化加载/存储 |
| Swizzling | 1.1-1.3x | L2缓存优化 |

---

## 7. 最佳实践

### 7.1 调优流程

```
1. 实现基础版本
   ↓
2. 使用自动调优找最优配置
   ↓
3. 分析性能瓶颈
   ↓
4. 针对性优化
   ↓
5. 验证正确性
   ↓
6. 性能回归测试
```

### 7.2 性能优化清单

- [ ] 使用自动调优找最优配置
- [ ] 优化内存访问模式
- [ ] 使用流水线并行
- [ ] 向量化加载/存储
- [ ] 减少同步次数
- [ ] 使用共享内存缓存
- [ ] 测试不同分块大小
- [ ] 验证数值正确性

---

*基于 tilelang-ascend 官方文档整理*
*最后更新：2026-02-15*
