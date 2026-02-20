# 并行计算最佳实践

> TileLang-Ascend 并行编程深度指南

## 概述

并行计算是充分利用 Ascend NPU 算力的关键。TileLang 提供了丰富的并行计算原语，本文详细介绍各种并行模式、实现技巧和最佳实践。

## 并行计算基础

### 并行层级

```
┌─────────────────────────────────────────────┐
│             任务级并行                        │
│        (多核、多设备并行)                      │
├─────────────────────────────────────────────┤
│             循环级并行                        │
│         (循环迭代并行执行)                     │
├─────────────────────────────────────────────┤
│             指令级并行                        │
│        (向量化、指令调度)                      │
├─────────────────────────────────────────────┤
│             数据级并行                        │
│       (SIMD、向量运算)                        │
└─────────────────────────────────────────────┘
```

## 并行原语

### `T.parallel` - 多线程并行

```python
@T.prim_func
def parallel_example(a, b, c):
    # 使用多线程并行执行
    for i in T.parallel(1024):
        with T.block("compute"):
            vi = T.axis.spatial(1024, i)
            c[vi] = a[vi] + b[vi]
```

### `T.thread_binding` - 线程绑定

```python
@T.prim_func
def thread_binding_example(a, b, c):
    # 绑定到线程块级别
    for i in T.thread_binding(64, thread="blockIdx.x"):
        # 绑定到线程级别
        for j in T.thread_binding(8, thread="threadIdx.x"):
            vi = i * 8 + j
            c[vi] = a[vi] + b[vi]
```

### `T.vectorize` - 向量化

```python
@T.prim_func
def vectorize_example(a, b, c):
    # 向量化操作 - 单指令多数据
    for i in T.serial(1024):
        with T.block("vec"):
            vi = T.axis.spatial(1024, i)
            # 一次处理 8 个元素
            for j in T.vectorize(8):
                c[vi * 8 + j] = a[vi * 8 + j] + b[vi * 8 + j]
```

### `T.unroll` - 循环展开

```python
@T.prim_func
def unroll_example(a, b):
    # 完全展开循环
    for i in T.unroll(8):
        b[i] = a[i] * 2
```

## 并行模式

### 数据并行

```python
@T.prim_func
def data_parallel(a, b, c):
    # 数据并行：每个处理单元处理数据的一部分
    # 等价于 SPMD (Single Program Multiple Data)
    
    # 步骤1：数据分发
    local_a = T.alloc_buffer((256,), "float16", scope="shared")
    local_b = T.alloc_buffer((256,), "float16", scope="shared")
    local_c = T.alloc_buffer((256,), "float16", "shared")
    
    # 获取线程ID和块ID
    tid = T.thread_idx.x
    bid = T.block_idx.x
    
    # 每个线程加载自己的数据
    for i in T.serial(256):
        local_a[i] = a[bid * 256 + i]
        local_b[i] = b[bid * 256 + i]
    
    # 并行计算
    for i in T.parallel(256):
        local_c[i] = local_a[i] + local_b[i]
    
    # 写回结果
    for i in T.serial(256):
        c[bid * 256 + i] = local_c[i]
    
    return c
```

### 任务并行

```python
@T.prim_func
def task_parallel(input_data):
    # 任务并行：不同任务同时执行
    
    # 创建多个任务
    result1 = T.alloc_buffer((256, 256), "float16")
    result2 = T.alloc_buffer((256, 256), "float16")
    result3 = T.alloc_buffer((256, 256), "float16")
    
    # 并行执行三个独立任务
    with T.task_parallel():
        compute_task1(input_data, result1)
        compute_task2(input_data, result2)
        compute_task3(input_data, result3)
    
    # 合并结果
    return merge_results(result1, result2, result3)
```

### 流水线并行

```python
@T.prim_func
def pipeline_parallel(input_buf, output_buf):
    # 流水线并行： stages 并行执行
    
    # 定义流水线 stages
    stage1_buf = T.alloc_buffer((256,), "float16")
    stage2_buf = T.alloc_buffer((256,), "float16")
    stage3_buf = T.alloc_buffer((256,), "float16")
    
    # Stage 1: 数据加载
    for i in T.pipelined(256, stage=0):
        with T.block("load"):
            stage1_buf[i] = input_buf[i]
    
    # Stage 2: 数据处理
    for i in T.pipelined(256, stage=1):
        with T.block("process"):
            stage2_buf[i] = stage1_buf[i] * 2 + 1
    
    # Stage 3: 结果存储
    for i in T.pipelined(256, stage=2):
        with T.block("store"):
            output_buf[i] = stage3_buf[i]
    
    return output_buf
```

### 内存并行

```python
@T.prim_func
def memory_parallel(a, b, c):
    # 内存并行：计算与数据传输重叠
    
    buf1 = T.alloc_buffer((256,), "float16", scope="shared")
    buf2 = T.alloc_buffer((256,), "float16", scope="shared")
    
    # 使用双缓冲
    for i in T.serial(2):
        if i % 2 == 0:
            # 偶数迭代：加载数据到 buf1
            T.copy(a, buf1)
            # 同时使用 buf2 计算
            compute(buf2, c)
        else:
            # 奇数迭代：加载数据到 buf2
            T.copy(a, buf2)
            # 同时使用 buf1 计算
            compute(buf1, c)
    
    return c
```

## 负载均衡

### 静态负载均衡

```python
@T.prim_func
def static_load_balance(a, b, c):
    # 静态负载均衡：数据均匀分配
    num_threads = 1024
    chunk_size = len(a) // num_threads
    
    for tid in T.parallel(num_threads):
        start = tid * chunk_size
        end = start + chunk_size
        for i in T.serial(start, end):
            c[i] = a[i] + b[i]
```

### 动态负载均衡

```python
@T.prim_func
def dynamic_load_balance(input_data):
    # 动态负载均衡：任务队列
    queue = T.create_task_queue()
    
    # 添加任务
    for i in range(num_chunks):
        queue.add_task(compute_task, i)
    
    # 动态调度
    while not queue.empty():
        # 获取空闲线程
        tid = T.get_idle_thread()
        # 分配任务
        task = queue.pop_task()
        execute(task, tid)
```

### 不规则数据负载均衡

```python
@T.prim_func
def irregular_load_balance(sparse_data):
    # 不规则数据：使用指针跳表
    idx_ptr = sparse_data.indices
    
    for i in T.parallel(sparse_data.nnz):
        # 使用索引指针访问非零元素
        row = idx_ptr[i]
        col = idx_ptr[i + 1]
        value = sparse_data.values[i]
        
        result[row, col] = value * 2
```

## 同步机制

### 屏障同步

```python
@T.prim_func
def barrier_sync(a, b, c):
    # 屏障同步：等待所有线程到达
    
    local_buf = T.alloc_buffer((256,), "float16", scope="shared")
    tid = T.thread_idx.x
    
    # 每个线程计算
    local_buf[tid] = a[tid] * 2
    
    # 屏障：等待所有线程
    T.sync()
    
    # 所有线程继续
    c[tid] = local_buf[tid] + b[tid]
```

### 原子操作

```python
@T.prim_func
def atomic_add(result, indices, values):
    # 原子加法：避免竞争条件
    for i in T.serial(1024):
        idx = indices[i]
        val = values[i]
        
        # 原子操作
        with T.atomic():
            result[idx] = result[idx] + val
```

### 归约操作

```python
@T.prim_func
def reduction(a):
    # 并行归约：求和
    local_sum = T.alloc_buffer((1024,), "float16", scope="shared")
    tid = T.thread_idx.x
    
    # 第一阶段：每个线程计算部分和
    local_sum[tid] = 0
    for i in T.serial(tid * 256, (tid + 1) * 256):
        local_sum[tid] = local_sum[tid] + a[i]
    
    # 同步
    T.sync()
    
    # 第二阶段：树状归约
    for offset in T.serial(512, 1, -1):
        if tid < offset:
            local_sum[tid] = local_sum[tid] + local_sum[tid + offset]
        T.sync()
    
    return local_sum[0]
```

## 性能优化技巧

### 1. 减少分支 divergence

```python
# 不好：线程束分化
@T.prim_func
def branch_heavy(data):
    for i in T.parallel(1024):
        if i % 2 == 0:  # 分支分化
            data[i] = data[i] * 2
        else:
            data[i] = data[i] + 1

# 好：合并分支
@T.prim_func
def branch_optimized(data):
    for i in T.parallel(1024):
        # 无分支计算
        mask = (i % 2 == 0)
        data[i] = data[i] * T.select(mask, 2, 1) + T.select(mask, 0, 1)
```

### 2. 合并内存访问

```python
# 好：合并访问
@T.prim_func
def coalesced(a, b, c):
    tid = T.thread_idx.x
    # 每个线程访问连续内存
    for i in T.serial(4):
        idx = tid * 4 + i
        c[idx] = a[idx] + b[idx]
```

### 3. 使用 Warp 同步

```python
# Warp 级别同步
@T.prim_func
def warp_sync(data):
    tid = T.thread_idx.x
    warp_id = tid // 32
    lane_id = tid % 32
    
    # Warp 内广播
    value = T.shfl(data, warp_id, lane_id)
```

### 4. 避免银行冲突

```python
# 好：避免共享内存银行冲突
@T.prim_func
def bank_conflict_free(data):
    tid = T.thread_idx.x
    bank_id = tid % 32
    
    # 使用 padding 避免冲突
    shared[tid * 2] = data[tid]
    shared[tid * 2 + 1] = data[tid + 512]
```

## 实战案例

### 矩阵向量乘法

```python
@T.prim_func
def matvec(A, x, y):
    # 并行化外层循环
    for i in T.parallel(1024):
        # 归约内层循环
        sum_val = 0.0
        for j in T.serial(1024):
            sum_val = sum_val + A[i, j] * x[j]
        
        y[i] = sum_val
```

### Batch GEMM

```python
@T.prim_func
def batch_gemm(A, B, C, batch_size, M, N, K):
    # Batch 并行
    for b in T.parallel(batch_size):
        # 矩阵乘法
        for i in T.serial(M):
            for j in T.serial(N):
                for k in T.serial(K):
                    C[b, i, j] = C[b, i, j] + A[b, i, k] * B[b, k, j]
```

### 归一化层

```python
@T.prim_func
def layer_norm(x, gamma, beta, y):
    # 并行计算均值和方差
    mean = T.alloc_buffer((1024,), "float16", scope="shared")
    var = T.alloc_buffer((1024,), "float16", "shared")
    
    # 第一步：计算均值
    for i in T.parallel(1024):
        mean[i] = T.reduce_sum(x[i, :], axis=1) / 1024
    
    # 第二步：计算方差
    for i in T.parallel(1024):
        diff = x[i, :] - mean[i]
        var[i] = T.reduce_sum(diff * diff, axis=1) / 1024
    
    # 第三步：归一化
    for i in T.parallel(1024):
        for j in T.serial(1024):
            y[i, j] = (x[i, j] - mean[i]) / T.sqrt(var[i] + 1e-6)
            y[i, j] = y[i, j] * gamma[j] + beta[j]
```

## 性能调优

### 并行度选择

| 计算类型 | 推荐并行度 |
|---------|-----------|
| 向量化操作 | 128-512 |
| 归约操作 | 64-256 |
| 内存密集型 | 256-1024 |
| 计算密集型 | 512-2048 |

### 性能瓶颈分析

```python
# 分析并行效率
analysis = mod.analyze_parallel()

print(f"并行效率: {analysis.parallel_efficiency:.2%}")
print(f"线程利用率: {analysis.thread_utilization:.2%}")
print(f"同步开销: {analysis.sync_overhead:.2%}")
```

## 常见问题

### Q1: 并行效率低？

```python
# 检查：线程束分化
# 解决：使用 T.select 替代 if-else

# 检查：内存访问不连续
# 解决：重排循环顺序

# 检查：同步过多
# 解决：减少 T.sync() 调用
```

### Q2: 如何选择并行粒度？

```python
# 大任务：使用 coarse-grained 并行
for i in T.parallel(16):  # 每个线程处理大块
    process_large_chunk(i)

# 小任务：使用 fine-grained 并行
for i in T.parallel(1024):  # 每个线程处理小数据
    process_small_item(i)
```

### Q3: 死锁怎么办？

```python
# 确保所有线程以相同顺序获取锁
# 避免循环依赖
# 使用超时机制
```

## 最佳实践总结

1. **选择合适的并行粒度**：根据任务特点
2. **最小化同步**：减少 T.sync() 调用
3. **避免分支分化**：使用向量化替代条件
4. **优化内存访问**：合并访问，避免 bank conflict
5. **负载均衡**：均匀分配任务
6. **充分利用硬件**：绑定到正确的线程层级

---

*本文档是 TileLang-Ascend 知识库的一部分*
*最后更新: 2026-02-18*
