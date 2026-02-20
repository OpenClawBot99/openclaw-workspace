# 内存优化最佳实践

> TileLang-Ascend 内存优化深度指南

## 概述

内存优化是 Ascend NPU 编程中最关键的环节之一。本文总结了在 TileLang 中实现高效内存使用的最佳实践，涵盖内存分配策略、数据布局、缓存优化等核心主题。

## 内存优化原则

### 核心原则

1. **最小化内存占用**：按需分配，及时释放
2. **最大化数据复用**：重用中间缓冲区
3. **优化内存布局**：提高缓存命中率
4. **减少数据搬运**：尽量使用片上内存

## 内存分配策略

### 静态分配 vs 动态分配

#### 静态分配

```python
# 编译时确定大小 - 最优性能
@T.prim_func
def static_allocation():
    # 固定大小，编译期优化
    buf = T.alloc_buffer((128, 128), "float16", scope="global")
    
    for i in T.serial(128):
        with T.block("compute"):
            vi = T.axis.spatial(128, i)
            buf[vi] = vi * 2
    return buf
```

#### 动态分配

```python
# 运行时确定大小 - 灵活性高
@T.prim_func
def dynamic_allocation(n: T.int32):
    # 动态大小，需要运行时计算
    buf = T.alloc_buffer((n, n), "float16", scope="global")
    
    for i in T.serial(n):
        with T.block("compute"):
            vi = T.axis.spatial(n, i)
            buf[vi] = vi * 2
    return buf
```

**推荐**：尽量使用静态分配

### 延迟分配

```python
@T.prim_func
def lazy_allocation():
    # 延迟分配 - 按需创建
    with T.allocate(dtype="float32", scope="shared") as buf:
        # 只在需要时分配
        init_buffer(buf)
        result = compute(buf)
    return result
```

## 数据布局优化

### 内存布局类型

| 布局 | 说明 | 适用场景 |
|------|------|---------|
| Row-Major (NCHW) | 行优先存储 | 通用计算 |
| Column-Major | 列优先存储 | 特定数学运算 |
| Block | 分块存储 | 大矩阵运算 |

### 选择合适的布局

```python
@T.prim_func
def nchw_layout(data):
    # NCHW 布局 - 通道优先
    # N: batch, C: channel, H: height, W: width
    
    # 适用场景: 卷积操作
    for n, c, h, w in T.grid(batch, channels, height, width):
        output[n, c, h, w] = data[n, c, h, w] * 2
    return output
```

### 布局转换

```python
@T.prim_func
def layout_transform(input_buf, output_buf):
    # 从 NCHW 转换到 NHWC
    for n, h, w, c in T.grid(N, H, W, C):
        output_buf[n, h, w, c] = input_buf[n, c, h, w]
    return output_buf
```

## 缓存优化

### 缓存友好访问模式

```python
@T.prim_func
def cache_friendly(a, b, c):
    # 缓存友好：按行遍历
    for i in T.serial(1024):
        for j in T.serial(1024):
            # 连续内存访问
            c[i, j] = a[i, j] + b[i, j]
```

### 缓存不友好

```python
@T.prim_func
def cache_unfriendly(a, b, c):
    # 缓存不友好：按列遍历
    for i in T.serial(1024):
        for j in T.serial(1024):
            # 跳跃内存访问
            c[j, i] = a[j, i] + b[j, i]
```

### 循环分块提高缓存命中率

```python
@T.prim_func
def tiled_cache(a, b, c):
    # 分块处理 - 提高缓存命中率
    for ii in T.serial(0, 1024, tile_i=32):
        for jj in T.serial(0, 1024, tile_j=32):
            for i in T.serial(32):
                for j in T.serial(32):
                    # 每次只处理 32x32 块
                    # 充分利用 L1 缓存
                    vi = ii + i
                    vj = jj + j
                    c[vi, vj] = a[vi, vj] + b[vi, vj]
```

## 内存复用模式

### 原地计算

```python
@T.prim_func
def inplace_compute(a, c):
    # 原地计算，复用输入缓冲区
    for i in T.serial(1024):
        with T.block("compute"):
            vi = T.axis.spatial(1024, i)
            # 直接修改输入缓冲区
            a[vi] = a[vi] * 2
    return a
```

### 缓冲区池

```python
@T.prim_func
def buffer_pool(a, b):
    # 创建缓冲区池
    pool = T.create_buffer_pool(size=3)
    
    # 分配临时缓冲区
    temp1 = pool.allocate((256, 256), "float16")
    temp2 = pool.allocate((256, 256), "float16")
    
    # 使用临时缓冲区
    stage1_result = compute_stage1(a, temp1)
    stage2_result = compute_stage2(stage1_result, temp2, b)
    
    # 释放回池
    pool.free(temp1)
    pool.free(temp2)
    
    return stage2_result
```

### 双缓冲

```python
@T.prim_func
def double_buffer(input_buf, output_buf):
    # 双缓冲：计算与加载重叠
    buf1 = T.alloc_buffer((256, 256), "float16")
    buf2 = T.alloc_buffer((256, 256), "float16")
    
    # 阶段1
    copy_to_buffer(input_buf, buf1)
    compute(buf1, output_buf)
    
    # 阶段2 - 重用缓冲区
    copy_to_buffer(input_buf, buf2)  # 加载下一块
    compute(buf2, output_buf)         # 计算当前块
    
    return output_buf
```

## 片上内存优化

### 使用 UB (Unified Buffer)

```python
@T.prim_func
def ub_optimization(a, b, c):
    # 将热点数据放在 UB
    ub_buf = T.alloc_buffer((256, 256), "float16", scope="shared")
    
    # 从 global 加载到 UB
    T.copy(a, ub_buf)
    
    # 在 UB 中计算
    for i in T.serial(256):
        for j in T.serial(256):
            ub_buf[i, j] = ub_buf[i, j] * 2
    
    # 结果写回 global
    T.copy(ub_buf, c)
    
    return c
```

### 寄存器优化

```python
@T.prim_func
def register_opt(a, b):
    # 将频繁访问的数据放在寄存器
    for i in T.serial(1024):
        # 将数据加载到寄存器
        reg_a = a[i]
        reg_b = b[i]
        
        # 多次使用寄存器值
        result1 = reg_a + reg_b
        result2 = reg_a * reg_b
        result3 = reg_a - reg_b
        
        # 写回
        c1[i] = result1
        c2[i] = result2
        c3[i] = result3
    
    return c1, c2, c3
```

## 内存带宽优化

### 合并内存访问

```python
@T.prim_func
def coalesced_access(data, output):
    # 合并访问 - 线程访问连续内存
    tid = T.thread_idx.x
    
    # 每个线程处理连续数据
    start = tid * 32
    for i in T.serial(32):
        output[start + i] = data[start + i] * 2
```

### 向量化内存访问

```python
@T.prim_func
def vectorized_memory(data, output):
    # 向量化加载/存储
    for i in T.serial(1024 // 8):
        with T.block("vec"):
            vi = T.axis.spatial(1024 // 8, i)
            # 一次加载 8 个元素
            vec = T.vectorize(8)
            for j in T.serial(8):
                output[vi * 8 + j] = data[vi * 8 + j] * 2
```

## 内存泄漏检测

### 手动检测

```python
@T.prim_func
def check_memory_leak():
    # 记录初始内存状态
    initial = T.memory_stats()
    
    # 执行计算
    result = compute()
    
    # 检查内存变化
    final = T.memory_stats()
    leaked = final.allocated_bytes - initial.allocated_bytes
    
    if leaked > 0:
        T.print(f"Memory leak detected: {leaked} bytes")
    
    return result
```

### 自动追踪

```python
# 启用内存追踪
with T.memory_trace(enabled=True):
    # 所有内存操作被追踪
    result = compute()

# 查看追踪报告
print(T.memory_trace_report())
# 显示:
# - 分配点
# - 释放点
# - 泄漏可疑点
```

## 性能案例

### GEMM 内存优化

```python
@T.prim_func
def optimized_gemm(
    A: T.Buffer((1024, 1024), "float16"),
    B: T.Buffer((1024, 1024), "float16"),
    C: T.Buffer((1024, 1024), "float16")
):
    # 1. 分配片上缓冲区
    A_local = T.alloc_buffer((128, 128), "float16", scope="shared")
    B_local = T.alloc_buffer((128, 128), "float16", scope="shared")
    C_local = T.alloc_buffer((128, 128), "float16", scope="shared")
    
    # 2. 分块计算
    for ii in T.serial(0, 1024, tile_i=128):
        for jj in T.serial(0, 1024, tile_j=128):
            # 3. 加载数据到片上
            copy_block(A, ii, jj, A_local)
            copy_block(B, ii, jj, B_local)
            
            # 4. 计算
            for kk in T.serial(0, 1024, tile_k=128):
                # 5. 累加计算
                compute_block(A_local, B_local, C_local, kk)
            
            # 6. 写回结果
            copy_block(C_local, ii, jj, C)
    
    return C
```

### 优化效果对比

| 优化策略 | 内存占用 | 带宽使用 | 性能提升 |
|---------|---------|---------|---------|
| 基础实现 | 100% | 40% | 1x |
| UB 优化 | 60% | 70% | 1.5x |
| 双缓冲 | 60% | 85% | 2.0x |
| 完整优化 | 40% | 95% | 3.0x |

## 常见问题

### Q1: 内存不足怎么办？

```python
# 解决方案1：分块处理
@T.prim_func
def chunked_compute():
    # 将大矩阵分成小块
    for chunk_i, chunk_j in T.grid(chunks, chunks):
        process_chunk(chunk_i, chunk_j)
    
    # 解决方案2：使用更小的数据类型
    # float16 代替 float32
    # int8 代替 int32
```

### Q2: 如何选择作用域？

```python
# 规则：
# - 大数据 (>1MB) → global
# - 中等数据 (1KB-1MB) → shared
# - 小数据 (<1KB) → local
```

### Q3: 内存带宽成为瓶颈？

```python
# 解决方案：
# 1. 使用双缓冲重叠计算和数据传输
# 2. 向量化内存访问
# 3. 压缩数据（使用更小的数据类型）
# 4. 重排数据布局提高缓存命中率
```

## 最佳实践总结

1. **预估内存需求**：提前规划，避免动态分配
2. **复用缓冲区**：减少分配/释放开销
3. **使用片上内存**：UB 比 Global 快 5-10 倍
4. **优化数据布局**：选择适合计算的布局
5. **分块处理**：提高缓存命中率
6. **监控内存使用**：开发阶段启用追踪

---

*本文档是 TileLang-Ascend 知识库的一部分*
*最后更新: 2026-02-18*
