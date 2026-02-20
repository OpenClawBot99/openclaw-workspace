# 内存管理 API

> TileLang-Ascend 内存管理完整指南

## 概述

TileLang-Ascend 提供了丰富的内存管理 API，帮助开发者高效控制 Ascend NPU 的内存使用。本文档详细介绍内存分配、释放、池化和复用等核心 API。

## 内存架构基础

### Ascend NPU 内存层级

```
┌─────────────────────────────────────────┐
│         Global Memory (HBM)             │
│  ┌─────────────────────────────────┐   │
│  │     Unified Buffer (UB)         │   │
│  │  ┌─────────────────────────┐   │   │
│  │  │    Local Memory (LM)    │   │   │
│  │  └─────────────────────────┘   │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

- **HBM (High Bandwidth Memory)**: 设备主内存，容量大但访问延迟高
- **UB (Unified Buffer)**: 统一缓冲，片上内存，用于数据中转
- **LM (Local Memory)**: 本地内存，寄存器级别的高速缓存

## 核心 API

### 1. 内存分配

#### `T.alloc_buffer`

```python
@T.prim_func
def example_alloc(shape, dtype="float16"):
    # 分配指定形状的 Buffer
    buf = T.alloc_buffer(
        shape,          # 形状，如 (128, 128)
        dtype,          # 数据类型，如 "float16"
        scope="global"  # 内存作用域
    )
    return buf
```

**参数说明**：
- `shape`: 元组或列表，指定缓冲区维度
- `dtype`: 字符串，数据类型（float16, float32, int8 等）
- `scope`: 字符串，内存作用域
  - `"global"`: 全局内存（HBM）
  - `"shared"`: 共享内存（UB）
  - `"local"`: 本地内存（LM）

#### `T.allocate`

```python
@T.prim_func
def allocate_example():
    # 在指定作用域分配临时缓冲区
    with T.allocate(dtype="float32", scope="shared") as buf:
        # 在此作用域内使用 buf
        T.evaluate(buf[0].assign(1.0))
    # 离开作用域后自动释放
    return
```

### 2. 内存释放

#### 作用域自动释放

```python
@T.prim_func
def auto_release():
    # 使用 with 语句，自动管理内存生命周期
    with T.allocate(dtype="float16", scope="shared") as temp_buf:
        # 执行计算
        # ...
    # 离开 with 块后自动释放
    return
```

#### 手动释放

```python
@T.prim_func
def manual_release(buf):
    # 释放缓冲区
    T.free(buf)
    return
```

### 3. 内存池管理

#### `T.memory_pool`

```python
# 创建内存池
pool = T.memory_pool(
    max_size=1024 * 1024,  # 最大内存（字节）
    block_size=4096,        # 块大小
    scope="shared"          # 作用域
)

@T.prim_func
def use_pool_example():
    # 从池中分配
    buf = pool.allocate(shape=(256, 256), dtype="float16")
    
    # 使用缓冲区
    # ...
    
    # 释放回池中
    pool.free(buf)
    return
```

### 4. 内存复用

#### `T.buffer_alias`

```python
@T.prim_func
def buffer_reuse(buf_a, buf_b):
    # 让 buf_alias 复用 buf_a 的内存
    buf_alias = T.buffer_alias(buf_a, shape=(64, 64))
    
    # 对 alias 的操作直接影响原缓冲区
    T.evaluate(buf_alias[0, 0].assign(buf_b[0, 0]))
    return
```

#### 共享工作区

```python
@T.prim_func
def workspace_reuse(workspace_size):
    # 声明工作区（用于临时计算）
    T.workspace(workspace_size)
    
    # 在不同计算阶段复用同一工作区
    with T.allocate(dtype="float32", scope="shared") as ws:
        # 第一阶段
        compute_stage1(ws)
        
        # 第二阶段（复用同一空间）
        compute_stage2(ws)
    return
```

## 内存分配策略

### 静态分配

```python
@T.prim_func
def static_allocation():
    # 编译时确定大小
    buf = T.alloc_buffer((128, 128), "float16", scope="global")
    return buf
```

### 动态分配

```python
@T.prim_func
def dynamic_allocation(n: T.int32):
    # 运行时确定大小（需要启发式或调优）
    buf = T.alloc_buffer((n, 128), "float16", scope="global")
    return buf
```

### 自动分配

```python
@T.prim_func
def auto_allocation():
    # 自动推导最优形状
    buf = T.alloc_buffer("auto", "float16")
    return buf
```

## 内存对齐

### 对齐 API

```python
@T.prim_func
def aligned_allocation():
    # 分配对齐的缓冲区（256 字节对齐）
    buf = T.alloc_buffer(
        (128, 128),
        "float16",
        scope="global",
        alignment=256
    )
    return buf
```

### 对齐检查

```python
@T.prim_func
def check_alignment(buf):
    # 获取缓冲区地址
    addr = T.address_of(buf)
    
    # 检查对齐
    is_aligned = T.is_aligned(addr, alignment=256)
    return is_aligned
```

## 内存拷贝

### `T.copy`

```python
@T.prim_func
def copy_example(src, dst):
    # 同步拷贝
    T.copy(src, dst)
    return
```

### 异步拷贝

```python
@T.prim_func
def async_copy_example(src, dst):
    # 异步拷贝（需要流支持）
    with T.stream("compute"):
        T.copy(src, dst)
    return
```

### 跨设备拷贝

```python
@T.prim_func
def cross_device_copy(cpu_buf, npu_buf):
    # CPU 到 NPU
    T.copy(cpu_buf, npu_buf, src_scope="cpu", dst_scope="npu")
    return
```

## 性能优化技巧

### 1. 内存复用

```python
@T.prim_func
def reuse_buffers():
    # 复用同一缓冲区用于不同阶段
    buf = T.alloc_buffer((256, 256), "float16", scope="shared")
    
    with T.evaluate(buf[0, 0].assign(1.0)):
        stage1_result = compute_stage1(buf)
    
    with T.evaluate(buf[0, 0].assign(2.0)):
        stage2_result = compute_stage2(buf)
    
    return stage1_result, stage2_result
```

### 2. 内存预分配

```python
@T.prim_func
def preallocate():
    # 预分配常用缓冲区
    workspace = T.alloc_buffer((1 << 20), "float32", scope="shared")
    
    # 在核心计算前预热
    warmup_workspace(workspace)
    return
```

### 3. 分块内存访问

```python
@T.prim_func
def tiled_access(input_buf, output_buf):
    # 分块处理，优化缓存命中
    for i in T.serial(0, 128, tile_i=32):
        for j in T.serial(0, 128, tile_j=32):
            # 每次处理 32x32 块
            tile = input_buf[i:i+32, j:j+32]
            process_tile(tile, output_buf[i:i+32, j:j+32])
    return
```

## 常见问题

### Q1: 内存分配失败怎么办？

```python
@T.prim_func
def safe_allocation():
    try:
        buf = T.alloc_buffer((1024, 1024), "float16")
    except T.MemoryError as e:
        # 尝试更小的分配
        buf = T.alloc_buffer((512, 512), "float16")
    return buf
```

### Q2: 如何选择内存作用域？

| 场景 | 推荐作用域 | 原因 |
|------|-----------|------|
| 大矩阵运算 | global | 容量大 |
| 中间结果 | shared | 访问快 |
| 寄存器变量 | local | 最快 |

### Q3: 内存泄漏如何排查？

1. 使用 `T.memory_stats()` 查看内存使用
2. 检查所有 `allocate` 是否有对应的 `free`
3. 确保 `with T.allocate()` 正确嵌套

## 内存调试 API

### `T.memory_stats`

```python
@T.prim_func
def check_memory():
    stats = T.memory_stats()
    # stats 包含:
    # - allocated_bytes: 当前分配
    # - peak_bytes: 峰值使用
    # - freed_bytes: 已释放
    return stats
```

### `T.memory_trace`

```python
# 启用内存追踪
with T.memory_trace(enabled=True):
    # 所有内存操作将被记录
    result = compute()
```

## 最佳实践总结

1. **尽量复用缓冲区**：减少分配/释放开销
2. **合理选择作用域**：根据数据大小和访问模式
3. **使用对齐**：提高内存访问效率
4. **注意生命周期**：避免过早释放或泄漏
5. **启用追踪**：开发阶段使用 `memory_trace`

---

*本文档是 TileLang-Ascend 知识库的一部分*
*最后更新: 2026-02-18*
