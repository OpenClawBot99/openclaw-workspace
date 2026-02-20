# 核函数 API

> TileLang-Ascend 核函数定义与调用完整指南

## 概述

核函数（Kernel Function）是 TileLang-Ascend 中的核心计算单元。本文详细介绍核函数的定义、配置、调用和优化方法。

## 核函数基础

### 什么是核函数？

核函数是 TileLang 中用于执行具体计算逻辑的函数。它封装了计算操作，可以被调度到不同的计算单元上执行。

```python
@T.prim_func
def kernel_example(a: T.Buffer((128, 128), "float16"), 
                   b: T.Buffer((128, 128), "float16"),
                   c: T.Buffer((128, 128), "float16")):
    """简单的向量加法核函数"""
    for i in T.serial(128):
        for j in T.serial(128):
            with T.block("compute"):
                vi = T.axis.spatial(128, i)
                vj = T.axis.spatial(128, j)
                c[vi, vj] = a[vi, vj] + b[vi, vj]
```

## 核函数定义

### 基本结构

```python
@T.prim_func
def my_kernel(
    input_buf: T.Buffer(shape, dtype),
    output_buf: T.Buffer(shape, dtype)
):
    """核函数主体"""
    # 计算逻辑
    for i in T.serial(n):
        with T.block("block_name"):
            # 块内计算
            vi = T.axis.spatial(n, i)
            output_buf[vi] = input_buf[vi] * 2
```

### 参数类型

| 参数类型 | 说明 | 示例 |
|---------|------|------|
| T.Buffer | 缓冲区 | `T.Buffer((128, 128), "float16")` |
| T.Tensor | 张量 | `T.Tensor((None, 128), "float16")` |
| T.int32/int64 | 标量 | `n: T.int32` |

## 核函数装饰器

### `@T.prim_func`

基础装饰器，定义一个原语函数：

```python
@T.prim_func
def basic_kernel(a, b, c):
    # 函数体
    pass
```

### `@jit`

即时编译装饰器，自动触发编译：

```python
@T.jit
def jit_kernel(a, b):
    # 编译时优化
    return a + b
```

### `@T.kernel`

专用核函数装饰器：

```python
@T.kernel
def vector_add(a: T.Buffer((1024,), "float16"),
               b: T.Buffer((1024,), "float16"),
               c: T.Buffer((1024,), "float16")):
    # 自动处理并行化
    for i in T.Parallel(1024):
        c[i] = a[i] + b[i]
```

## 块结构

### T.block

```python
@T.prim_func
def block_example(a, b, c):
    for i in T.serial(128):
        for j in T.serial(128):
            with T.block("compute"):  # 定义计算块
                vi = T.axis.spatial(128, i)
                vj = T.axis.spatial(128, j)
                c[vi, vj] = a[vi, vj] + b[vi, vj]
```

### 块属性

```python
with T.block("compute") as [vi, vj]:
    # 可以访问块迭代变量
    c[vi, vj] = a[vi, vj] + b[vi, vj]
```

## 轴定义

### 空间轴 (Spatial Axis)

```python
@T.prim_func
def spatial_axis_example(c):
    for i in T.serial(128):
        with T.block("compute"):
            vi = T.axis.spatial(128, i)  # 空间轴
            c[vi] = vi * 2
```

### 归约轴 (Reduction Axis)

```python
@T.prim_func
def reduction_axis_example(a, b, c):
    for i in T.serial(128):
        with T.block("reduce"):
            vi = T.axis.spatial(128, i)
            # 归约轴
            for k in T.serial(128):
                with T.block("inner"):
                    vk = T.axis.reduce(128, k)
                    c[vi] = c[vi] + a[vi, vk] * b[vk, vi]
```

### 压缩轴 (Squeezed Axis)

```python
@T.prim_func
def squeezed_axis_example(a):
    # 广播操作使用压缩轴
    for i in T.serial(128):
        with T.block("broadcast"):
            vi = T.axis.spatial(128, i)
            vk = T.axis.squeeze  # 压缩轴
            a[vi] = a[vk]  # 广播标量
```

## 并行化配置

### `T.serial`

串行执行：

```python
for i in T.serial(100):  # 顺序执行
    process(i)
```

### `T.parallel`

并行执行：

```python
for i in T.parallel(100):  # 并行执行
    result[i] = input[i] * 2
```

### `T.unroll`

展开循环：

```python
for i in T.unroll(8):  # 完全展开
    result[i] = input[i] * 2
```

### `T.vectorize`

向量化：

```python
for i in T.serial(128):
    with T.block("vec"):
        vi = T.axis.spatial(128, i)
        # 向量化加载
        vec = T.vectorize(8)
        for j in T.serial(8):
            result[vi*8+j] = input[vi*8+j] * 2
```

## 流水线调度

### `T.pipelined`

```python
@T.prim_func
def pipelined_kernel(a, b, c):
    for i in T.pipelined(128, stage=1):  # 流水线阶段
        with T.block("compute"):
            vi = T.axis.spatial(128, i)
            # 计算逻辑
            c[vi] = a[vi] + b[vi]
```

### 多阶段流水线

```python
@T.prim_func
def multi_stage_pipeline(input_buf, output_buf):
    # 阶段 0: 加载
    for i in T.pipelined(128, stage=0):
        with T.block("load"):
            load_data(input_buf[i])
    
    # 阶段 1: 计算
    for i in T.pipelined(128, stage=1):
        with T.block("compute"):
            compute_data()
    
    # 阶段 2: 存储
    for i in T.pipelined(128, stage=2):
        with T.block("store"):
            store_data(output_buf[i])
```

## 核函数调用

### 同步调用

```python
# 定义核函数
@T.prim_func
def my_kernel(a, b, c):
    # ...
    return

# 同步调用
result = my_kernel(input_a, input_b, output_c)
```

### 异步调用

```python
# 异步调用（需要流）
with T.stream("compute"):
    my_kernel(input_a, input_b, output_c)
# 不等待完成，继续执行
```

### 批量调用

```python
# 批量执行
results = T.batch(my_kernel)(
    [(a1, b1, c1), (a2, b2, c2), ...]
)
```

## 核函数参数

### Buffer 参数

```python
@T.prim_func
def buffer_kernel(
    a: T.Buffer((128, 128), "float16"),  # 只读
    b: T.Buffer((128, 128), "float16", "rw"),  # 读写
):
    # a 是只读，b 是读写
    pass
```

### Tensor 参数

```python
@T.prim_func
def tensor_kernel(
    a: T.Tensor((None, 128), "float16"),  # 动态形状
    b: T.Tensor((128, 128), "float16"),   # 静态形状
):
    # 处理不同形状的张量
    pass
```

### 可选参数

```python
@T.prim_func
def optional_kernel(
    a,
    b,
    c=None,  # 可选参数
    config=None  # 配置对象
):
    if c is not None:
        # 使用 c
        pass
    return
```

## 性能优化

### 1. 循环分块

```python
@T.prim_func
def tiled_kernel(a, b, c):
    # 分块处理，提高缓存命中率
    for i in T.serial(0, 128, tile_i=32):
        for j in T.serial(0, 128, tile_j=32):
            for ii in T.serial(32):
                for jj in T.serial(32):
                    vi = i + ii
                    vj = j + jj
                    c[vi, vj] = a[vi, vj] + b[vi, vj]
```

### 2. 内存访问优化

```python
@T.prim_func
def optimized_kernel(a, b, c):
    # 连续内存访问
    for i in T.serial(128):
        for j in T.serial(128):
            # 按行访问，连续
            c[i, j] = a[i, j] + b[i, j]
```

### 3. 寄存器复用

```python
@T.prim_func
def register_reuse(a, b, c):
    for i in T.serial(128):
        # 加载到寄存器
        temp = a[i]
        temp = temp * b[i]
        # 复用寄存器
        c[i] = temp + 1
```

## 核函数变体

### 变体1: GEMM 核函数

```python
@T.prim_func
def gemm_kernel(
    a: T.Buffer((M, K), "float16"),
    b: T.Buffer((K, N), "float16"),
    c: T.Buffer((M, N), "float16"),
    trans_a: T.int32 = 0,
    trans_b: T.int32 = 0
):
    for i in T.serial(M):
        for j in T.serial(N):
            with T.block("gemm"):
                vi = T.axis.spatial(M, i)
                vj = T.axis.spatial(N, j)
                c[vi, vj] = 0
                for k in T.serial(K):
                    with T.block("reduce"):
                        vk = T.axis.reduce(K, k)
                        if trans_a == 0 and trans_b == 0:
                            c[vi, vj] = c[vi, vj] + a[vi, vk] * b[vk, vj]
```

### 变体2: 卷积核函数

```python
@T.prim_func
def conv2d_kernel(
    input: T.Buffer((N, C, H, W), "float16"),
    weight: T.Buffer((K, C, R, S), "float16"),
    output: T.Buffer((N, K, Ho, Wo), "float16")
):
    for n in T.serial(N):
        for k in T.serial(K):
            for ho in T.serial(Ho):
                for wo in T.serial(W T.block("convo):
                    with"):
                        vn = T.axis.spatial(N, n)
                        vk = T.axis.spatial(K, k)
                        vho = T.axis.spatial(Ho, ho)
                        vwo = T.axis.spatial(Wo, wo)
                        
                        output[vn, vk, vho, vwo] = 0
                        for c in T.serial(C):
                            for r in T.serial(R):
                                for s in T.serial(S):
                                    with T.block("inner"):
                                        vc = T.axis.reduce(C, c)
                                        vr = T.axis.reduce(R, r)
                                        vs = T.axis.reduce(S, s)
                                        output[vn, vk, vho, vwo] += (
                                            input[vn, vc, vho + vr, vwo + vs] *
                                            weight[vk, vc, vr, vs]
                                        )
```

## 调试技巧

### 打印调试

```python
@T.prim_func
def debug_kernel(a, b):
    for i in T.serial(10):
        with T.block("debug"):
            vi = T.axis.spatial(10, i)
            # 打印值
            T.print(vi, a[vi], b[vi])
            b[vi] = a[vi] * 2
```

### 断点调试

```python
@T.prim_func
def breakpoint_kernel(a):
    # 设置断点
    T.break_point()
    result = a * 2
    return result
```

## 常见错误

### 1. 轴范围不匹配

```python
# 错误
for i in T.serial(100):
    with T.block("compute"):
        vi = T.axis.spatial(50, i)  # 范围不匹配!
        
# 正确
for i in T.serial(50):
    with T.block("compute"):
        vi = T.axis.spatial(50, i)
```

### 2. 缓冲区形状不匹配

```python
# 错误
@T.prim_func
def shape_mismatch(a, b):
    # a 是 (100,)，b 是 (50,)
    c = a[0] + b[0]  # 形状冲突

# 正确
@T.prim_func
def shape_match(a, b):
    c = T.alloc_buffer((100,), "float16")
    for i in T.serial(100):
        c[i] = a[i] + b[i]
```

## 最佳实践

1. **明确轴类型**：空间轴、归约轴、压缩轴要分清
2. **合理使用并行**：不要过度并行化
3. **优化内存访问**：优先连续访问
4. **流水线化**：重叠计算和数据移动
5. **模块化设计**：复杂核函数拆分成小模块

---

*本文档是 TileLang-Ascend 知识库的一部分*
*最后更新: 2026-02-18*
