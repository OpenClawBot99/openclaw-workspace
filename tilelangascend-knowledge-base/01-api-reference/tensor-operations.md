# TileLang-Ascend API 参考 - 张量操作

> 基于 tilelang-ascend 项目整理

---

## 目录

1. [张量定义](#1-张量定义)
2. [内存分配](#2-内存分配)
3. [数据拷贝](#3-数据拷贝)
4. [计算原语](#4-计算原语)
5. [同步原语](#5-同步原语)
6. [控制流](#6-控制流)

---

## 1. 张量定义

### T.Tensor

**功能描述**：
定义张量数据类型，用于声明 kernel 的输入/输出参数。

**语法**：
```python
T.Tensor(shape, dtype)
```

**参数说明**：
- `shape`: 元组，张量的形状，如 `(M, K)`
- `dtype`: 字符串，数据类型，如 `"float16"`, `"float32"`, `"int32"`

**返回值**：
张量对象，可在 kernel 中使用。

**示例代码**：
```python
@T.prim_func
def main(
    A: T.Tensor((M, K), "float16"),  # 输入矩阵 A
    B: T.Tensor((K, N), "float16"),  # 输入矩阵 B
    C: T.Tensor((M, N), "float16"),  # 输出矩阵 C
):
    # kernel 逻辑
    pass
```

**注意事项**：
- 张量通常位于全局内存（Global Memory）
- 通过 `@jit` 装饰器的 `out_idx` 参数指定输出张量

---

## 2. 内存分配

### T.alloc_L1

**功能描述**：
在 L1 缓存中分配内存空间。

**语法**：
```python
T.alloc_L1(shape, dtype)
```

**参数说明**：
- `shape`: 元组，分配的形状
- `dtype`: 字符串，数据类型

**返回值**：
L1 缓存中的张量对象。

**示例代码**：
```python
# 分配 (128, 64) 的 float16 张量
A_L1 = T.alloc_L1((128, 64), "float16")
```

**注意事项**：
- L1 缓存位于 Cube Core
- 容量有限，需合理规划

---

### T.alloc_L0C

**功能描述**：
在 L0C 缓存中分配内存空间（用于累加）。

**语法**：
```python
T.alloc_L0C(shape, dtype)
```

**参数说明**：
- `shape`: 元组，分配的形状
- `dtype`: 字符串，数据类型（通常为 float）

**返回值**：
L0C 缓存中的张量对象。

**示例代码**：
```python
# 分配累加缓存
C_L0 = T.alloc_L0C((128, 256), "float")
```

**注意事项**：
- L0C 专门用于矩阵乘法累加
- 通常使用 float32 提高精度

---

### T.alloc_ub

**功能描述**：
在 Unified Buffer 中分配内存空间（Vector Core 使用）。

**语法**：
```python
T.alloc_ub(shape, dtype)
```

**参数说明**：
- `shape`: 元组，分配的形状
- `dtype`: 字符串，数据类型

**返回值**：
Unified Buffer 中的张量对象。

**示例代码**：
```python
# 分配 UB 缓存
a_ub = T.alloc_ub((64, 128), "float16")
```

**注意事项**：
- UB 位于 Vector Core
- 用于向量计算

---

## 3. 数据拷贝

### T.copy

**功能描述**：
在不同内存层级之间拷贝数据。

**语法**：
```python
T.copy(src, dst)
```

**参数说明**：
- `src`: 源张量
- `dst`: 目标张量

**示例代码**：
```python
# 从全局内存拷贝到 L1
T.copy(A[bx * block_M, k * K_L1], A_L1)

# 从 L0C 拷贝到全局内存
T.copy(C_L0, C[bx * block_M, by * block_N])
```

**注意事项**：
- 支持跨内存层级拷贝
- 自动处理数据布局转换

---

## 4. 计算原语

### T.gemm_v0

**功能描述**：
执行矩阵乘法（GEMM）。

**语法**：
```python
T.gemm_v0(A, B, C, init=False, transpose_B=False)
```

**参数说明**：
- `A`: 矩阵 A
- `B`: 矩阵 B
- `C`: 结果矩阵 C
- `init`: 布尔值，是否初始化 C（首次计算时为 True）
- `transpose_B`: 布尔值，是否转置 B

**示例代码**：
```python
# 首次计算
T.gemm_v0(A_L1, B_L1, C_L0, init=True)

# 累加计算
for k in range(loop_k):
    T.copy(A[:, k*K_L1], A_L1)
    T.copy(B[k*K_L1, :], B_L1)
    T.gemm_v0(A_L1, B_L1, C_L0)
```

**注意事项**：
- 支持 float16 和 float32
- 使用 Cube Core 进行计算

---

### T.add

**功能描述**：
执行逐元素加法。

**语法**：
```python
T.add(dst, src1, src2)
```

**示例代码**：
```python
# c = a + b
T.add(c_ub, a_ub, b_ub)
```

---

### T.mul

**功能描述**：
执行逐元素乘法。

**语法**：
```python
T.mul(dst, src1, src2)
```

**示例代码**：
```python
# c = a * b
T.mul(c_ub, a_ub, b_ub)
```

---

## 5. 同步原语

### T.barrier_all

**功能描述**：
同步所有执行单元。

**语法**：
```python
T.barrier_all()
```

**示例代码**：
```python
# 拷贝数据
T.copy(A[src], A_L1)
T.copy(B[src], B_L1)

# 同步
T.barrier_all()

# 计算
T.gemm_v0(A_L1, B_L1, C_L0)

# 同步
T.barrier_all()
```

---

### T.set_flag / T.wait_flag

**功能描述**：
设置/等待同步标志（用于流水线）。

**语法**：
```python
T.set_flag(from_unit, to_unit, flag_id)
T.wait_flag(from_unit, to_unit, flag_id)
```

**示例代码**：
```python
# 设置标志
T.set_flag("mte1", "mte2", 0)

# 等待标志
T.wait_flag("mte1", "mte2", 0)
```

---

## 6. 控制流

### T.Kernel

**功能描述**：
定义 kernel 执行上下文。

**语法**：
```python
with T.Kernel(num_blocks, is_npu=True) as (cid, vid):
    # kernel 逻辑
```

**参数说明**：
- `num_blocks`: 整数，并行块数量
- `is_npu`: 布尔值，是否在 NPU 上运行
- `cid`: 块索引
- `vid`: 向量单元索引

**示例代码**：
```python
m_num = M // block_M
n_num = N // block_N

with T.Kernel(m_num * n_num, is_npu=True) as (cid, vid):
    bx = cid // n_num
    by = cid % n_num
    # kernel 逻辑
```

---

### T.Scope

**功能描述**：
定义执行作用域。

**语法**：
```python
with T.Scope(scope_type):
    # 作用域内的操作
```

**参数说明**：
- `scope_type`: 字符串，作用域类型
  - `"C"`: Cube Core
  - `"V"`: Vector Core

**示例代码**：
```python
with T.Scope("C"):
    # Cube Core 操作
    T.gemm_v0(A_L1, B_L1, C_L0)
```

---

### T.serial

**功能描述**：
串行循环。

**语法**：
```python
for i in T.serial(n):
    # 循环体
```

**示例代码**：
```python
for k in T.serial(loop_k):
    T.copy(A[:, k*K_L1], A_L1)
    T.gemm_v0(A_L1, B_L1, C_L0)
```

---

### T.Parallel

**功能描述**：
并行循环。

**语法**：
```python
for i, j in T.Parallel(n, m):
    # 循环体
```

**示例代码**：
```python
# 并行执行加法
for i, j in T.Parallel(block_M, block_N):
    c_ub[i, j] = a_ub[i, j] + b_ub[i, j]
```

---

### T.Pipelined

**功能描述**：
流水线循环。

**语法**：
```python
for k in T.Pipelined(n, num_stages=2):
    # 流水线体
```

**示例代码**：
```python
for k in T.Pipelined(loop_k, num_stages=2):
    T.copy(A[:, k*K_L1], A_L1)
    T.gemm_v0(A_L1, B_L1, C_L0)
```

---

*基于 tilelang-ascend v1.0 整理*
*最后更新：2026-02-15*
