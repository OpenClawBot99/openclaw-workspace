# TileLang-Ascend 完整教科书

> 基于官方文档系统整理 | 最后更新：2026-02-15

---

## 目录结构

### 第一部分：基础篇
1. [TileLang-Ascend 简介](#1-tilelang-ascend-简介)
2. [编程模型概述](#2-编程模型概述)
3. [开发环境搭建](#3-开发环境搭建)
4. [第一个 TileLang 程序](#4-第一个-tilelang-程序)

### 第二部分：核心语法
5. [Kernel 定义与编译](#5-kernel-定义与编译)
6. [数据类型与符号变量](#6-数据类型与符号变量)
7. [控制流与循环](#7-控制流与循环)
8. [内存层级与分配](#8-内存层级与分配)
9. [数据搬运原语](#9-数据搬运原语)
10. [计算原语](#10-计算原语)

### 第三部分：高级特性
11. [Developer 模式编程](#11-developer-模式编程)
12. [Expert 模式编程](#12-expert-模式编程)
13. [流水线优化（T.Pipelined）](#13-流水线优化tpipelined)
14. [并行计算（T.Parallel）](#14-并行计算tparallel)
15. [持久化调度（T.Persistent）](#15-持久化调度tpersistent)

### 第四部分：性能优化
16. [内存布局与缓存优化](#16-内存布局与缓存优化)
17. [流水线并行技术](#17-流水线并行技术)
18. [自动调优策略](#18-自动调优策略)
19. [性能分析与调试](#19-性能分析与调试)

### 第五部分：实战案例
20. [矩阵乘法（GEMM）](#20-矩阵乘法gemm)
21. [Flash Attention](#21-flash-attention)
22. [Layer Normalization](#22-layer-normalization)
23. [激活函数](#23-激活函数)
24. [稀疏注意力](#24-稀疏注意力)

### 第六部分：附录
25. [API 快速参考](#25-api-快速参考)
26. [常见问题解答](#26-常见问题解答)
27. [性能调优指南](#27-性能调优指南)
28. [错误排查手册](#28-错误排查手册)

---

# 第一部分：基础篇

## 1. TileLang-Ascend 简介

### 1.1 什么是 TileLang-Ascend？

**TileLang-Ascend** 是一种专为华为昇腾 NPU（Neural Processing Unit）优化的领域特定语言（DSL），基于 **TVM 编译器基础设施**构建。

#### 核心特性

| 特性 | 描述 |
|------|------|
| **Python 语法** | 简洁易用，降低学习门槛 |
| **Tile 级抽象** | 基于数据块的高级编程模型 |
| **显式控制** | 直接控制内存分配、数据移动和并行执行 |
| **跨平台** | 支持 GPU、CPU、NPU 多种硬件后端 |
| **高性能** | 自动优化与手动调优相结合 |

#### 1.1.1 设计理念

TileLang 采用 **Tile（数据块）** 作为核心抽象单位：

```
大张量 → 切分为 Tile → 并行处理 → 高效执行
```

**优势**：
- ✅ 充分利用片上高速存储（L1, UB）
- ✅ 减少全局内存访问次数
- ✅ 支持细粒度并行计算

### 1.2 与传统编程方式对比

| 对比项 | 传统 CUDA/AscendC | TileLang-Ascend |
|--------|-------------------|-----------------|
| **编程难度** | 高（需深入理解硬件） | 中（Python语法 + Tile抽象） |
| **性能** | 极高（手动优化） | 高（自动优化 + 手动调优） |
| **可移植性** | 低（架构绑定） | 高（多后端支持） |
| **开发效率** | 低（大量底层代码） | 高（简洁的高级表达） |

### 1.3 编译与执行流程

```
┌─────────────────────────────────────────────────────────────┐
│                    TileLang 编译流程                          │
└─────────────────────────────────────────────────────────────┘

1. Tile Program (Python)
   ↓
2. IRModule (TVM IR)
   ↓
3. Lower Passes (多轮优化)
   ↓
4. AscendC Code Generation
   ↓
5. Bisheng Compiler → 动态库 (.so)
   ↓
6. Runtime Loading & Execution
```

**关键组件**：
- **JIT 编译器**：动态编译与优化
- **Ascend Codegen**：生成 AscendC 代码
- **毕昇编译器**：编译为 NPU 可执行文件
- **运行时库**：加载和执行算子

---

## 2. 编程模型概述

### 2.1 三层编程接口

TileLang 提供三种编程抽象层级：

#### Level 1: Beginner (Hardware-Unaware) ⚠️

- **目标**：不依赖硬件细节的编程
- **状态**：当前尚未完全实现
- **适用场景**：快速原型开发

#### Level 2: Developer (Hardware-Aware with Tile Library) ✅

- **目标**：提供预优化的 Tile 库
- **特点**：
  - 无需关注底层线程细节
  - 使用 `T.alloc_shared`, `T.alloc_fragment` 等抽象原语
  - 编译器自动映射到具体存储层级
- **适用场景**：大多数算子开发

#### Level 3: Expert (Hardware-Aware with Thread Primitives) ✅

- **目标**：底层硬件完全控制
- **特点**：
  - 直接使用 `T.alloc_L1`, `T.alloc_ub` 等具体原语
  - 手动控制同步、寄存器分配
  - 追求极致性能
- **适用场景**：性能关键算子

### 2.2 混合编程

**Developer 和 Expert 模式可以在同一 kernel 中混合使用**：

```python
@T.prim_func
def hybrid_kernel(...):
    # Developer 模式
    A_shared = T.alloc_shared((block_M, block_K), dtype)
    
    # Expert 模式
    A_L1 = T.alloc_L1((block_M, block_K), dtype)
    
    # 混合使用
    T.copy(A_shared, A_L1)
```

---

## 3. 开发环境搭建

### 3.1 系统要求

| 组件 | 版本要求 |
|------|----------|
| **CANN** | ≥ 8.3.RC1 |
| **torch-npu** | ≥ 2.6.0.RC1 |
| **Python** | ≥ 3.8 |
| **GCC** | ≥ 7.3.0 |

### 3.2 安装步骤

```bash
# 1. 设置 CANN 环境变量
source {your-cann-path}/ascend-toolkit/set_env.sh

# 2. 克隆仓库
git clone --recursive https://github.com/tile-ai/tilelang-ascend.git
cd tilelang-ascend

# 3. 编译安装
bash install_ascend.sh

# 4. 设置环境变量
source set_env.sh

# 5. 验证安装
cd examples/gemm
python example_gemm.py
# 输出: Kernel Output Match!
```

### 3.3 目录结构

```
tilelang-ascend/
├── tilelang/              # 核心库
│   ├── language/          # 语言定义
│   ├── jit/               # JIT 编译器
│   ├── carver/            # 自动调优
│   └── transform/         # IR 变换
├── docs/                  # 文档
├── examples/              # 示例代码
└── testing/               # 测试用例
```

---

## 4. 第一个 TileLang 程序

### 4.1 向量加法示例

```python
import tilelang
import tilelang.language as T
from tilelang import jit
import torch

# 配置自动优化
pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_AUTO_SYNC: True,
    tilelang.PassConfigKey.TL_ASCEND_MEMORY_PLANNING: True,
}

# 参数定义
M, N = 1024, 1024
block_M, block_N = 128, 128
VEC_NUM = 2  # Vector Core 数量

@jit(out_idx=[-1], pass_configs=pass_configs)
def tile_add(M: int, N: int, block_M: int, block_N: int, dtype: str = 'float16'):
    m_num = M // block_M
    n_num = N // block_N

    @T.prim_func
    def add_kernel(
        A: T.Tensor((M, N), dtype),  # 输入 A
        B: T.Tensor((M, N), dtype),  # 输入 B
        C: T.Tensor((M, N), dtype),  # 输出 C
    ):
        with T.Kernel(m_num * n_num, is_npu=True) as (cid, vid):
            # 计算块索引
            bx = cid // n_num
            by = cid % n_num

            # 分配 UB 缓存
            a_ub = T.alloc_shared((block_M // VEC_NUM, block_N), dtype)
            b_ub = T.alloc_shared((block_M // VEC_NUM, block_N), dtype)
            c_ub = T.alloc_shared((block_M // VEC_NUM, block_N), dtype)
            
            # 拷贝数据
            T.copy(A[bx * block_M + vid * block_M // VEC_NUM, by * block_N], a_ub)
            T.copy(B[bx * block_M + vid * block_M // VEC_NUM, by * block_N], b_ub)

            # 并行计算
            for i, j in T.Parallel(block_M // VEC_NUM, block_N):
                c_ub[i, j] = a_ub[i, j] + b_ub[i, j]

            # 拷贝结果
            T.copy(c_ub, C[bx * block_M + vid * block_M // VEC_NUM, by * block_N])

    return add_kernel

# 实例化 kernel
func = tile_add(M, N, block_M, block_N)

# 准备数据
torch.manual_seed(0)
a = torch.randn(M, N).half().npu()
b = torch.randn(M, N).half().npu()

# 执行 kernel
c = func(a, b)

# 验证结果
ref_c = a + b
torch.testing.assert_close(c, ref_c, rtol=1e-2, atol=1e-2)
print("Kernel Output Match!")
```

### 4.2 代码解析

#### 4.2.1 核心组件

| 组件 | 作用 |
|------|------|
| `@jit` | 触发 JIT 编译 |
| `@T.prim_func` | 定义 kernel 函数 |
| `T.Tensor` | 声明张量参数 |
| `T.Kernel` | 定义执行上下文 |
| `T.alloc_shared` | 分配片上存储 |
| `T.copy` | 数据搬运 |
| `T.Parallel` | 并行计算 |

#### 4.2.2 执行流程

```
1. @jit 触发编译
   ↓
2. 解析 @T.prim_func
   ↓
3. 生成 TensorIR
   ↓
4. 优化和 Lowering
   ↓
5. 生成 AscendC 代码
   ↓
6. 编译为 .so 文件
   ↓
7. 加载并执行
```

#### 4.2.3 数据切分

```
原始数据 (M, N) = (1024, 1024)
        ↓ 切分
Tile 块 (block_M, block_N) = (128, 128)
        ↓ 数量
Tile 数量 = m_num * n_num = 8 * 8 = 64

每个 Tile 由 2 个 Vector Core 并行处理
```

---

# 第二部分：核心语法

## 5. Kernel 定义与编译

### 5.1 @T.prim_func 装饰器

**作用**：定义 TileLang kernel 函数。

```python
@T.prim_func
def kernel_name(
    input1: T.Tensor(shape, dtype),
    input2: T.Tensor(shape, dtype),
    output: T.Tensor(shape, dtype),
):
    # kernel 逻辑
    pass
```

### 5.2 @jit 装饰器

**作用**：触发即时编译。

```python
@tilelang.jit(
    out_idx=[-1],           # 输出参数索引
    pass_configs={...},     # 编译配置
    workspace_idx=[4,5],    # 工作空间索引
)
```

**参数说明**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `out_idx` | List[int] | 输出参数在参数列表中的索引 |
| `pass_configs` | Dict | 编译优化配置 |
| `workspace_idx` | List[int] | 自动分配工作空间的索引 |

**常用 pass_configs**：

```python
pass_configs = {
    # 自动同步插入
    tilelang.PassConfigKey.TL_ASCEND_AUTO_SYNC: True,
    
    # 自动内存规划
    tilelang.PassConfigKey.TL_ASCEND_MEMORY_PLANNING: True,
    
    # CV 自动分离
    tilelang.PassConfigKey.TL_ASCEND_AUTO_CV_COMBINE: True,
    
    # CV 间自动同步
    tilelang.PassConfigKey.TL_ASCEND_AUTO_CV_SYNC: True,
}
```

### 5.3 符号变量

支持动态形状编程：

#### 方式 1: T.dyn[]

```python
K = T.dyn['K']  # 声明符号变量

@T.prim_func
def foo(A: T.Tensor((K,), 'float32')):
    N = A.shape[0]  # 从 shape 获取
    for i in T.serial(N):
        ...
```

#### 方式 2: T.dynamic()

```python
K = T.dynamic('K', 'int32')  # 直接创建 tir.Var

@T.prim_func
def bar(A: T.Tensor((K,), 'float32')):
    for i in T.serial(K):  # 直接使用
        ...
```

---

## 6. 数据类型与符号变量

### 6.1 支持的数据类型

| 类型 | 说明 | 示例 |
|------|------|------|
| `float16` | 半精度浮点 | `T.Tensor((M, K), "float16")` |
| `float32` | 单精度浮点 | `T.Tensor((M, K), "float32")` |
| `bfloat16` | Brain Float | `T.Tensor((M, K), "bfloat16")` |
| `int8` | 8位整数 | `T.Tensor((M, K), "int8")` |
| `int32` | 32位整数 | `T.Tensor((M, K), "int32")` |

### 6.2 类型转换

```python
# 显式转换
x_float = T.cast(x_int, "float32")

# 自动推导
y = x + 0.5  # 自动转换为 float
```

---

## 7. 控制流与循环

### 7.1 串行循环（T.serial）

```python
# 基础用法
for i in T.serial(N):
    ...

# 带步长
for i in T.serial(0, N, 2):  # 0, 2, 4, ...
    ...
```

### 7.2 并行循环（T.Parallel）

```python
# 1D 并行
for i in T.Parallel(N):
    c[i] = a[i] + b[i]

# 2D 并行
for i, j in T.Parallel(M, N):
    c[i, j] = a[i, j] + b[i, j]
```

**特点**：
- ✅ 元素级并行
- ✅ 自动向量化
- ✅ 支持广播机制

### 7.3 流水线循环（T.Pipelined）

```python
for k in T.Pipelined(loop_k, num_stages=2):
    T.copy(A[k], A_L1)      # Stage 1
    T.gemm_v0(A_L1, B, C)   # Stage 2
```

**时间线**：
```
Time | Copy | Compute
-----|------|--------
t₀   | A₀   |
t₁   | A₁   |
t₂   | A₂   | C₀
t₃   | A₃   | C₁
t₄   |      | C₂
t₅   |      | C₃
```

### 7.4 持久化循环（T.Persistent）

```python
for bx, by in T.Persistent(
    [T.ceildiv(M, block_M), T.ceildiv(N, block_N)],
    core_num, cid
):
    # 负载均衡调度
    ...
```

**优势**：
- ✅ 更好的缓存命中率
- ✅ 负载均衡

### 7.5 条件语句

```python
# if-elif-else
if condition:
    ...
elif another_condition:
    ...
else:
    ...

# 三元表达式
x = (A[i] if i < N else 0)
```

### 7.6 While 循环

```python
i = 0
while i < N:
    ...
    if done:
        break
    i += 1
```

---

## 8. 内存层级与分配

### 8.1 Ascend NPU 内存架构

```
┌─────────────────────────────────────────────────────────┐
│                   Global Memory (HBM)                    │
│                      大容量，慢速                          │
└───────────────────────┬─────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
┌───────────────────┐           ┌───────────────────┐
│   L1 Buffer       │           │  Unified Buffer   │
│  (Cube Core)      │           │  (Vector Core)    │
│   中容量，快速      │           │   中容量，快速      │
└─────────┬─────────┘           └─────────┬─────────┘
          │                               │
    ┌─────┴─────┐                         │
    ▼           ▼                         ▼
┌────────┐  ┌────────┐              ┌────────┐
│  L0A   │  │  L0B   │              │   UB   │
│ Buffer │  │ Buffer │              │        │
└────┬───┘  └────┬───┘              └────┬───┘
     │           │                       │
     └─────┬─────┘                       │
           ▼                             │
    ┌────────────┐                        │
    │   L0C      │                        │
    │  Buffer    │                        │
    │ (累加器)    │                        │
    └────────────┘                        │
```

### 8.2 Developer 模式内存分配

#### 8.2.1 T.alloc_shared

**用途**：分配片上共享存储（L1 或 UB，编译器自动选择）。

```python
# 语法
buffer = T.alloc_shared(shape, dtype)

# 示例
A_shared = T.alloc_shared((block_M, block_K), "float16")
```

#### 8.2.2 T.alloc_fragment

**用途**：分配寄存器级存储（L0A/L0B/L0C，编译器自动选择）。

```python
# 语法
buffer = T.alloc_fragment(shape, dtype, scope='local.fragment')

# 示例
C_frag = T.alloc_fragment((block_M, block_N), "float")
```

### 8.3 Expert 模式内存分配

#### 8.3.1 T.alloc_L1

```python
A_L1 = T.alloc_L1((block_M, block_K), "float16")
```

#### 8.3.2 T.alloc_ub

```python
a_ub = T.alloc_ub((block_M, block_N), "float16")
```

#### 8.3.3 T.alloc_L0A / T.alloc_L0B

```python
A_L0 = T.alloc_L0A((block_M, block_K), "float16")
B_L0 = T.alloc_L0B((block_K, block_N), "float16")
```

#### 8.3.4 T.alloc_L0C

```python
C_L0 = T.alloc_L0C((block_M, block_N), "float")
```

### 8.4 内存分配最佳实践

| 场景 | 推荐原语 | 说明 |
|------|----------|------|
| 通用开发 | `T.alloc_shared` | 编译器自动优化 |
| 矩阵乘累加 | `T.alloc_fragment` | 高效累加 |
| 极致性能 | `T.alloc_L1/L0A/L0B/L0C` | 完全控制 |

---

## 9. 数据搬运原语

### 9.1 T.copy

**语法**：
```python
T.copy(src, dst)
```

**支持的数据搬运路径**：

| 源 | 目标 | 说明 |
|----|------|------|
| GM | L1 | Global Memory → L1 Buffer |
| GM | UB | Global Memory → Unified Buffer |
| L1 | L0A | L1 Buffer → L0A Buffer |
| L1 | L0B | L1 Buffer → L0B Buffer |
| L0C | GM | L0C Buffer → Global Memory |
| UB | GM | Unified Buffer → Global Memory |
| UB | UB | Unified Buffer 内部拷贝 |
| UB | L1 | Unified Buffer → L1 Buffer |

**示例**：

```python
# GM → L1
T.copy(A[bx * block_M, k * K_L1], A_L1)

# L0C → GM
T.copy(C_L0, C[bx * block_M, by * block_N])

# GM → UB
T.copy(A[cid, :], a_ub)
```

---

## 10. 计算原语

### 10.1 矩阵计算

#### 10.1.1 T.gemm_v0

**语法**：
```python
T.gemm_v0(A, B, C, transpose_A=False, transpose_B=False, init=False)
```

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `A` | Buffer | 左矩阵 |
| `B` | Buffer | 右矩阵 |
| `C` | Buffer | 结果矩阵 |
| `transpose_A` | bool | 是否转置 A |
| `transpose_B` | bool | 是否转置 B |
| `init` | bool | 是否初始化 C（首次为 True） |

**语义**：
```python
C += A @ B  # 或 C = A @ B if init=True
```

**示例**：

```python
# 首次计算
T.gemm_v0(A_L1, B_L1, C_L0, init=True)

# 累加计算
for k in T.serial(loop_k):
    T.copy(A[:, k*K_L1], A_L1)
    T.copy(B[k*K_L1, :], B_L1)
    T.gemm_v0(A_L1, B_L1, C_L0)  # 自动累加
```

### 10.2 Reduce 类操作

#### 10.2.1 T.reduce_sum

```python
T.reduce_sum(buffer, out, tmp, dim=-1)
```

**示例**：
```python
tmp_ub = T.alloc_ub([3 * DataType(accum_dtype).bits // 8 * block_M // 2 * block_N], "uint8")
T.reduce_sum(acc_s_ub, sumexp_i_ub, tmp_ub, dim=-1)
```

#### 10.2.2 T.reduce_max / T.reduce_min

```python
T.reduce_max(buffer, out, tmp, dim=-1)
T.reduce_min(buffer, out, tmp, dim=-1)
```

### 10.3 Element-wise 操作

#### 10.3.1 基础算术

| 操作 | 表达式 | 说明 |
|------|--------|------|
| 加法 | `a + b` | 逐元素相加 |
| 减法 | `a - b` | 逐元素相减 |
| 乘法 | `a * b` | 逐元素相乘 |
| 除法 | `a / b` | 逐元素相除 |
| 最大值 | `T.max(a, b)` | 逐元素最大值 |
| 最小值 | `T.min(a, b)` | 逐元素最小值 |

#### 10.3.2 数学函数

| 函数 | 表达式 | 说明 |
|------|--------|------|
| 绝对值 | `T.abs(x)` | `|x|` |
| 指数 | `T.exp(x)` | `e^x` |
| 对数 | `T.log(x)` | `ln(x)` |
| 平方根 | `T.sqrt(x)` | `√x` |
| 平方根倒数 | `T.rsqrt(x)` | `1/√x` |

---

# 第三部分：高级特性

## 11. Developer 模式编程

### 11.1 核心原语

#### 11.1.1 内存分配

```python
# Shared 层级（自动映射到 L1 或 UB）
A_shared = T.alloc_shared((block_M, block_K), "float16")

# Fragment 层级（自动映射到 L0A/L0B/L0C）
C_frag = T.alloc_fragment((block_M, block_N), "float")
```

#### 11.1.2 数据搬运

```python
T.copy(A[src], A_shared)  # 自动处理数据布局
```

#### 11.1.3 计算

```python
# 矩阵乘法
T.gemm_v0(A_shared, B_shared, C_frag)

# Reduce 操作
T.reduce_sum(buffer, out, tmp, dim=-1)
```

### 11.2 调度原语

#### 11.2.1 T.Parallel

详见 [第 14 章](#14-并行计算tparallel)

#### 11.2.2 T.Pipelined

详见 [第 13 章](#13-流水线优化tpipelined)

#### 11.2.3 T.Persistent

```python
for bx, by in T.Persistent(
    [T.ceildiv(M, block_M), T.ceildiv(N, block_N)],
    core_num,
    cid
):
    # 负载均衡调度
    ...
```

**优势**：
- ✅ 更好的缓存命中率
- ✅ 负载均衡

---

## 12. Expert 模式编程

### 12.1 扩展计算原语

#### 12.1.1 数学计算

| 原语 | 语义 |
|------|------|
| `T.tile.add(dst, src0, src1)` | `dst = src0 + src1` |
| `T.tile.sub(dst, src0, src1)` | `dst = src0 - src1` |
| `T.tile.mul(dst, src0, src1)` | `dst = src0 * src1` |
| `T.tile.div(dst, src0, src1)` | `dst = src0 / src1` |
| `T.tile.exp(dst, src)` | `dst = exp(src)` |
| `T.tile.ln(dst, src)` | `dst = ln(src)` |
| `T.tile.relu(dst, src)` | `dst = max(0, src)` |

#### 12.1.2 示例

```python
# 逐元素加法
T.tile.add(c_ub, a_ub, b_ub)

# ReLU 激活
T.tile.relu(c_ub, a_ub)

# 指数函数
T.tile.exp(c_ub, a_ub)
```

---

## 13. 流水线优化（T.Pipelined）

### 13.1 概念

**流水线并行**：通过重叠计算和数据搬运来提高性能。

### 13.2 核内流水线（Intra-core）

```python
for k in T.Pipelined(loop_k, num_stages=2):
    T.copy(A[bx * block_M, k * block_K], A_L1)  # Copy A
    T.copy(B[k * block_K, by * block_N], B_L1)  # Copy B
    T.barrier_all()
    T.gemm_v0(A_L1, B_L1, C_L0)                  # Compute
    T.barrier_all()
```

**时间线（num_stages=2）**：

| 时间 | Copy A | Copy B | Compute |
|------|--------|--------|---------|
| t₀   | A₀     | B₀     |         |
| t₁   | A₁     | B₁     |         |
| t₂   | A₂     | B₂     | C₀      |
| t₃   | A₃     | B₃     | C₁      |
| t₄   |        |        | C₂      |
| t₅   |        |        | C₃      |

### 13.3 核间流水线（Inter-core）

```python
for k in T.Pipelined(T.ceildiv(seq_len, block_N), num_stages=2):
    # Cube Core 操作
    T.copy(K[bz, by, k * block_N:(k+1) * block_N, :], k_l1)
    T.gemm_v0(q_l1, k_l1, acc_s_l0c)
    T.copy(acc_s_l0c, workspace_1[cid, :, :])
    
    # Vector Core 操作
    T.tile.fill(acc_s_ub, 0.0)
    T.copy(workspace_1[cid, :, :], acc_s_ub_)
    ...
```

**时间线**：

| 时间 | Cube (Write) | Vector (Read) |
|------|--------------|---------------|
| t₀   | W0           |               |
| t₁   | W1           | R0            |
| t₂   | W2           | R1            |
| t₃   | W3           | R2            |
| t₄   |              | R3            |

### 13.4 约束条件

- ⚠️ 核内流水线与核间流水线不能同时启用
- ⚠️ 核间流水线需要开启自动 CV 分离和同步

```python
pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_AUTO_CV_COMBINE: True,
    tilelang.PassConfigKey.TL_ASCEND_AUTO_CV_SYNC: True,
}
```

---

## 14. 并行计算（T.Parallel）

### 14.1 基本语法

```python
# 1D 并行
for i in T.Parallel(N):
    c[i] = a[i] + b[i]

# 2D 并行
for i, j in T.Parallel(M, N):
    c[i, j] = a[i, j] + b[i, j]
```

### 14.2 支持的操作

#### 14.2.1 二元操作

| 类别 | 表达式 | TileLang 表达 |
|------|--------|---------------|
| 加法 | `c = a + b` | `a + b` |
| 减法 | `c = a - b` | `a - b` |
| 乘法 | `c = a * b` | `a * b` |
| 除法 | `c = a / b` | `a / b` |
| 最大值 | `c = max(a, b)` | `T.max(a, b)` |
| 最小值 | `c = min(a, b)` | `T.min(a, b)` |

#### 14.2.2 一元操作

| 类别 | 表达式 | TileLang 表达 |
|------|--------|---------------|
| 绝对值 | `y = |x|` | `T.abs(x)` |
| 指数 | `y = e^x` | `T.exp(x)` |
| 对数 | `y = ln(x)` | `T.log(x)` |
| 平方根 | `y = √x` | `T.sqrt(x)` |
| ReLU | `y = max(x, 0)` | `T.max(x, 0)` |

### 14.3 广播机制

```python
# 向量-标量运算
for j in T.Parallel(block_N):
    c_ub[j] = a_ub[j] + 1

# 行广播
for i, j in T.Parallel(block_M, block_N):
    c_ub[i, j] = a_ub[i, j] * b_ub[i]  # b_ub.shape = (block_M,)
```

### 14.4 复杂表达式处理

```python
# 复杂表达式
for i, j in T.Parallel(M, N):
    c_ub[i, j] = a_ub[i, j] * b_ub[i, j] + a_ub[i, j] / b_ub[i, j]

# 自动分解为
for i, j in T.Parallel(M, N):
    c_tmp_0[i, j] = a_ub[i, j] * b_ub[i, j]
    c_tmp_1[i, j] = a_ub[i, j] / b_ub[i, j]
    c_ub[i, j] = c_tmp_0[i, j] + c_tmp_1[i, j]
```

**建议**：开启自动内存规划以避免临时缓冲区浪费。

---

## 15. 持久化调度（T.Persistent）

### 15.1 功能

通过优化数据块在 AI Core 间的调度策略，提高缓存命中率。

### 15.2 示例

```python
with T.Kernel(m_num * n_num, is_npu=True) as (cid, _):
    for bx, by in T.Persistent(
        [T.ceildiv(M, block_M), T.ceildiv(N, block_N)],
        core_num,
        cid
    ):
        # 负载均衡调度
        T.copy(A[bx * block_M, :], A_L1)
        T.copy(B[:, by * block_N], B_L1)
        T.gemm_v0(A_L1, B_L1, C_L0)
        T.copy(C_L0, C[bx * block_M, by * block_N])
```

---

*文档继续... 第四部分：性能优化、第五部分：实战案例、第六部分：附录*

---

**基于 tilelang-ascend 官方文档整理**
**最后更新：2026-02-15**
