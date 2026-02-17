# TileLang-Ascend 实战案例集

> 基于 tilelang-ascend examples 目录整理
> 最后更新：2026-02-15

---

## 目录

1. [矩阵乘法（GEMM）](#1-矩阵乘法gemm)
2. [Flash Attention](#2-flash-attention)
3. [Layer Normalization](#3-layer-normalization)
4. [激活函数](#4-激活函数)
5. [稀疏注意力](#5-稀疏注意力)
6. [向量运算](#6-向量运算)
7. [量化矩阵乘法](#7-量化矩阵乘法)

---

## 1. 矩阵乘法（GEMM）

### 1.1 基础版本

**文件**：`examples/gemm/example_gemm.py`

```python
import tilelang
import tilelang.language as T
import torch

@tilelang.jit(out_idx=[-1])
def matmul(M, N, K, block_M, block_N, K_L1, dtype="float16", accum_dtype="float"):
    """
    基础矩阵乘法：C = A @ B
    
    参数：
    - M, N, K: 矩阵维度
    - block_M, block_N: Tile 块大小
    - K_L1: K 维度的 L1 分块大小
    """
    m_num = M // block_M
    n_num = N // block_N

    @T.prim_func
    def main(
        A: T.Tensor((M, K), dtype),
        B: T.Tensor((K, N), dtype),
        C: T.Tensor((M, N), dtype),
    ):
        with T.Kernel(m_num * n_num, is_npu=True) as (cid, _):
            bx = cid // n_num
            by = cid % n_num

            # 分配 L1 缓存
            A_L1 = T.alloc_L1((block_M, K_L1), dtype)
            B_L1 = T.alloc_L1((K_L1, block_N), dtype)
            
            # 分配 L0C 累加缓存
            C_L0 = T.alloc_L0C((block_M, block_N), accum_dtype)

            with T.Scope("C"):
                loop_k = T.ceildiv(K, K_L1)
                
                for k in T.serial(loop_k):
                    # 拷贝数据到 L1
                    T.copy(A[bx * block_M, k * K_L1], A_L1)
                    T.copy(B[k * K_L1, by * block_N], B_L1)

                    # 同步
                    T.barrier_all()
                    
                    # 矩阵乘法
                    T.gemm_v0(A_L1, B_L1, C_L0, init=(k == 0))

                    # 同步
                    T.barrier_all()

                # 拷贝结果到全局内存
                T.copy(C_L0, C[bx * block_M, by * block_N])

    return main

# 使用示例
M, N, K = 1024, 1024, 1024
func = matmul(M, N, K, 128, 256, 64)

a = torch.randn(M, K).half().npu()
b = torch.randn(K, N).half().npu()
c = func(a, b)

# 验证
ref_c = a @ b
torch.testing.assert_close(c, ref_c, rtol=1e-2, atol=1e-2)
print("Kernel Output Match!")
```

**性能特点**：
- ✅ 简单易懂
- ⚠️ 性能中等（未使用流水线）

---

### 1.2 高性能版本

**文件**：`examples/gemm/example_gemm_intrinsic.py`

**特性**：
- ✅ 流水线并行
- ✅ 内存布局优化
- ✅ L2 缓存 Swizzling

```python
@tilelang.jit(out_idx=[-1])
def matmul_high_perf(M, N, K, block_M, block_N, block_K, K_L1, S1, S2, 
                     dtype="float16", accum_dtype="float"):
    m_num = M // block_M
    n_num = N // block_N
    core_num = 20  # AI Core 数量

    @T.macro
    def init_flag():
        T.set_flag("mte1", "mte2", 0)
        T.set_flag("mte1", "mte2", 1)
        T.set_flag("m", "mte1", 0)
        T.set_flag("m", "mte1", 1)
        T.set_flag("fix", "m", 0)

    @T.macro
    def clear_flag():
        T.wait_flag("mte1", "mte2", 0)
        T.wait_flag("mte1", "mte2", 1)
        T.wait_flag("m", "mte1", 0)
        T.wait_flag("m", "mte1", 1)
        T.wait_flag("fix", "m", 0)

    @T.prim_func
    def main(
        A: T.Tensor((M, K), dtype),
        B: T.Tensor((K, N), dtype),
        C: T.Tensor((M, N), dtype),
    ):
        with T.Kernel(core_num, is_npu=True) as (cid, _):
            # 多级缓存分配
            A_L1 = T.alloc_L1((S1, block_M, K_L1), dtype)
            B_L1 = T.alloc_L1((S1, K_L1, block_N), dtype)

            # 布局注解
            T.annotate_layout({
                A_L1: make_zn_layout(A_L1),
                B_L1: make_zn_layout(B_L1),
            })

            A_L0 = T.alloc_L0A((S2, block_M, block_K), dtype)
            B_L0 = T.alloc_L0B((S2, block_K, block_N), dtype)
            C_L0 = T.alloc_L0C((block_M, block_N), accum_dtype)

            with T.Scope("C"):
                init_flag()

                for i in T.serial(T.ceildiv(m_num * n_num, core_num)):
                    # Swizzling 优化
                    T.use_swizzle(i * core_num + cid, M, N, K, block_M, block_N, 
                                  off=3, in_loop=True)
                    
                    bx = cid // n_num
                    by = cid % n_num

                    loop_k = T.ceildiv(K, K_L1)

                    # 流水线拷贝
                    T.wait_flag("mte1", "mte2", 0)
                    T.copy(A[bx * block_M, 0], A_L1[0, :, :])
                    T.copy(B[0, by * block_N], B_L1[0, :, :])
                    T.set_flag("mte2", "mte1", 0)
                    
                    T.wait_flag("fix", "m", 0)
                    
                    for k in T.serial(loop_k):
                        if k < loop_k - 1:
                            T.wait_flag("mte1", "mte2", (k + 1) % S1)
                            T.copy(A[bx * block_M, (k + 1) * K_L1], A_L1[(k + 1) % S1, :, :])
                            T.copy(B[(k + 1) * K_L1, by * block_N], B_L1[(k + 1) % S1, :, :])
                            T.set_flag("mte2", "mte1", (k + 1) % S1)

                        loop_kk = T.ceildiv(K_L1, block_K)

                        for kk in T.serial(loop_kk):
                            if kk == 0:
                                T.wait_flag("mte2", "mte1", k % S1)
                            T.wait_flag("m", "mte1", kk % S2)
                            T.copy(A_L1[k % S1, 0, kk * block_K], A_L0[kk % S2, :, :])
                            T.copy(B_L1[k % S1, kk * block_K, 0], B_L0[kk % S2, :, :])
                            
                            if kk == 3:
                                T.set_flag("mte1", "mte2", k % S1)
                            T.set_flag("mte1", "m", kk % S2)
                            T.wait_flag("mte1", "m", kk % S2)

                            if k == 0 and kk == 0:
                                T.mma(A_L0[kk % S2, :, :], B_L0[kk % S2, :, :], 
                                      C_L0, init=True)
                            else:
                                T.mma(A_L0[kk % S2, :, :], B_L0[kk % S2, :, :], C_L0)

                            T.set_flag("m", "mte1", kk % S2)

                    T.set_flag("m", "fix", 0)
                    T.wait_flag("m", "fix", 0)
                    T.copy(C_L0, C[bx * block_M, by * block_N])
                    T.set_flag("fix", "m", 0)

                clear_flag()
                T.barrier_all()

    return main
```

**性能特点**：
- ✅ 三级流水线
- ✅ Swizzling 优化
- ✅ 布局优化
- ✅ 极致性能

---

## 2. Flash Attention

### 2.1 标准版本

**文件**：`examples/flash_attention/flash_attn_bhsd.py`

```python
@tilelang.jit(out_idx=[3])
def flash_attention_fwd(B, S, H, D, block_M, block_N, dtype="float16", accum_dtype="float"):
    """
    Flash Attention 前向传播
    
    参数：
    - B: batch size
    - S: sequence length
    - H: head number
    - D: head dimension
    """
    sm_scale = 1.0 / (D ** 0.5)

    @T.prim_func
    def main(
        Q: T.Tensor((B, H, S, D), dtype),
        K: T.Tensor((B, H, S, D), dtype),
        V: T.Tensor((B, H, S, D), dtype),
        Output: T.Tensor((B, H, S, D), dtype),
    ):
        with T.Kernel(B * H, is_npu=True) as (cid, _):
            bz = cid // H
            h = cid % H

            # 分配缓存
            q_l1 = T.alloc_L1((block_M, D), dtype)
            k_l1 = T.alloc_L1((block_N, D), dtype)
            v_l1 = T.alloc_L1((block_N, D), dtype)
            
            acc_o = T.alloc_ub((block_M, D), accum_dtype)
            acc_s = T.alloc_ub((block_M, block_N), accum_dtype)
            
            m_i = T.alloc_ub((block_M,), accum_dtype)
            l_i = T.alloc_ub((block_M,), accum_dtype)
            m_i_prev = T.alloc_ub((block_M,), accum_dtype)

            # 初始化
            for i in T.serial(block_M):
                m_i[i] = T.float32(-1e9)
                l_i[i] = T.float32(0.0)
                for j in T.serial(D):
                    acc_o[i, j] = T.float32(0.0)

            # 主循环
            for i in T.serial(T.ceildiv(S, block_M)):
                # 加载 Q
                T.copy(Q[bz, h, i * block_M:(i+1) * block_M, :], q_l1)

                for j in T.serial(T.ceildiv(S, block_N)):
                    # 加载 K, V
                    T.copy(K[bz, h, j * block_N:(j+1) * block_N, :], k_l1)
                    T.copy(V[bz, h, j * block_N:(j+1) * block_N, :], v_l1)

                    # 计算 attention score: S = Q @ K^T
                    T.gemm_v0(q_l1, k_l1, acc_s, transpose_B=True)

                    # Softmax（简化版）
                    # 1. 计算最大值
                    for m in T.serial(block_M):
                        max_val = m_i[m]
                        for n in T.serial(block_N):
                            max_val = T.max(max_val, acc_s[m, n])
                        m_i_prev[m] = m_i[m]
                        m_i[m] = max_val

                    # 2. 指数化和归一化
                    for m in T.serial(block_M):
                        for n in T.serial(block_N):
                            acc_s[m, n] = T.exp(acc_s[m, n] - m_i[m])

                    # 3. 计算分母
                    for m in T.serial(block_M):
                        sum_exp = T.float32(0.0)
                        for n in T.serial(block_N):
                            sum_exp += acc_s[m, n]
                        l_i[m] = sum_exp

                    # 4. 加权求和
                    for m in T.serial(block_M):
                        for d in T.serial(D):
                            val = T.float32(0.0)
                            for n in T.serial(block_N):
                                val += acc_s[m, n] * v_l1[n, d]
                            acc_o[m, d] += val

                # 写回结果
                T.copy(acc_o, Output[bz, h, i * block_M:(i+1) * block_M, :])

    return main
```

### 2.2 流水线版本

**文件**：`examples/pipeline/flash_attn_bshd_pipeline.py`

**特性**：
- ✅ Cube-Vector 核间流水线
- ✅ 自动 CV 同步

```python
pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_AUTO_CV_COMBINE: True,
    tilelang.PassConfigKey.TL_ASCEND_AUTO_CV_SYNC: True,
}

@tilelang.jit(out_idx=[3], pass_configs=pass_configs)
def flash_attention_pipeline(B, S, H, D, block_M, block_N, 
                             dtype="float16", accum_dtype="float"):
    @T.prim_func
    def main(
        Q: T.Tensor((B, S, H, D), dtype),
        K: T.Tensor((B, S, H, D), dtype),
        V: T.Tensor((B, S, H, D), dtype),
        Output: T.Tensor((B, S, H, D), dtype),
    ):
        with T.Kernel(B * H, is_npu=True) as (cid, vid):
            # ... 初始化 ...

            for i in T.serial(T.ceildiv(S, block_M)):
                T.copy(Q[bz, i * block_M:(i+1) * block_M, h, :], q_l1)

                for k in T.Pipelined(T.ceildiv(S, block_N), num_stages=2):
                    # Cube Core: Q @ K^T
                    T.copy(K[bz, k * block_N:(k+1) * block_N, h, :], k_l1)
                    T.gemm_v0(q_l1, k_l1, acc_s_l0c, transpose_B=True)
                    T.copy(acc_s_l0c, workspace[cid, :, :])

                    # Vector Core: Softmax + Accumulation
                    T.tile.fill(acc_s_ub, 0.0)
                    T.copy(workspace[cid, :, :], acc_s_ub)
                    T.tile.mul(acc_s_ub, acc_s_ub, sm_scale)
                    # ... softmax logic ...

    return main
```

---

## 3. Layer Normalization

**文件**：`examples/normalization/layer_norm.py`

```python
@tilelang.jit(out_idx=[-1])
def layer_norm(M, N, dtype="float16", eps=1e-5):
    """
    Layer Normalization
    
    参数：
    - M: 行数（batch * seq_len）
    - N: 列数（hidden_dim）
    """
    @T.prim_func
    def main(
        X: T.Tensor((M, N), dtype),
        Gamma: T.Tensor((N,), dtype),
        Beta: T.Tensor((N,), dtype),
        Y: T.Tensor((M, N), dtype),
    ):
        with T.Kernel(M, is_npu=True) as (cid, _):
            # 分配缓存
            x_ub = T.alloc_ub((N,), dtype)
            y_ub = T.alloc_ub((N,), dtype)
            
            # 拷贝输入
            T.copy(X[cid, :], x_ub)
            
            # 计算均值
            mean = T.float32(0.0)
            for i in T.serial(N):
                mean += x_ub[i]
            mean /= N
            
            # 计算方差
            var = T.float32(0.0)
            for i in T.serial(N):
                diff = x_ub[i] - mean
                var += diff * diff
            var /= N
            
            # 归一化
            rstd = T.rsqrt(var + eps)
            for i in T.serial(N):
                y_ub[i] = (x_ub[i] - mean) * rstd * Gamma[i] + Beta[i]
            
            # 拷贝输出
            T.copy(y_ub, Y[cid, :])

    return main

# 使用示例
M, N = 1024, 768
func = layer_norm(M, N)

x = torch.randn(M, N).half().npu()
gamma = torch.randn(N).half().npu()
beta = torch.randn(N).half().npu()

y = func(x, gamma, beta)
```

---

## 4. 激活函数

### 4.1 ReLU

**文件**：`examples/activation/relu.py`

```python
@tilelang.jit(out_idx=[-1])
def relu(M, N, dtype="float16"):
    @T.prim_func
    def main(
        X: T.Tensor((M, N), dtype),
        Y: T.Tensor((M, N), dtype),
    ):
        with T.Kernel(M, is_npu=True) as (cid, _):
            x_ub = T.alloc_ub((N,), dtype)
            y_ub = T.alloc_ub((N,), dtype)
            
            T.copy(X[cid, :], x_ub)
            
            for i in T.serial(N):
                y_ub[i] = T.max(x_ub[i], T.float16(0.0))
            
            T.copy(y_ub, Y[cid, :])
    
    return main
```

### 4.2 GELU

**文件**：`examples/activation/gelu_mul.py`

```python
@tilelang.jit(out_idx=[-1])
def gelu(M, N, dtype="float16"):
    @T.prim_func
    def main(
        X: T.Tensor((M, N), dtype),
        Y: T.Tensor((M, N), dtype),
    ):
        with T.Kernel(M, is_npu=True) as (cid, _):
            x_ub = T.alloc_ub((N,), dtype)
            y_ub = T.alloc_ub((N,), dtype)
            
            T.copy(X[cid, :], x_ub)
            
            for i in T.serial(N):
                x_val = T.cast(x_ub[i], "float32")
                # GELU(x) ≈ 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x^3)))
                gelu_val = T.gelu(x_val)
                y_ub[i] = T.cast(gelu_val, dtype)
            
            T.copy(y_ub, Y[cid, :])
    
    return main
```

### 4.3 SiLU (Swish)

**文件**：`examples/activation/silu.py`

```python
@tilelang.jit(out_idx=[-1])
def silu(M, N, dtype="float16"):
    @T.prim_func
    def main(
        X: T.Tensor((M, N), dtype),
        Y: T.Tensor((M, N), dtype),
    ):
        with T.Kernel(M, is_npu=True) as (cid, _):
            x_ub = T.alloc_ub((N,), dtype)
            y_ub = T.alloc_ub((N,), dtype)
            
            T.copy(X[cid, :], x_ub)
            
            # SiLU(x) = x * sigmoid(x)
            T.tile.mul(y_ub, x_ub, T.sigmoid(x_ub))
            
            T.copy(y_ub, Y[cid, :])
    
    return main
```

---

## 5. 稀疏注意力

**文件**：`examples/sparse_flash_attention/example_sparse_flash_attn.py`

```python
pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_AUTO_SYNC: True,
    tilelang.PassConfigKey.TL_ASCEND_MEMORY_PLANNING: True,
}

@tilelang.jit(out_idx=[3], pass_configs=pass_configs)
def sparse_attention_fwd(heads, dim, tail_dim, topk, kv_stride,
                         block_M, block_N, dtype="float16", accum_dtype="float"):
    """
    稀疏 Flash Attention
    
    特性：
    - 支持 top-k 稀疏模式
    - 自动工作空间分配
    - 自动同步插入
    """
    @T.prim_func
    def main(
        Q: T.Tensor((B, S, H, D), dtype),
        KV: T.Tensor((B, SKV, HKV, D), dtype),
        Indices: T.Tensor((B, S, HKV, topk), "int32"),
        Output: T.Tensor((B, S, H, D), dtype),
        # 自动分配的工作空间
        workspace_1: T.Tensor([block_num, BI, D], dtype),
        workspace_2: T.Tensor([block_num, BI, D_tail], dtype),
        workspace_3: T.Tensor([block_num, H_per_block, BI], accum_dtype),
        workspace_4: T.Tensor([block_num, H_per_block, BI], dtype),
        workspace_5: T.Tensor([block_num, H_per_block, D], accum_dtype),
    ):
        with T.Kernel(B * H, is_npu=True) as (cid, _):
            # ... 稀疏注意力实现 ...
            
            # 使用 T.Parallel 进行并行计算
            for i, j in T.Parallel(v_block, BI):
                acc_s_ub[i, j] = acc_s_ub[i, j] + acc_s_ub_[i, j]
            
            # ... 更多计算 ...

    return main

# 使用示例
func = sparse_attention_fwd(
    heads=128,
    dim=512,
    tail_dim=64,
    topk=2048,
    kv_stride=1,
)

q = torch.randn((B, S, H, DQK), dtype=torch.float16).npu()
kv = torch.randn((B, SKV, HKV, DQK), dtype=torch.float16).npu()
indices = torch.full((B, S, HKV, topk), SKV, dtype=torch.int32).npu()

# 自动分配工作空间
output = func(q, kv, indices)
```

---

## 6. 向量运算

**文件**：`examples/elementwise/elementwise_add.py`

```python
pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_AUTO_SYNC: True,
    tilelang.PassConfigKey.TL_ASCEND_MEMORY_PLANNING: True,
}

@tilelang.jit(out_idx=[-1], pass_configs=pass_configs)
def elementwise_add(M, N, block_M, block_N, dtype="float16"):
    """
    逐元素加法：C = A + B
    
    特性：
    - 自动同步插入
    - 自动内存规划
    - T.Parallel 并行计算
    """
    m_num = M // block_M
    n_num = N // block_N
    VEC_NUM = 2

    @T.prim_func
    def add_kernel(
        A: T.Tensor((M, N), dtype),
        B: T.Tensor((M, N), dtype),
        C: T.Tensor((M, N), dtype),
    ):
        with T.Kernel(m_num * n_num, is_npu=True) as (cid, vid):
            bx = cid // n_num
            by = cid % n_num

            # 分配 UB 缓存
            a_ub = T.alloc_ub((block_M // VEC_NUM, block_N), dtype)
            b_ub = T.alloc_ub((block_M // VEC_NUM, block_N), dtype)
            c_ub = T.alloc_ub((block_M // VEC_NUM, block_N), dtype)
            
            # 拷贝数据
            T.copy(A[bx * block_M + vid * block_M // VEC_NUM, by * block_N], a_ub)
            T.copy(B[bx * block_M + vid * block_M // VEC_NUM, by * block_N], b_ub)

            # 并行计算
            for i, j in T.Parallel(block_M // VEC_NUM, block_N):
                c_ub[i, j] = a_ub[i, j] + b_ub[i, j]

            # 拷贝结果
            T.copy(c_ub, C[bx * block_M + vid * block_M // VEC_NUM, by * block_N])

    return add_kernel
```

---

## 7. 量化矩阵乘法

**文件**：`examples/quant_batch_matmul/example_quant_matmul.py`

```python
@tilelang.jit(out_idx=[-1])
def quant_matmul(M, N, K, block_M, block_N, block_K, 
                 dtype="int8", accum_dtype="int32"):
    """
    量化矩阵乘法：C = A @ B
    
    特性：
    - INT8 输入
    - INT32 累加
    - 支持反量化
    """
    @T.prim_func
    def main(
        A: T.Tensor((M, K), dtype),
        B: T.Tensor((K, N), dtype),
        Scale: T.Tensor((N,), "float32"),
        C: T.Tensor((M, N), "float16"),
    ):
        with T.Kernel(T.ceildiv(M, block_M) * T.ceildiv(N, block_N), 
                      is_npu=True) as (cid, _):
            # INT8 矩阵乘法
            # ...
            
            # 反量化
            for i, j in T.Parallel(block_M, block_N):
                C[i, j] = T.cast(C_int32[i, j], "float16") * Scale[j]

    return main
```

---

## 使用技巧

### 1. 调试工具

```python
# 打印设备端数据
T.printf("Value: %f\n", x_ub[i])

# Dump 张量
T.dump_tensor(x_ub, "debug_tensor.bin")
```

### 2. 自动调优

```python
from tilelang.autotuner import Tuner

tuner = Tuner(
    func=matmul,
    search_space={
        "block_M": [64, 128, 256],
        "block_N": [64, 128, 256],
        "K_L1": [32, 64, 128],
    }
)

best_config = tuner.tune(M=1024, N=1024, K=1024)
```

### 3. 性能分析

```python
from tilelang.profiler import Profiler

profiler = Profiler(func)
latency = profiler.benchmark(a, b, num_runs=100)
print(f"Average latency: {latency:.3f} ms")
```

---

## 完整示例列表

| 类别 | 示例文件 | 说明 |
|------|----------|------|
| **GEMM** | `examples/gemm/` | 矩阵乘法 |
| **Flash Attention** | `examples/flash_attention/` | 注意力机制 |
| **Normalization** | `examples/normalization/` | 归一化层 |
| **Activation** | `examples/activation/` | 激活函数 |
| **Elementwise** | `examples/elementwise/` | 逐元素操作 |
| **Convolution** | `examples/convolution/` | 卷积操作 |
| **Quantization** | `examples/quant_batch_matmul/` | 量化计算 |

---

*基于 tilelang-ascend examples 目录整理*
*最后更新：2026-02-15*
