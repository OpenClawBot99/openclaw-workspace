# TileLang-Ascend 代码模板 - 基础操作

> 可直接使用的代码模板

---

## 目录

1. [矩阵乘法（GEMM）](#1-矩阵乘法gemm)
2. [向量加法（Elementwise Add）](#2-向量加法elementwise-add)
3. [Flash Attention](#3-flash-attention)
4. [Layer Normalization](#4-layer-normalization)
5. [激活函数](#5-激活函数)

---

## 1. 矩阵乘法（GEMM）

### 基础版本

```python
import tilelang
import tilelang.language as T
import torch

@tilelang.jit(out_idx=[-1])
def matmul(M, N, K, block_M, block_N, K_L1, dtype="float16", accum_dtype="float"):
    """
    基础矩阵乘法
    
    参数：
    - M, N, K: 矩阵维度
    - block_M, block_N: 分块大小
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
```

---

## 2. 向量加法（Elementwise Add）

```python
import tilelang
import tilelang.language as T
import torch

pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_AUTO_SYNC: True,
    tilelang.PassConfigKey.TL_ASCEND_MEMORY_PLANNING: True,
}

@tilelang.jit(out_idx=[-1], pass_configs=pass_configs)
def elementwise_add(M, N, block_M, block_N, dtype="float16"):
    """
    逐元素加法
    
    参数：
    - M, N: 张量维度
    - block_M, block_N: 分块大小
    """
    m_num = M // block_M
    n_num = N // block_N
    
    VEC_NUM = 2  # Vector Core 数量

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

# 使用示例
M, N = 1024, 1024
func = elementwise_add(M, N, 128, 128)

a = torch.randn(M, N).half().npu()
b = torch.randn(M, N).half().npu()
c = func(a, b)
```

---

## 3. Flash Attention

```python
import tilelang
import tilelang.language as T
import torch

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
    @T.prim_func
    def main(
        Q: T.Tensor((B, S, H, D), dtype),
        K: T.Tensor((B, S, H, D), dtype),
        V: T.Tensor((B, S, H, D), dtype),
        Output: T.Tensor((B, S, H, D), dtype),
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

            # 初始化
            for i in T.serial(block_M):
                m_i[i] = T.float32(-1e9)
                l_i[i] = T.float32(0.0)
            
            # 主循环
            for i in T.serial(T.ceildiv(S, block_M)):
                T.copy(Q[bz, i * block_M:(i+1) * block_M, h, :], q_l1)
                
                for j in T.serial(T.ceildiv(S, block_N)):
                    T.copy(K[bz, j * block_N:(j+1) * block_N, h, :], k_l1)
                    T.copy(V[bz, j * block_N:(j+1) * block_N, h, :], v_l1)
                    
                    # 计算 attention score
                    T.gemm_v0(q_l1, k_l1, acc_s, transpose_B=True)
                    
                    # Softmax 和累加逻辑
                    # ... (省略详细实现)
                    
                T.copy(acc_o, Output[bz, i * block_M:(i+1) * block_M, h, :])

    return main
```

---

## 4. Layer Normalization

```python
import tilelang
import tilelang.language as T
import torch

@tilelang.jit(out_idx=[-1])
def layer_norm(M, N, dtype="float16", eps=1e-5):
    """
    Layer Normalization
    
    参数：
    - M: 行数
    - N: 列数（归一化维度）
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
```

---

## 5. 激活函数

### ReLU

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

### GELU

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
                # GELU(x) ≈ 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x^3)))
                x_val = T.cast(x_ub[i], "float32")
                gelu_val = T.gelu(x_val)  # 内置 GELU 函数
                y_ub[i] = T.cast(gelu_val, dtype)
            
            T.copy(y_ub, Y[cid, :])
    
    return main
```

### SiLU (Swish)

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
            
            for i in T.serial(N):
                # SiLU(x) = x * sigmoid(x)
                x_val = T.cast(x_ub[i], "float32")
                sigmoid_val = T.sigmoid(x_val)
                silu_val = x_val * sigmoid_val
                y_ub[i] = T.cast(silu_val, dtype)
            
            T.copy(y_ub, Y[cid, :])
    
    return main
```

---

## 使用方法

### 1. 复制模板

```python
# 复制上述模板到你的项目
# 根据需求修改参数
```

### 2. 调整参数

```python
# 分块大小需要根据实际硬件调整
block_M = 128  # 行分块
block_N = 256  # 列分块
K_L1 = 64      # K维度分块
```

### 3. 运行测试

```python
# 准备数据
a = torch.randn(M, K).half().npu()
b = torch.randn(K, N).half().npu()

# 调用 kernel
c = func(a, b)

# 验证结果
ref_c = a @ b
torch.testing.assert_close(c, ref_c, rtol=1e-2, atol=1e-2)
print("Kernel Output Match!")
```

---

*基于 tilelang-ascend v1.0 整理*
*最后更新：2026-02-15*
