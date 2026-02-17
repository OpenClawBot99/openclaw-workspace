# TileLang-Ascend 最佳实践指南

> 基于 tilelang-ascend 官方文档和社区经验整理
> 最后更新：2026-02-15

---

## 目录

1. [代码风格最佳实践](#1-代码风格最佳实践)
2. [性能优化最佳实践](#2-性能优化最佳实践)
3. [调试最佳实践](#3-调试最佳实践)
4. [内存管理最佳实践](#4-内存管理最佳实践)
5. [安全性最佳实践](#5-安全性最佳实践)
6. [常见错误和解决方案](#6-常见错误和解决方案)

---

## 1. 代码风格最佳实践

### 1.1 命名规范

```python
# ✅ 推荐：清晰的命名
def matmul(M, N, K, block_M, block_N, block_K):
    @T.prim_func
    def main(
        A: T.Tensor((M, K), dtype),
        B: T.Tensor((K, N), dtype),
        C: T.Tensor((M, N), dtype),
    ):
        # kernel 逻辑
        pass
    return main

# ❌ 不推荐：模糊的命名
def func(a, b, c, d, e, f):
    # ...
    pass
```

### 1.2 注释和文档

```python
def flash_attention_fwd(B, S, H, D, block_M, block_N, 
                       dtype="float16", accum_dtype="float"):
    """
    Flash Attention 前向传播
    
    参数：
    - B: batch size
    - S: sequence length
    - H: head number
    - D: head dimension
    - block_M: M维度分块大小
    - block_N: N维度分块大小
    
    返回：
    - TileLang kernel 函数
    
    示例：
    >>> kernel = flash_attention_fwd(1, 1024, 12, 64, 128, 64)
    >>> output = kernel(q, k, v)
    """
    @T.prim_func
    def main(Q: T.Tensor((B, S, H, D), dtype), ...):
        # 加载 Q 到 L1 缓存
        T.copy(Q[bz, h, i * block_M:(i+1) * block_M, :], q_l1)
        
        # 计算 attention score
        T.gemm_v0(q_l1, k_l1, acc_s, transpose_B=True)
        
        # ... 更多计算
        
    return main
```

### 1.3 代码组织

```python
# ✅ 推荐：模块化组织
@tilelang.jit(out_idx=[-1])
def matmul(M, N, K, block_M, block_N, block_K):
    # 1. 参数定义
    m_num = M // block_M
    n_num = N // block_N
    
    @T.prim_func
    def main(A, B, C):
        # 2. kernel 主体
        with T.Kernel(m_num * n_num, is_npu=True) as (cid, _):
            # 3. 内存分配
            A_L1 = T.alloc_L1((block_M, block_K), dtype)
            B_L1 = T.alloc_L1((block_K, block_N), dtype)
            C_L0 = T.alloc_L0C((block_M, block_N), accum_dtype)
            
            # 4. 计算逻辑
            with T.Scope("C"):
                # 主循环
                for k in T.serial(loop_k):
                    # 数据搬运
                    T.copy(A[src], A_L1)
                    # 矩阵乘法
                    T.gemm_v0(A_L1, B_L1, C_L0)
                    # 结果写回
                    T.copy(C_L0, C[dst])
    
    return main
```

---

## 2. 性能优化最佳实践

### 2.1 分块大小选择

```python
# ✅ 推荐：根据硬件选择合适的分块大小
# Ascend A2/A3 典型配置
block_M = 128  # 行分块
block_N = 256  # 列分块
block_K = 64   # K维度分块

# ❌ 不推荐：过小或过大的分块
block_M = 4    # 太小，无法充分利用硬件
block_N = 4096 # 太大，超出共享内存容量
```

### 2.2 流水线优化

```python
# ✅ 推荐：使用流水线隐藏内存延迟
for ko in T.Pipelined(T.ceildiv(K, block_K), num_stages=2):
    T.copy(A[ko * block_K], A_L1)
    T.gemm_v0(A_L1, B, C_L0)

# ❌ 不推荐：串行执行
for ko in T.serial(T.ceildiv(K, block_K)):
    T.copy(A[ko * block_K], A_L1)
    T.gemm_v0(A_L1, B, C_L0)
```

### 2.3 内存访问优化

```python
# ✅ 推荐：合并访问
for i, j in T.Parallel(block_M, block_N):
    C[i, j] = A[i, j] + B[i, j]

# ❌ 不推荐：非合并访问
for i in T.serial(block_M):
    for j in T.serial(block_N):
        C[i, j] = A[i, j] + B[i, j]
```

### 2.4 自动调优

```python
# ✅ 推荐：使用自动调优找最优配置
from tilelang.autotuner import AutoTuner

autotuner = AutoTuner.from_kernel(kernel=matmul, configs=configs)
result = autotuner.run(warmup=3, rep=20)
best_kernel = result.kernel

# ❌ 不推荐：手动猜测配置
kernel = matmul(1024, 1024, 1024, 128, 128, 32)  # 可能不是最优
```

---

## 3. 调试最佳实践

### 3.1 打印调试

```python
# ✅ 推荐：使用 T.printf 调试
T.printf("Index: %d, Value: %f\n", i, A[i])

# ✅ 推荐：条件打印
if i < 10:
    T.printf("First 10 elements: idx=%d, val=%f\n", i, A[i])

# ❌ 不推荐：过多打印（影响性能）
for i in T.serial(N):
    T.printf("i=%d, A[i]=%f\n", i, A[i])  # 打印太多
```

### 3.2 张量 Dump

```python
# ✅ 推荐：Dump 中间结果
T.dump_tensor(A_L1, "A_L1.bin")
T.dump_tensor(C_L0, "C_L0.bin")

# 分析 dump 文件
# python analyze_dump.py A_L1.bin
```

### 3.3 查看生成代码

```python
# ✅ 推荐：检查生成的 CUDA/AscendC 代码
kernel_source = kernel.get_kernel_source()
print(kernel_source)

# 保存到文件以便检查
with open("debug_kernel.cu", "w") as f:
    f.write(kernel_source)
```

### 3.4 单元测试

```python
# ✅ 推荐：编写单元测试
import torch
import torch.testing

def test_matmul():
    M, N, K = 1024, 1024, 1024
    kernel = matmul(M, N, K, 128, 256, 64)
    
    a = torch.randn(M, K).half().npu()
    b = torch.randn(K, N).half().npu()
    c = kernel(a, b)
    
    ref_c = a @ b
    torch.testing.assert_close(c, ref_c, rtol=1e-2, atol=1e-2)
    print("✅ 测试通过")

test_matmul()
```

---

## 4. 内存管理最佳实践

### 4.1 内存分配

```python
# ✅ 推荐：在 kernel 顶部统一分配
@T.prim_func
def main(A, B, C):
    with T.Kernel(...) as (...):
        # 统一分配所有缓冲区
        A_L1 = T.alloc_L1(...)
        B_L1 = T.alloc_L1(...)
        C_L0 = T.alloc_L0C(...)
        
        # 计算逻辑
        ...

# ❌ 不推荐：在循环内分配
for k in T.serial(loop_k):
    A_temp = T.alloc_L1(...)  # 重复分配，效率低
    ...
```

### 4.2 内存复用

```python
# ✅ 推荐：复用缓冲区
temp_buffer = T.alloc_ub((block_size,), dtype)

# 任务1使用 temp_buffer
compute_task1(temp_buffer)

# 任务2复用 temp_buffer
compute_task2(temp_buffer)

# ❌ 不推荐：重复分配
buffer1 = T.alloc_ub(...)
compute_task1(buffer1)
buffer2 = T.alloc_ub(...)  # 浪费内存
compute_task2(buffer2)
```

### 4.3 自动内存规划

```python
# ✅ 推荐：启用自动内存规划
pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_MEMORY_PLANNING: True,
}

@tilelang.jit(out_idx=[-1], pass_configs=pass_configs)
def kernel(...):
    # 编译器会自动优化内存分配
    ...
```

---

## 5. 安全性最佳实践

### 5.1 边界检查

```python
# ✅ 推荐：显式边界检查
for i in T.serial(block_M):
    if i < N:  # 边界检查
        C[i] = A[i] + B[i]

# ❌ 不推荐：假设边界条件总是满足
for i in T.serial(block_M):
    C[i] = A[i] + B[i]  # 可能越界
```

### 5.2 数据类型检查

```python
# ✅ 推荐：验证数据类型
def kernel(dtype="float16"):
    if dtype not in ["float16", "float32", "bfloat16"]:
        raise ValueError(f"Unsupported dtype: {dtype}")
    
    @T.prim_func
    def main(A: T.Tensor((M, K), dtype), ...):
        ...
    
    return main
```

### 5.3 数值稳定性

```python
# ✅ 推荐：使用高精度累加
accum_dtype = "float"  # 累加使用 float32

@T.prim_func
def main(A: T.Tensor((M, K), "float16"), ...):
    C_L0 = T.alloc_L0C((block_M, block_N), accum_dtype)  # float32
    T.gemm_v0(A_L1, B_L1, C_L0)  # 高精度累加

# ❌ 不推荐：低精度累加（可能精度损失）
accum_dtype = "float16"  # 低精度累加
```

---

## 6. 常见错误和解决方案

### 6.1 编译错误

#### 错误：内存不足

```
错误：shared memory allocation failed
```

**解决方案**：
```python
# 减小分块大小
block_M = 64   # 原来是 128
block_N = 128  # 原来是 256
```

#### 错误：不支持的操作

```
错误：unsupported operation for dtype
```

**解决方案**：
```python
# 检查数据类型支持
dtype = "float16"  # 某些操作只支持特定类型
```

### 6.2 运行时错误

#### 错误：结果不匹配

```
错误：AssertionError: Not equal to tolerance
```

**解决方案**：
```python
# 1. 检查数据布局
T.annotate_layout({...})

# 2. 增加累加精度
accum_dtype = "float"

# 3. 检查边界条件
if i < N:
    ...
```

#### 错误：同步问题

```
错误：race condition detected
```

**解决方案**：
```python
# 添加必要的同步
T.barrier_all()

# 或者启用自动同步
pass_configs = {
    tilelang.PassConfigKey.TL_ASCEND_AUTO_SYNC: True,
}
```

### 6.3 性能问题

#### 问题：性能低下

**诊断步骤**：
1. 检查内存访问模式
2. 使用自动调优
3. 查看生成的代码
4. 分析性能瓶颈

**解决方案**：
```python
# 1. 使用自动调优
autotuner = AutoTuner.from_kernel(kernel, configs)
result = autotuner.run()

# 2. 优化内存访问
for i, j in T.Parallel(...):  # 并行访问

# 3. 使用流水线
for k in T.Pipelined(..., num_stages=2):

# 4. 向量化加载
for k in T.vectorized(...):
```

---

## 7. 检查清单

### 代码提交前检查

- [ ] 代码风格符合规范
- [ ] 添加了必要的注释
- [ ] 通过所有单元测试
- [ ] 性能符合预期
- [ ] 无内存泄漏
- [ ] 边界检查完整
- [ ] 数值稳定性验证

### 性能优化检查

- [ ] 使用了自动调优
- [ ] 内存访问模式优化
- [ ] 使用了流水线
- [ ] 向量化加载/存储
- [ ] 减少了同步次数
- [ ] 内存复用

### 调试检查

- [ ] 添加了调试信息
- [ ] 检查了生成代码
- [ ] 验证了数值正确性
- [ ] 测试了边界条件
- [ ] 性能回归测试

---

*基于 tilelang-ascend 官方文档和社区经验整理*
*最后更新：2026-02-15*
