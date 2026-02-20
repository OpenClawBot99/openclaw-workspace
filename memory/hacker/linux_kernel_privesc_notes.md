# Linux内核漏洞提权学习笔记

## 什么是Linux内核漏洞提权?
Linux内核漏洞利用是获取root权限的最直接方式，利用内核中的安全漏洞进行提权。

## 常见内核漏洞类型

### 1. 内存损坏漏洞
- 缓冲区溢出
- 堆溢出
- 格式化字符串
- 双重释放(Use-After-Free)

### 2. 权限绕过漏洞
- Capability绕过
- SELinux绕过
- AppArmor绕过

### 3. 竞态条件
- Time-of-Check-Time-of-Use
- 脏牛(Dirty COW)

## 历史著名漏洞

### 1. Dirty COW (CVE-2016-5195)
- 竞争条件漏洞
- 可写只读文件
- 影响广泛

### 2. Dirty Pipe (CVE-2022-0847)
- 管道缓冲区漏洞
- 覆盖只读文件
- 影响Linux 5.8+

### 3. overlayfs (CVE-2015-8660)
- Ubuntu提权漏洞
- 容器逃逸

### 4. BoxBox (CVE-2017-1000112)
- UDP Fragmentation Offload漏洞
- 权限提升

## 利用步骤

### 1. 信息收集
```bash
# 内核版本
uname -a
cat /proc/version

# 发行版
cat /etc/issue
lsb_release -a

# 已安装补丁
dpkg -l | grep kernel
rpm -qa kernel
```

### 2. 漏洞搜索
- searchsploit
- exploitdb
- GitHub POC

### 3. 漏洞利用
- 下载POC
- 编译
- 执行

### 4. 提权成功
- 获取root shell

## 常用工具

### 1. 信息收集
- linux-exploit-suggester
- LinPEAS
- linuxprivchecker

### 2. 漏洞利用
- Dirty COW POC
- Dirty Pipe POC
- kernel-exploits

## 防御措施

### 1. 及时打补丁
- 定期更新内核
- 关注CVE公告

### 2. 最小权限
- 禁用不必要的内核Capability
- AppArmor/SELinux强制

### 3. 容器隔离
- 避免特权容器
- 资源限制

### 4. 监控
- 内核日志审计
- 异常行为检测

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
