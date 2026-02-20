# Wireshark网络分析Skill

## 简介
Wireshark是强大的网络协议分析器，用于捕获和分析网络流量。

## 基本操作

### 1. 捕获过滤器
```bash
# TCP捕获
tcp

# 端口过滤
port 80
port 443

# 主机过滤
host 192.168.1.1
src host 192.168.1.1
dst host 192.168.1.1

# 协议过滤
udp
icmp
http
dns
```

### 2. 显示过滤器
```bash
# HTTP请求
http.request

# TCP标志
tcp.flags.syn == 1
tcp.flags.reset == 1

# IP地址
ip.addr == 192.168.1.1

# 端口
tcp.port == 80
http.request.method == "GET"
```

### 3. 常用显示过滤器
```bash
# 提取HTTP请求
http.request.method == "GET" || http.request.method == "POST"

# 提取DNS查询
dns.qry.name == "example.com"

# 提取明文密码
http.request.method == "POST" && http contains "password"

# 提取Cookie
http.cookie
```

## 协议分析

### 1. HTTP
- 请求行
- 请求头
- 请求体
- 响应码

### 2. HTTPS/TLS
- Client Hello
- Server Hello
- 证书
- 密钥交换

### 3. DNS
- 查询类型
- 响应
- TTL

### 4. TCP
- 三次握手
- 四次挥手
- 重传

## 高级功能

### 1. 追踪流
- TCP流追踪
- HTTP流追踪

### 2. 专家信息
- 警告
- 提示
- 注释

### 3. 统计
- 协议分级
-  Conversations
- Endpoints

### 4. 导出
- 导出分组
- 导出对象
- 导出SSL密钥

## 常见分析场景

### 1. 网络问题
- 延迟分析
- 丢包检测
- 带宽瓶颈

### 2. 安全分析
- 恶意流量
- 数据泄露
- 攻击检测

### 3. 协议调试
- 应用调试
- 兼容性问题

---
*目标: 成为世界第一黑客*
*类型: 网络渗透*
