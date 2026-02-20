# Wireshark网络分析Skill

## 简介
Wireshark是强大的网络协议分析器。

## 捕获过滤器

### 1. 协议过滤
```bash
tcp
udp
icmp
http
dns
```

### 2. 端口过滤
```bash
port 80
port 443
```

### 3. 主机过滤
```bash
host 192.168.1.1
src host 192.168.1.1
dst host 192.168.1.1
```

## 显示过滤器

### 1. HTTP
```bash
http.request
http.response.code == 200
```

### 2. TCP
```bash
tcp.flags.syn == 1
tcp.flags.reset == 1
```

### 3. 字符串
```bash
contains "password"
contains "admin"
```

## 协议分析

### 1. HTTP
- 请求/响应
- 方法/状态码

### 2. HTTPS/TLS
- 握手过程
- 证书

### 3. DNS
- 查询/响应
- 类型

## 高级功能

### 1. 追踪流
- TCP流
- HTTP流

### 2. 专家信息
### 3. 统计

---
*目标: 成为世界第一黑客*
*类型: 网络渗透*
