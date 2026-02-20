# Nmap网络扫描学习笔记

## 简介
Nmap是世界上最流行的网络扫描工具，用于发现主机、服务和漏洞。

## 基本扫描

### 1. 主机发现
```bash
# Ping扫描
nmap -sn 192.168.1.0/24

# 不Ping扫描
nmap -PN 192.168.1.1
```

### 2. 端口扫描
```bash
# TCP连接扫描
nmap -sT 192.168.1.1

# SYN扫描(需要root)
nmap -sS 192.168.1.1

# UDP扫描
nmap -sU 192.168.1.1
```

### 3. 服务识别
```bash
# 版本检测
nmap -sV 192.168.1.1

# 操作系统检测
nmap -O 192.168.1.1
```

## 高级扫描

### 1. 脚本扫描
```bash
# 默认脚本
nmap -sC 192.168.1.1

# 漏洞脚本
nmap --script vuln 192.168.1.1

# 暴力破解
nmap --script brute 192.168.1.1
```

### 2. 躲避技术
```bash
# 分片
nmap -f 192.168.1.1

# 诱饵
nmap -D RND:10 192.168.1.1

# 源端口
nmap -g 53 192.168.1.1
```

## NSE脚本

### 1. 发现
- broadcast-discover
- ping-scan

### 2. 漏洞
- http-csrf
- http-sql-injection
- smb-vuln*

### 3. 暴力破解
- http-brute
- ssh-brute
- ftp-brute

## 防御措施

### 1. 防火墙
- 限制ICMP
- 关闭不必要的端口

### 2. 入侵检测
- Snort规则
- 流量监控

### 3. 最小化服务
- 关闭无用服务
- 最小权限

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
