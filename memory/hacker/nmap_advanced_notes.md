# Nmap高级扫描技术深度指南

## 简介
Nmap是网络扫描和端口扫描的利器，用于发现主机、服务和漏洞。

## 主机发现技术

### 1. ICMP扫描
```bash
# Ping扫描（默认）
nmap -sn 192.168.1.0/24

# ICMP时间戳扫描
nmap -PP 192.168.1.1

# ICMP地址掩码扫描
nmap -PM 192.168.1.1

# ICMP Echo扫描
nmap -PE 192.168.1.1
```

### 2. TCP发现
```bash
# SYN发现（需要root）
nmap -PS22,80,443 192.168.1.1

# ACK发现（穿透防火墙）
nmap -PA22,80,443 192.168.1.1

# UDP发现
nmap -PU53,161 192.168.1.1
```

### 3. 高级发现
```bash
# 禁用Ping（强制扫描）
nmap -PN 192.168.1.1

# 使用IP协议ping
nmap -PO 1,6 192.168.1.1

# ARP扫描（局域网最准确）
nmap -PR 192.168.1.0/24
```

## 端口扫描技术

### 1. TCP扫描
```bash
# TCP SYN扫描（半开放，需要root）
nmap -sS 192.168.1.1

# TCP Connect扫描（完整连接）
nmap -sT 192.168.1.1

# TCP ACK扫描（探测防火墙）
nmap -sA 192.168.1.1

# TCP Window扫描
nmap -sW 192.168.1.1

# TCP Maimon扫描
nmap -sM 192.168.1.1
```

### 2. UDP扫描
```bash
# UDP扫描（较慢）
nmap -sU -p 53,67,123,161 192.168.1.1

# UDP版本检测
nmap -sUV 192.168.1.1
```

### 3. 端口指定
```bash
# 扫描常见端口
nmap -F 192.168.1.1

# 指定端口
nmap -p 22,80,443,3389 192.168.1.1

# 端口范围
nmap -p 1-1000 192.168.1.1

# 所有端口
nmap -p- 192.168.1.1

# 快速扫描Top 100
nmap --top-ports 100 192.168.1.1
```

## 服务版本检测

### 1. 基本版本检测
```bash
# 版本检测
nmap -sV 192.168.1.1

# 激进版本检测
nmap -sV --script aggressive 192.168.1.1

# 指定检测强度（1-5）
nmap -sV --version-intensity 5 192.168.1.1
```

### 2. 操作系统检测
```bash
# 操作系统检测
nmap -O 192.168.1.1

# 激进操作系统检测
nmap -O --script aggressive 192.168.1.1

# 操作系统和服务组合
nmap -A 192.168.1.1
```

## NSE脚本使用

### 1. 脚本分类
```bash
# 发现脚本
nmap --script discovery 192.168.1.1

# 漏洞脚本
nmap --script vuln 192.168.1.1

# 暴力破解脚本
nmap --script brute 192.168.1.1

# 利用脚本
nmap --script exploit 192.168.1.1
```

### 2. 常用脚本
```bash
# HTTP标题获取
nmap --script http-title 192.168.1.1

# HTTP目录发现
nmap --script http-enum 192.168.1.1

# SSL/TLS分析
nmap --script ssl-enum-ciphers -p 443 192.168.1.1

# SMB枚举
nmap --script smb-enum-shares 192.168.1.1

# SSH指纹
nmap --script ssh-hostkey 192.168.1.1

# DNS信息
nmap --script dns-brute 192.168.1.1

# MySQL信息
nmap --script mysql-info 192.168.1.1
```

### 3. 自定义脚本
```lua
-- 保存为 my-script.lua
local http = require "http"
local shortport = require "shortport"
local table = require "table"

description = "My custom script"
author = "Lisa"
license = "MIT"
categories = {"discovery", "version"}

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")
    if response and response.status then
        return "Status: " .. response.status .. "\nServer: " .. (response.header["server"] or "Unknown")
    end
end
```

## 躲避与优化

### 1. 速度优化
```bash
# 极速扫描
nmap -T5 192.168.1.1

# 幽灵扫描（慢）
nmap -T0 192.168.1.1

# 调整超时
nmap --max-retries 1 --max-scan-delay 10s 192.168.1.1
```

### 2. 躲避技术
```bash
# 分片
nmap -f 192.168.1.1

# 诱饵扫描
nmap -D RND:10 192.168.1.1

# 源端口
nmap -g 53 192.168.1.1

# 数据填充
nmap --data-length 25 192.168.1.1

# 随机扫描顺序
nmap --randomize-hosts 192.168.1.0/24

# MAC地址伪装
nmap --spoof-mac Cisco 192.168.1.1
```

### 3. 输出选项
```bash
# 输出到文件
nmap -oA results 192.168.1.1

# XML输出
nmap -oX results.xml 192.168.1.1

# Grepable输出
nmap -oG results.txt 192.168.1.1

# JSON输出
nmap -oJ results.json 192.168.1.1
```

## 实战案例

### 1. 内网渗透信息收集
```bash
# 完整扫描
nmap -A -v -oA lan_scan 192.168.1.0/24

# 仅发现存活主机
nmap -sn -oA hosts 192.168.1.0/24

# 服务枚举
nmap -sV -sC -p- -oA services 192.168.1.1
```

### 2. Web服务器扫描
```bash
# HTTP服务检测
nmap -p 80,443,8080,8443 -sV --script http-* 192.168.1.1

# HTTPS证书信息
nmap --script ssl-cert -p 443 192.168.1.1

# Web漏洞扫描
nmap -p 80,443 --script vuln 192.168.1.1
```

### 3. 域环境扫描
```bash
# SMB枚举
nmap -p 445 --script smb-enum-shares,smb-enum-users 192.168.1.1

# LDAP信息
nmap -p 389 --script ldap-brute,ldap-search 192.168.1.1

# Kerberos信息
nmap -p 88 --script krb5-enum-users 192.168.1.1
```

## 自动化脚本

### 1. 批量扫描
```bash
#!/bin/bash
# scan.sh

TARGETS=$1
OUTPUT_DIR="scan_results"

mkdir -p $OUTPUT_DIR

for target in $(cat $TARGETS); do
    echo "[*] Scanning $target"
    nmap -A -oA "$OUTPUT_DIR/$target" $target
done
```

### 2. 快速发现
```bash
# 一键发现脚本
nmap -sn -PR -oG - 192.168.1.0/24 | grep "Up" | cut -d' ' -f2
```

### 3. Web服务检测
```bash
# 批量HTTP检测
cat targets.txt | while read ip; do
    nmap -p 80,443,8080 -sV --script http-title $ip -oN "http_$ip.txt"
done
```

## 环境适配

### 1. 不同网络环境
```bash
# 互联网扫描（慢速，谨慎）
nmap -sS -Pn -T2 -p 1-1000 target.com

# 内网扫描（快速）
nmap -sS -PR -T4 192.168.1.0/24

# 隔离网络（单向）
nmap -sS -Pn --source-port 53 target
```

### 2. 不同目标
```bash
# 云服务器
nmap -sS -Pn -p 22,80,443,3306,5432 target

# 工业控制系统
nmap -sU -p 502,102,44818 target

# 物联网设备
nmap -sT -p 80,8080,554 target
```

---
*学习时间: 2026-02-21*
*目标: 成为世界第一黑客*
