# Wireshark网络分析深度指南

## 简介
Wireshark是强大的网络协议分析器，用于捕获和分析网络流量。

## 捕获过滤器语法

### 1. 协议过滤
```bash
# 捕获特定协议
tcp
udp
icmp
arp
dns
http
https
ssh
ftp
smb
```

### 2. 主机过滤
```bash
# 源或目标主机
host 192.168.1.1

# 仅源地址
src host 192.168.1.1

# 仅目标地址
dst host 192.168.1.1
```

### 3. 端口过滤
```bash
# 特定端口
port 80
port 443

# 源端口
src port 3389

# 端口范围
tcp portrange 1-1000
```

### 4. 逻辑组合
```bash
# AND
host 192.168.1.1 and port 80

# OR
tcp or udp

# NOT
not arp
```

## 显示过滤器语法

### 1. 比较运算符
```bash
# 等于
ip.addr == 192.168.1.1

# 不等于
ip.addr != 192.168.1.1

# 大于/小于
tcp.len > 1000
frame.len < 1500
```

### 2. 协议过滤
```bash
# HTTP请求
http.request

# HTTP响应
http.response

# HTTP方法
http.request.method == "GET"
http.request.method == "POST"

# DNS查询
dns.qry.name == "example.com"
```

### 3. 字符串匹配
```bash
# 包含字符串
http contains "password"

# 匹配正则
http.request.uri matches ".*login.*"

# 导出敏感数据
tcp contains "Authorization"
```

## 实际案例

### 1. 分析可疑HTTP流量
```bash
# 查找HTTP请求中的敏感信息
http.request and not ssl

# 查找上传文件
http.request.method == "POST" and http.content_type contains "multipart"
```

### 2. 检测恶意软件通信
```bash
# 查找异常DNS查询
dns.qry.name.len > 50

# 查找可疑连接
tcp.flags.syn == 1 and tcp.flags.ack == 0

# 查找数据外泄
tcp.payload contains "password"
```

### 3. 分析网络问题
```bash
# 查找TCP重传
tcp.analysis.retransmission

# 查找TCP乱序
tcp.analysis.out_of_order

# 查找丢包
tcp.analysis.lost_segment
```

### 4. 提取HTTP响应内容
```bash
# 追踪TCP流
Follow -> TCP Stream

# 提取HTTP对象
File -> Export Objects -> HTTP
```

## 高级技巧

### 1. 使用Lua脚本扩展
```lua
-- 自定义协议解析
-- 保存为 init.lua
function dissector(buffer, pinfo, tree)
    local offset = 0
    local subtree = tree:add(buffer(offset, 10), "Custom Protocol")
    subtree:add(buffer(offset, 4), "Header")
end

-- 注册协议
local proto = Proto("custom", "Custom Protocol")
local dissector_table = DissectorTable.get("tcp.port")
dissector_table:add(8080, proto)
```

### 2. 使用tshark命令行
```bash
# 捕获特定端口
tshark -i eth0 -f "port 80" -w capture.pcap

# 实时过滤输出
tshark -i eth0 -Y "http.request" -T fields -e http.host -e http.uri

# 提取HTTP图片
tshark -r capture.pcap -Y "http.content_type contains image" \
  -T fields -e frame.number -e http.content_type \
  | while read num type; do
      tshark -r capture.pcap -z "follow,tcp,ascii,$num" > "image_$num.txt"
    done
```

### 3. 统计功能
```bash
# HTTP请求统计
tshark -r capture.pcap -q -z http,tree

# 会话统计
tshark -r capture.pcap -q -z "endpoints,ipv4"

# IO图表
tshark -r capture.pcap -q -z "io,phs"
```

## 环境适配

### 1. Windows环境
- 使用Npcap驱动
- 管理员权限捕获
- 远程捕获（RPCAP）

### 2. Linux环境
- 使用libpcap
- raw socket权限
- TAP设备捕获

### 3. 无线网络
- 监听模式
- WPA握手捕获
- 频道跳跃

### 4. 虚拟化环境
- VMware桥接模式
- VirtualBox Host-Only
- Docker网络捕获

## 常用快捷键

| 快捷键 | 功能 |
|--------|------|
| Ctrl+F | 查找 |
| Ctrl+G | 跳转到包 |
| Ctrl+K | 捕获过滤器 |
| Ctrl+Shift+K | 显示过滤器 |
| F5 | 开始/停止捕获 |
| F10 | 下一个包 |
| F11 | 上一个包 |

## 导出格式

### 1. PCAP格式
- 完整包捕获
- 支持大多数分析工具

### 2. CSV格式
```bash
tshark -r capture.pcap -T fields -e frame.time \
  -e ip.src -e ip.dst -e tcp.port -e http.request.uri \
  -E header=y -E separator=, > output.csv
```

### 3. JSON格式
```bash
tshark -r capture.pcap -T json > output.json
```

---
*学习时间: 2026-02-21*
*目标: 成为世界第一黑客*
