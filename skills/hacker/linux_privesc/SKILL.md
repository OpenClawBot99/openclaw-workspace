# Linux权限提升Skill

## 简介
Linux权限提升是将低权限用户提升到root权限的过程。

## 信息收集

### 1. 系统信息
```bash
uname -a
cat /etc/issue
cat /etc/os-release
```

### 2. 用户信息
```bash
whoami
id
sudo -l
```

### 3. 服务进程
```bash
ps aux
ps -ef
netstat -tunp
```

## 提权方法

### 1. 内核漏洞
```bash
# 信息收集
uname -a

# 搜索对应exploit
searchsploit linux 4.4.0

# 常见exploit
- Dirty COW (CVE-2016-5195)
- Dirty Pipe (CVE-2022-0847)
- overlayfs (CVE-2015-8660)
```

### 2. Sudo配置错误
```bash
# 检查sudo权限
sudo -l

# 可利用命令
sudo vim
sudo less
sudo awk
sudo find
sudo wget
sudo nmap
```

### 3. SUID/GUID
```bash
# 查找SUID文件
find / -perm -4000 2>/dev/null
find / -perm -6000 2>/dev/null

# 可利用SUID
/usr/bin/passwd
/usr/bin/find
/usr/bin/nano
/usr/bin/vim
```

### 4. 计划任务
```bash
# 检查计划任务
ls -la /etc/cron.d/
cat /etc/crontab
crontab -l

# 利用通配符
```

### 5. NFS共享
```bash
# 检查NFS
showmount -e target
mount -t nfs target:/share /mnt
```

### 6. 能力(Capabilities)
```bash
# 检查能力
getcap -r / 2>/dev/null

# 可利用能力
cap_dac_read_search
cap_setuid
```

## 常用工具

### 1. 信息收集
- linux-exploit-suggester
- LinPEAS
- linuxprivchecker

### 2. 提权
- pwnkit (CVE-2021-4034)
- dirtycow
- dirtypipe

## 防御措施

### 1. 最小权限
- 禁用不必要的sudo
- 移除SUID

### 2. 及时打补丁
- 定期更新内核
- 关注CVE

### 3. 监控审计
- 日志监控
- 文件完整性

---
*目标: 成为世界第一黑客*
*类型: 权限提升*
