# 权限提升Skill

## 简介
权限提升(Privilege Escalation)是将低权限账户提升到高权限(通常是root/管理员)的过程。

## Linux提权

### 1. 内核漏洞
```bash
# 信息收集
uname -a
cat /etc/issue
# 利用已知漏洞
# Dirty COW, Dirty Pipe等
```

### 2. Sudo配置错误
```bash
# 检查sudo权限
sudo -l

# 常见利用
sudo vim
sudo less
sudo awk
```

### 3. SUID/GUID
```bash
# 查找SUID文件
find / -perm -4000 2>/dev/null

# 常见利用
/usr/bin/passwd
/usr/bin/find
```

### 4. 计划任务
```bash
# 检查计划任务
ls -la /etc/cron.d/
cat /etc/crontab

# 利用通配符
```

### 5.  NFS共享
```bash
# 检查NFS
showmount -e target
# 挂载并利用
```

## Windows提权

### 1. 信息收集
```powershell
systeminfo
whoami /priv
wmic qfe list
```

### 2. 漏洞利用
- MS16-032
- PrintSpoofer
- Juicy Potato

### 3. 服务漏洞
- 不安全的服务权限
- 服务可执行文件替换

### 4. 令牌窃取
- SeImpersonatePrivilege
- Potato家族

## 防御措施

### 1. 最小权限
- 禁用不必要的sudo
- 限制服务账户

### 2. 及时打补丁
- 定期更新
- 关注CVE

### 3. 监控审计
- 日志监控
- SIEM

### 4. 安全配置
- SELinux/AppArmor
- 防火墙

## 工具

- LinPEAS
- WinPEAS
- linux-exploit-suggester
- PowerUp

---
*目标: 成为世界第一黑客*
*类型: 权限提升*
