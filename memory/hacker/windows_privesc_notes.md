# Windows提权学习笔记

## 什么是Windows提权?
Windows提权是将普通用户权限提升到管理员或SYSTEM权限的过程。

## 提权类型

### 1. 垂直提权
- 普通用户 → 管理员
- 管理员 → SYSTEM
- 最高权限

### 2. 水平提权
- 同级别用户间切换
- 访问其他普通用户资源

## 常见提权方法

### 1. 系统漏洞
- CVE-2021-43297 (PrintNightmare)
- CVE-2021-34527 (PrintSpooler)
- 未打补丁的内核漏洞

### 2. 服务配置错误
- 不安全的服务权限
- 弱服务权限
- 服务可执行文件替换

### 3. 计划任务
- 修改计划任务脚本
- 利用高权限任务

### 4. 注册表提权
- AutoRun注册表键
- 服务注册表键

### 5. 令牌窃取
- SeImpersonatePrivilege
- Potato家族漏洞

### 6. 密码搜集
- 本地密码缓存
- SAM数据库
- LSA Secrets

## 常用工具

### 1. 信息收集
- winPEAS
- PowerUp
- Seatbelt

### 2. 漏洞利用
- Metasploit
- Cobalt Strike
- SharpUp

### 3. 密码获取
- Mimikatz
- LaZagne
- ProcDump

## 防御措施

### 1. 及时打补丁
- 定期更新系统
- 关注CVE漏洞

### 2. 最小权限原则
- 禁用管理员权限
- 限制服务账户

### 3. 监控审计
- Windows事件日志
- SIEM监控
- EDR部署

### 4. 密码策略
- 强密码策略
- 定期更换密码
- 禁用LM哈希

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
