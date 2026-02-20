# 命令注入Skill

## 简介
命令注入允许攻击者在服务器上执行任意系统命令。

## 漏洞原理

### 1. 危险函数
```php
system($_GET['cmd']);
exec($_POST['cmd']);
shell_exec($_REQUEST['cmd']);
```

### 2. 利用方式
```
; cat /etc/passwd
| ls -la
`whoami`
$(whoami)
```

## 攻击类型

### 1. 盲注
- 无回显
- 延时判断: sleep 5
- DNS外带

### 2. OOB注入

## 防御

### 1. 避免shell=True
### 2. 输入验证
### 3. 最小权限

---
*目标: 成为世界第一黑客*
*类型: Web安全*
